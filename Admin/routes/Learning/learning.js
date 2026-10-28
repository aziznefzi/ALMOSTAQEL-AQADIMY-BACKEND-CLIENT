import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure uploads/learning directory exists
const uploadDir = path.resolve(__dirname, "../../../uploads/learning");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage for learning images
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `learning-${unique}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedMimes = [
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/jpg",
    "image/gif",
    "image/svg+xml",
  ];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("ONLY_IMAGES_ALLOWED"), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "views", "enrollments", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "published", "draft", "archived"];

// Normalizes tab names from Admin ("Courses", "Articles", "Videos", "All Vidios") to DB query
const resolveTypeFilter = (rawType) => {
  if (!rawType || rawType === "all") return null;
  const t = String(rawType).trim();
  const lower = t.toLowerCase();
  if (lower.includes("course")) return ["course", "Courses"];
  if (lower.includes("article")) return ["article", "Articles"];
  if (lower.includes("all") || lower.includes("ai")) return ["ai-video", "All Vidios", "ai_video"];
  if (lower.includes("video")) return ["video", "Videos"];
  return [t];
};

// ============================================================================
// 0. POST /admin/learning/upload-image - Upload Learning Image
// ============================================================================
router.post("/learning/upload-image", AdminAuth, (req, res) => {
  upload.single("image")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({ message: "Image size must not exceed 5MB" });
        }
        return res.status(400).json({ message: err.message });
      }
      return res.status(400).json({ message: err.message || "Failed to upload image" });
    }
    if (!req.file) {
      return res.status(400).json({ message: "No image file provided" });
    }
    const imageUrl = `/uploads/learning/${req.file.filename}`;
    res.status(200).json({
      message: "Image uploaded successfully",
      imageUrl,
      filename: req.file.filename,
    });
  });
});

// ============================================================================
// 1. GET /admin/learning - Fetch Paginated Learning Items
// ============================================================================
router.get("/learning", AdminAuth, async (req, res) => {
  try {
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawType = req.query.type ?? req.body?.type;
    const rawSearch = req.query.search ?? req.body?.search;
    const rawStatus = req.query.status ?? req.body?.status;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    // Validate pagination bounds
    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1
      ? Math.min(parsedLimit, 100)
      : 50;

    const skip = (page - 1) * limit;

    const query = {};

    // Type filter
    const resolvedTypes = resolveTypeFilter(rawType);
    if (resolvedTypes) {
      query.type = { $in: resolvedTypes };
    }

    // Status filter
    if (rawStatus && ALLOWED_STATUS_FILTERS.includes(rawStatus) && rawStatus !== "all") {
      query.status = rawStatus;
    }

    // Safe Search
    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        query.$or = [
          { title: regex },
          { titleAr: regex },
          { instructor: regex },
          { author: regex },
          { category: regex },
          { tag: regex },
        ];
      }
    }

    // Sort
    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;
    const sortObj = { [sortField]: sortOrder };

    // Parallel Execution
    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query)
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    res.status(200).json({
      items: items.map((i) => ({ ...i, id: i._id })),
      pagination: {
        total,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (err) {
    console.error("Error in GET /admin/learning:", err);
    res.status(500).json({ message: "Failed to fetch learning content" });
  }
});

// Also support POST for backwards compatibility
router.post("/learning/list", AdminAuth, async (req, res) => {
  // Re-routes to the same logic
  req.query = { ...req.query, ...req.body };
  return router.handle(req, res);
});

// ============================================================================
// 2. POST /admin/learning - Create New Learning Item
// ============================================================================
router.post("/learning", AdminAuth, async (req, res) => {
  try {
    const {
      type,
      title,
      titleAr,
      description,
      descriptionAr,
      category,
      tag,
      level,
      levelAr,
      instructor,
      instructorAr,
      author,
      tool,
      platform,
      duration,
      hours,
      lessons,
      readTime,
      price,
      priceAfter,
      status,
      image,
      stack,
      enrollments,
      views,
      rating,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "Title is required" });
    }
    if (!type || !type.trim()) {
      return res.status(400).json({ message: "Content type is required" });
    }

    // Map Admin tab type to standard schema type
    let normalizedType = type.trim();
    if (normalizedType === "Courses") normalizedType = "course";
    if (normalizedType === "Articles") normalizedType = "article";
    if (normalizedType === "Videos") normalizedType = "video";
    if (normalizedType === "All Vidios") normalizedType = "ai-video";

    const newItem = await Learning.create({
      type: normalizedType,
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      description: description?.trim() || "",
      descriptionAr: descriptionAr?.trim() || "",
      category: category?.trim() || "General",
      tag: tag?.trim() || category?.trim() || "General",
      level: ["Beginner", "Intermediate", "Advanced"].includes(level) ? level : "Beginner",
      levelAr: levelAr?.trim() || (level === "Advanced" ? "متقدم" : level === "Intermediate" ? "متوسط" : "مبتدئ"),
      instructor: instructor?.trim() || author?.trim() || "",
      instructorAr: instructorAr?.trim() || "",
      author: author?.trim() || instructor?.trim() || "",
      tool: tool?.trim() || "",
      platform: platform?.trim() || "Native",
      duration: duration?.trim() || (hours ? `${hours}h` : "0h"),
      hours: Number(hours) || 0,
      lessons: Number(lessons) || 0,
      readTime: Number(readTime) || 0,
      price: Number(price) || 0,
      priceAfter: Number(priceAfter) || Number(price) || 0,
      status: ["published", "draft", "archived"].includes(status) ? status : "draft",
      enrollments: Number(enrollments) || 0,
      views: Number(views) || 0,
      rating: Number(rating) || 5.0,
      image: image?.trim() || "",
      stack: Array.isArray(stack) ? stack : [],
    });

    res.status(201).json({
      message: "Learning item created successfully",
      item: { ...newItem.toObject(), id: newItem._id },
    });
  } catch (err) {
    console.error("Error in POST /admin/learning:", err);
    res.status(500).json({ message: "Failed to create learning item" });
  }
});

// ============================================================================
// 3. PUT /admin/learning/:id - Update Learning Item
// ============================================================================
router.put("/learning/:id", AdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findById(id);
    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    const updatable = [
      "type",
      "title",
      "titleAr",
      "description",
      "descriptionAr",
      "category",
      "tag",
      "level",
      "levelAr",
      "instructor",
      "instructorAr",
      "author",
      "tool",
      "platform",
      "duration",
      "hours",
      "lessons",
      "readTime",
      "price",
      "priceAfter",
      "status",
      "image",
      "stack",
      "rating",
      "enrollments",
      "views",
    ];

    for (const key of updatable) {
      if (req.body[key] !== undefined) {
        item[key] = req.body[key];
      }
    }

    await item.save();

    res.status(200).json({
      message: "Learning item updated successfully",
      item: { ...item.toObject(), id: item._id },
    });
  } catch (err) {
    console.error("Error in PUT /admin/learning/:id:", err);
    res.status(500).json({ message: "Failed to update learning item" });
  }
});

// ============================================================================
// 4. PATCH /admin/learning/:id/status - Toggle or Set Status
// ============================================================================
router.patch("/learning/:id/status", AdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findById(id);
    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    if (req.body.status && ["published", "draft", "archived"].includes(req.body.status)) {
      item.status = req.body.status;
    } else {
      // Toggle published <-> draft
      item.status = item.status === "published" ? "draft" : "published";
    }

    await item.save();

    res.status(200).json({
      message: "Status updated successfully",
      status: item.status,
      item: { ...item.toObject(), id: item._id },
    });
  } catch (err) {
    console.error("Error in PATCH /admin/learning/:id/status:", err);
    res.status(500).json({ message: "Failed to update status" });
  }
});

// ============================================================================
// 5. DELETE /admin/learning/:id - Delete Learning Item
// ============================================================================
router.delete("/learning/:id", AdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findByIdAndDelete(id);
    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    res.status(200).json({ message: "Learning item deleted successfully" });
  } catch (err) {
    console.error("Error in DELETE /admin/learning/:id:", err);
    res.status(500).json({ message: "Failed to delete learning item" });
  }
});

export default router;
