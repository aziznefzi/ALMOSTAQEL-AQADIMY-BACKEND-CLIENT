import express from "express";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "views", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "published", "draft", "archived"];

const formatVideoDoc = (doc) => {
  const obj = typeof doc.toObject === "function" ? doc.toObject() : doc;
  return {
    ...obj,
    id: obj._id,
  };
};

// ============================================================================
// 1. GET & POST /admin/learning/videos - Fetch Paginated Educational / AI Videos
// ============================================================================
const handleGetVideos = async (req, res) => {
  try {
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawType = req.query.type ?? req.body?.type;
    const rawSearch = req.query.search ?? req.body?.search;
    const rawStatus = req.query.status ?? req.body?.status ?? req.query.filter ?? req.body?.filter;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1 ? Math.min(parsedLimit, 100) : 50;
    const skip = (page - 1) * limit;

    const lowerType = String(rawType || "").toLowerCase();
    const isAiVideo = lowerType.includes("all") || lowerType.includes("ai");
    const query = {
      type: isAiVideo
        ? { $in: ["ai-video", "All Vidios", "ai_video"] }
        : { $in: ["video", "Videos"] },
    };

    if (rawStatus && ALLOWED_STATUS_FILTERS.includes(rawStatus) && rawStatus !== "all") {
      query.status = rawStatus;
    }

    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        query.$or = [
          { title: regex },
          { titleAr: regex },
          { description: regex },
          { descriptionAr: regex },
          { instructor: regex },
          { tool: regex },
          { category: regex },
          { tag: regex },
        ];
      }
    }

    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;

    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query)
        .sort({ [sortField]: sortOrder })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    res.status(200).json({
      items: items.map(formatVideoDoc),
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
    console.error("Error in handleGetVideos:", err);
    res.status(500).json({ message: "Failed to fetch videos" });
  }
};

router.get("/learning/videos", AdminAuth, handleGetVideos);
router.post("/learning/videos/list", AdminAuth, handleGetVideos);

// ============================================================================
// 2. GET /admin/learning/videos/:id - Get Single Video Details
// ============================================================================
router.get("/learning/videos/:id", AdminAuth, async (req, res) => {
  try {
    const video = await Learning.findById(req.params.id).lean();
    if (!video) {
      return res.status(404).json({ message: "Video not found" });
    }
    res.status(200).json({ item: formatVideoDoc(video) });
  } catch (err) {
    console.error("Error in GET /learning/videos/:id:", err);
    res.status(500).json({ message: "Failed to fetch video details" });
  }
});

// ============================================================================
// 3. POST /admin/learning/videos - Create Educational / AI Video
// ============================================================================
router.post("/learning/videos", AdminAuth, async (req, res) => {
  try {
    const {
      type,
      title,
      titleAr,
      description,
      descriptionAr,
      category,
      tag,
      instructor,
      instructorAr,
      tool,
      platform,
      duration,
      hours,
      price,
      priceAfter,
      status,
      image,
      imageDataUrl,
      videoUrl,
      stack,
      rating,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "Video title is required" });
    }

    const lowerType = String(type || "").toLowerCase();
    const normalizedType =
      lowerType.includes("all") || lowerType.includes("ai") ? "ai-video" : "video";

    const newVideo = await Learning.create({
      type: normalizedType,
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      description: description?.trim() || "",
      descriptionAr: descriptionAr?.trim() || "",
      category: category?.trim() || "General",
      tag: tag?.trim() || category?.trim() || "General",
      instructor: instructor?.trim() || "",
      instructorAr: instructorAr?.trim() || "",
      tool: tool?.trim() || "",
      platform: platform?.trim() || "Native",
      duration: duration?.trim() || (hours ? `${hours}h` : "0:15:00"),
      hours: Number(hours) || 0,
      price: Number(price) || 0,
      priceAfter: priceAfter !== undefined ? Number(priceAfter) : Number(price) || 0,
      status: ["published", "draft", "archived"].includes(status) ? status : "published",
      rating: Number(rating) || 5.0,
      image: image?.trim() || "",
      imageDataUrl: imageDataUrl || "",
      videoUrl: videoUrl?.trim() || "",
      stack: Array.isArray(stack) ? stack : [],
    });

    res.status(201).json({
      message: "Video created successfully",
      item: formatVideoDoc(newVideo),
    });
  } catch (err) {
    console.error("Error in POST /learning/videos:", err);
    res.status(500).json({ message: "Failed to create video" });
  }
});

// ============================================================================
// 4. PUT /admin/learning/videos/:id - Update Video
// ============================================================================
router.put("/learning/videos/:id", AdminAuth, async (req, res) => {
  try {
    const video = await Learning.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ message: "Video not found" });
    }

    const updatable = [
      "title",
      "titleAr",
      "description",
      "descriptionAr",
      "category",
      "tag",
      "instructor",
      "instructorAr",
      "tool",
      "platform",
      "duration",
      "hours",
      "price",
      "priceAfter",
      "status",
      "image",
      "imageDataUrl",
      "videoUrl",
      "stack",
      "rating",
    ];

    for (const key of updatable) {
      if (req.body[key] !== undefined) {
        video[key] = req.body[key];
      }
    }

    await video.save();

    res.status(200).json({
      message: "Video updated successfully",
      item: formatVideoDoc(video),
    });
  } catch (err) {
    console.error("Error in PUT /learning/videos/:id:", err);
    res.status(500).json({ message: "Failed to update video" });
  }
});

// ============================================================================
// 5. PATCH /admin/learning/videos/:id/status - Archive / Hide / Publish Video
// ============================================================================
router.patch("/learning/videos/:id/status", AdminAuth, async (req, res) => {
  try {
    const video = await Learning.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ message: "Video not found" });
    }

    if (req.body.status && ["published", "draft", "archived"].includes(req.body.status)) {
      video.status = req.body.status;
    } else {
      video.status = video.status === "published" ? "archived" : "published";
    }

    await video.save();

    res.status(200).json({
      message: "Video status updated successfully",
      status: video.status,
      item: formatVideoDoc(video),
    });
  } catch (err) {
    console.error("Error in PATCH /learning/videos/:id/status:", err);
    res.status(500).json({ message: "Failed to update video status" });
  }
});

// ============================================================================
// 6. DELETE /admin/learning/videos/:id - Delete Video
// ============================================================================
router.delete("/learning/videos/:id", AdminAuth, async (req, res) => {
  try {
    const deleted = await Learning.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ message: "Video not found" });
    }
    res.status(200).json({ message: "Video deleted successfully" });
  } catch (err) {
    console.error("Error in DELETE /learning/videos/:id:", err);
    res.status(500).json({ message: "Failed to delete video" });
  }
});

export default router;

