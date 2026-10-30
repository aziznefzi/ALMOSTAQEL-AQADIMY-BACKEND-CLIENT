import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";
import coursesRouter from "./courses.js";
import articlesRouter from "./articles.js";
import learningVideoRouter from "./learningVideo.js";
import ordersRouter from "./orders.js";
import { sendOrderEmail } from "../../../router/learning/orders.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure uploads/learning directory exists
const uploadDir = path.resolve(__dirname, "../../../uploads/learning");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage for learning images
const imageStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `learning-${unique}${ext}`);
  },
});

const imageFileFilter = (req, file, cb) => {
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

const uploadImage = multer({
  storage: imageStorage,
  fileFilter: imageFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Multer storage for learning videos
const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || ".mp4";
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `learning-video-${unique}${ext}`);
  },
});

const videoFileFilter = (req, file, cb) => {
  const allowedVideoMimes = [
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/quicktime",
    "video/x-matroska",
  ];
  if (allowedVideoMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("ONLY_VIDEOS_ALLOWED"), false);
  }
};

const uploadVideo = multer({
  storage: videoStorage,
  fileFilter: videoFileFilter,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
});

const router = express.Router();

// Mount specialized routers (Courses, Articles, Educational Videos)
router.use(ordersRouter);
router.use(coursesRouter);
router.use(articlesRouter);
router.use(learningVideoRouter);

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "views", "enrollments", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "published", "draft", "archived"];

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
// 0A. POST /admin/learning/upload-image - Upload Learning Cover Image
// ============================================================================
router.post("/learning/upload-image", AdminAuth, (req, res) => {
  uploadImage.single("image")(req, res, (err) => {
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
    let imageDataUrl = "";
    try {
      const buf = fs.readFileSync(req.file.path);
      imageDataUrl = `data:${req.file.mimetype};base64,${buf.toString("base64")}`;
    } catch {
      // ignore base64 encoding error
    }
    res.status(200).json({
      message: "Image uploaded successfully",
      imageUrl,
      imageDataUrl,
      filename: req.file.filename,
    });
  });
});

// ============================================================================
// 0B. POST /admin/learning/upload-video - Upload Learning Video File
// ============================================================================
router.post("/learning/upload-video", AdminAuth, (req, res) => {
  uploadVideo.single("video")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({ message: "Video size must not exceed 100MB" });
        }
        return res.status(400).json({ message: err.message });
      }
      return res.status(400).json({ message: err.message || "Failed to upload video" });
    }
    if (!req.file) {
      return res.status(400).json({ message: "No video file provided" });
    }
    const videoUrl = `/uploads/learning/${req.file.filename}`;
    res.status(200).json({
      message: "Video uploaded successfully",
      videoUrl,
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

    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1 ? Math.min(parsedLimit, 100) : 50;

    const skip = (page - 1) * limit;

    const query = {};

    const resolvedTypes = resolveTypeFilter(rawType);
    if (resolvedTypes) {
      query.type = { $in: resolvedTypes };
    }

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
          { author: regex },
          { category: regex },
          { tag: regex },
        ];
      }
    }

    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;
    const sortObj = { [sortField]: sortOrder };

    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query).sort(sortObj).skip(skip).limit(limit).lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    res.status(200).json({
      items: items.map((i) => ({
        ...i,
        id: i._id,
        courseVideos: Array.isArray(i.courseVideos)
          ? i.courseVideos.map((v) => ({ ...v, id: v._id }))
          : [],
      })),
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

router.post("/learning/list", AdminAuth, async (req, res) => {
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
      content,
      contentAr,
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
      imageDataUrl,
      videoUrl,
      courseVideos,
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

    let normalizedType = type.trim();
    if (normalizedType === "Courses") normalizedType = "course";
    if (normalizedType === "Articles") normalizedType = "article";
    if (normalizedType === "Videos") normalizedType = "video";
    if (normalizedType === "All Vidios") normalizedType = "ai-video";

    const validVideos = Array.isArray(courseVideos)
      ? courseVideos
          .filter((v) => v && v.title && v.videoUrl)
          .map((v, idx) => ({
            title: String(v.title).trim(),
            titleAr: String(v.titleAr || "").trim(),
            description: String(v.description || "").trim(),
            videoUrl: String(v.videoUrl).trim(),
            duration: String(v.duration || "0:00").trim(),
            order: idx + 1,
          }))
      : [];

    const newItem = await Learning.create({
      type: normalizedType,
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      description: description?.trim() || "",
      descriptionAr: descriptionAr?.trim() || "",
      content: content?.trim() || "",
      contentAr: contentAr?.trim() || "",
      category: category?.trim() || "General",
      tag: tag?.trim() || category?.trim() || "General",
      level: ["Beginner", "Intermediate", "Advanced"].includes(level) ? level : "Beginner",
      levelAr:
        levelAr?.trim() ||
        (level === "Advanced" ? "متقدم" : level === "Intermediate" ? "متوسط" : "مبتدئ"),
      instructor: instructor?.trim() || author?.trim() || "",
      instructorAr: instructorAr?.trim() || "",
      author: author?.trim() || instructor?.trim() || "",
      tool: tool?.trim() || "",
      platform: platform?.trim() || "Native",
      duration: duration?.trim() || (hours ? `${hours}h` : "0h"),
      hours: Number(hours) || 0,
      lessons: validVideos.length || Number(lessons) || 0,
      readTime: Number(readTime) || 0,
      price: Number(price) || 0,
      priceAfter: priceAfter !== undefined ? Number(priceAfter) : Number(price) || 0,
      status: ["published", "draft", "archived"].includes(status) ? status : "published",
      enrollments: Number(enrollments) || 0,
      views: Number(views) || 0,
      rating: Number(rating) || 5.0,
      image: image?.trim() || "",
      imageDataUrl: imageDataUrl || "",
      videoUrl: videoUrl?.trim() || "",
      courseVideos: validVideos,
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
      "content",
      "contentAr",
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
      "availabilityStatus",
      "image",
      "imageDataUrl",
      "videoUrl",
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
// 4B. PATCH & POST /admin/learning/:id/availability
// Set availabilityStatus: "preorder" | "available" (Production) | "unavailable"
// When switched to "available" (Production), automatically emails all pre-order users!
// ============================================================================
const buildPreorderLaunchEmail = ({ userName, item, lang = "ar" }) => {
  const isEn = String(lang || "ar").trim().toLowerCase().startsWith("en");
  const isAr = !isEn;
  const titleAr = item.titleAr || item.title;
  const titleEn = item.title || item.titleAr;
  const effectivePrice = Number(item.priceAfter ?? item.price ?? 0);
  const priceDisplay =
    effectivePrice <= 0
      ? isAr
        ? "مجاني"
        : "Free"
      : `$${effectivePrice}`;
  const buyNowUrl = "https://almostaqelaqademy.com/learn/courses";

  const subject = isAr
    ? `تم إطلاق المنتوج رسمياً: ${titleAr} — أكاديمية المستقبل 🚀`
    : `Product Officially Launched: ${titleEn} — Almostaqel Academy 🚀`;

  const html = isAr
    ? `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #07070f; color: #f0efff; margin: 0; padding: 36px 16px; direction: rtl; text-align: right;">
  <div style="max-width: 600px; margin: 0 auto; background-color: #13111c; border: 1px solid #2b2440; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.5);">
    <div style="background: linear-gradient(135deg, #10b981 0%, #7c3aed 55%, #ec4899 100%); padding: 28px 20px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800;">تم إطلاق المنتوج رسمياً! 🚀</h1>
      <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.92); font-size: 13px;">أكاديمية المستقبل — Almostaqel Academy</p>
    </div>

    <div style="padding: 30px 26px;">
      <p style="font-size: 17px; font-weight: 700; color: #ffffff; margin-top: 0;">مرحباً ${userName || "عزيزي المتعلم"}،</p>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.8;">
        يسعدنا إبلاغك بأن المنتوج التعليمي الذي قمت بتسجيل <strong>طلب مسبق</strong> عليه قد اكتمل إنتاجه وأصبح متاحاً الآن رسمياً على منصة <strong>أكاديمية المستقبل</strong>!
      </p>

      <div style="background: #1a1628; border: 1px solid #10b981; border-radius: 14px; padding: 18px; margin: 22px 0;">
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">المنتوج:</strong> <span style="color: #34d399; font-weight: 700;">${titleAr}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">السعر:</strong> <span style="color: #ffffff; font-family: monospace;">${priceDisplay}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">الحالة:</strong> <span style="color: #10b981; font-weight: 800;">متوفر الآن ✓</span></p>
      </div>

      <p style="font-size: 13px; color: #cbd5e1; line-height: 1.7;">
        يمكنك الآن الدخول إلى المنصة وإتمام عملية الشراء أو المشاهدة مباشرة للاستفادة من كامل محتوى المنتوج.
      </p>

      <div style="text-align: center; margin: 28px 0 10px 0;">
        <a href="${buyNowUrl}" target="_blank" rel="noopener noreferrer" style="display: inline-block; background: linear-gradient(135deg, #7c3aed 0%, #ec4899 100%); color: #ffffff; text-decoration: none; font-weight: 800; font-size: 15px; padding: 14px 36px; border-radius: 12px; box-shadow: 0 6px 20px rgba(236,72,153,0.35);">
          إشتري الأن
        </a>
      </div>
    </div>

    <div style="padding: 18px; text-align: center; background-color: #0e0c16; border-top: 1px solid #1f1b2e; font-size: 12px; color: #64748b;">
      &copy; ${new Date().getFullYear()} أكاديمية المستقبل. جميع الحقوق محفوظة.
    </div>
  </div>
</body>
</html>`
    : `
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #07070f; color: #f0efff; margin: 0; padding: 36px 16px; direction: ltr; text-align: left;">
  <div style="max-width: 600px; margin: 0 auto; background-color: #13111c; border: 1px solid #2b2440; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.5);">
    <div style="background: linear-gradient(135deg, #10b981 0%, #7c3aed 55%, #ec4899 100%); padding: 28px 20px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800;">Product Officially Launched! 🚀</h1>
      <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.92); font-size: 13px;">Almostaqel Academy</p>
    </div>

    <div style="padding: 30px 26px;">
      <p style="font-size: 17px; font-weight: 700; color: #ffffff; margin-top: 0;">Hello ${userName || "Student"},</p>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.8;">
        We are excited to let you know that the educational product you registered a <strong>Pre-Order</strong> for has finished production and is now officially live on <strong>Almostaqel Academy</strong>!
      </p>

      <div style="background: #1a1628; border: 1px solid #10b981; border-radius: 14px; padding: 18px; margin: 22px 0;">
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Product:</strong> <span style="color: #34d399; font-weight: 700;">${titleEn}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Price:</strong> <span style="color: #ffffff; font-family: monospace;">${priceDisplay}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Status:</strong> <span style="color: #10b981; font-weight: 800;">Available Now ✓</span></p>
      </div>

      <p style="font-size: 13px; color: #cbd5e1; line-height: 1.7;">
        You can now visit the platform and purchase or watch the full content right away.
      </p>

      <div style="text-align: center; margin: 28px 0 10px 0;">
        <a href="${buyNowUrl}" target="_blank" rel="noopener noreferrer" style="display: inline-block; background: linear-gradient(135deg, #7c3aed 0%, #ec4899 100%); color: #ffffff; text-decoration: none; font-weight: 800; font-size: 15px; padding: 14px 36px; border-radius: 12px; box-shadow: 0 6px 20px rgba(236,72,153,0.35);">
          Buy Now
        </a>
      </div>
    </div>

    <div style="padding: 18px; text-align: center; background-color: #0e0c16; border-top: 1px solid #1f1b2e; font-size: 12px; color: #64748b;">
      &copy; ${new Date().getFullYear()} Almostaqel Academy. All rights reserved.
    </div>
  </div>
</body>
</html>`;

  return { subject, html };
};

const handleUpdateAvailability = async (req, res) => {
  try {
    const { id } = req.params;
    const { availabilityStatus } = req.body || {};

    if (!["preorder", "available", "unavailable"].includes(availabilityStatus)) {
      return res.status(400).json({
        message: "Invalid availabilityStatus. Must be preorder, available, or unavailable.",
      });
    }

    const item = await Learning.findById(id);
    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    const previousAvailability = item.availabilityStatus || "preorder";
    item.availabilityStatus = availabilityStatus;

    let notifiedCount = 0;
    const preordersList = Array.isArray(item.preorders) ? item.preorders : [];

    // When launching to Production ("available"), email all pre-order subscribers
    if (availabilityStatus === "available" && preordersList.length > 0) {
      const seenEmails = new Set();
      for (const entry of preordersList) {
        const email = String(entry.userEmail || "").trim().toLowerCase();
        if (!email || seenEmails.has(email)) continue;
        seenEmails.add(email);

        const emailPayload = buildPreorderLaunchEmail({
          userName: entry.userName || "Student",
          item,
          lang: entry.lang || "ar",
        });

        const result = await sendOrderEmail({
          to: email,
          subject: emailPayload.subject,
          html: emailPayload.html,
        });

        if (result?.success) {
          notifiedCount += 1;
          entry.notifiedAt = new Date();
        }
      }
      item.markModified("preorders");
    }

    await item.save();

    return res.status(200).json({
      message:
        availabilityStatus === "available"
          ? `Product launched to production! Sent email notifications to ${notifiedCount} pre-order subscriber(s).`
          : availabilityStatus === "unavailable"
          ? "Product marked as currently unavailable."
          : "Product set to Pre-Order mode.",
      availabilityStatus: item.availabilityStatus,
      previousAvailability,
      notifiedCount,
      preordersCount: preordersList.length,
      item: { ...item.toObject(), id: item._id },
    });
  } catch (err) {
    console.error("Error in /admin/learning/:id/availability:", err);
    return res.status(500).json({ message: "Failed to update product availability" });
  }
};

router.patch("/learning/:id/availability", AdminAuth, handleUpdateAvailability);
router.post("/learning/:id/availability", AdminAuth, handleUpdateAvailability);

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
