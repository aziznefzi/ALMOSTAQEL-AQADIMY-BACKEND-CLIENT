import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import mongoose from "mongoose";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";
import { resolveVideoPlaybackForUser } from "../../utils/mediaValidation.js";
import { recordUserLearningView } from "../../utils/trackUserLearningView.js";
import coursesRouter from "./courses.js";
import articlesRouter from "./articles.js";
import videosRouter from "./videos.js";
import ordersRouter from "./orders.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const learningUploadsDir = path.resolve(__dirname, "../../uploads/learning");

const router = express.Router();

// Helper: decode base64 data URL from MongoDB and send as cacheable binary image
export const sendBase64Image = (res, dataUrl, maxAgeSeconds = 86400) => {
  if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/")) {
    return false;
  }
  const match = dataUrl.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
  if (!match) return false;
  const mimeType = match[1];
  const base64Body = match[2];
  try {
    const buffer = Buffer.from(base64Body, "base64");
    if (!buffer || buffer.length === 0) return false;
    res.setHeader("Content-Type", mimeType);
    res.setHeader("Content-Length", buffer.length);
    res.setHeader(
      "Cache-Control",
      `public, max-age=${maxAgeSeconds}${maxAgeSeconds >= 86400 ? ", immutable" : ""}`
    );
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.status(200).send(buffer);
    return true;
  } catch {
    return false;
  }
};

// Fallback handler for GET /uploads/learning/:filename when file is not on local/ephemeral disk
// Serves the image directly from MongoDB `imageDataUrl` so production deployments never 404.
export const serveLearningUploadFallback =
  ({ requirePublished = true } = {}) =>
  async (req, res) => {
    try {
      const rawFilename = String(req.params.filename || "").trim();
      if (!rawFilename || !/^[a-zA-Z0-9._-]+$/.test(rawFilename)) {
        return res.status(404).end();
      }

      const imagePath = `/uploads/learning/${rawFilename}`;
      const query = {
        $or: [{ image: imagePath }, { image: rawFilename }],
      };
      if (requirePublished) {
        query.status = "published";
      }

      const item = await Learning.findOne(query)
        .select("imageDataUrl")
        .lean();

      if (item?.imageDataUrl && sendBase64Image(res, item.imageDataUrl, 31536000)) {
        return;
      }

      return res.status(404).end();
    } catch (err) {
      console.error("Error in serveLearningUploadFallback:", err);
      return res.status(500).end();
    }
  };

// Mount modular protected routes for orders, courses, articles, and videos
router.use("/", ordersRouter);
router.use("/", coursesRouter);
router.use("/", articlesRouter);
router.use("/", videosRouter);

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const ALLOWED_SORT_FIELDS = [
  "createdAt",
  "views",
  "enrollments",
  "rating",
  "price",
  "title",
];

const ALLOWED_ARTICLE_TYPES = ["daily_news", "educational", "technical"];

const resolveArticleType = (doc) => {
  if (doc?.articleType && ALLOWED_ARTICLE_TYPES.includes(doc.articleType)) {
    return doc.articleType;
  }
  const cat = String(doc?.category || doc?.tag || "").toLowerCase();
  if (doc?.source === "ai_agent" || cat.includes("news")) return "daily_news";
  if (cat.includes("educat") || cat.includes("tutorial") || cat.includes("guide") || cat.includes("learn")) {
    return "educational";
  }
  return "technical";
};

// Strip protected media/article body AND bulky legacy Base64 data from public catalog cards
const toPublicCatalogItem = (item) => {
  const courseVideosCount = Array.isArray(item.courseVideos)
    ? item.courseVideos.length
    : 0;
  const preordersCount = Array.isArray(item.preorders)
    ? item.preorders.length
    : 0;
  const {
    courseVideos,
    videoUrl,
    videoMedia,
    content,
    contentAr,
    preorders,
    imageDataUrl,
    source,
    ...publicFields
  } = item;

  const isArticleItem =
    String(item.type || "").toLowerCase().includes("article");
  const publicAuthor = isArticleItem ? "Almostaqel Academy" : item.author || "";

  const thumbnailUrl = item.thumbnail?.url || item.image || "";
  const isExternalUrl =
    thumbnailUrl.startsWith("https://") || thumbnailUrl.startsWith("http://");
  // For legacy items whose binary still lives in MongoDB imageDataUrl, serve via
  // cacheable binary URL `/api/learning/:id/image` instead of shipping megabytes of Base64 JSON!
  const deliveryImage = isExternalUrl
    ? thumbnailUrl
    : thumbnailUrl && thumbnailUrl.startsWith("/uploads/")
    ? thumbnailUrl
    : imageDataUrl
    ? `/api/learning/${item._id}/image`
    : "";

  return {
    ...publicFields,
    id: item._id,
    author: publicAuthor,
    ...(isArticleItem ? { articleType: resolveArticleType(item) } : {}),
    publishedAt: item.publishedAt || item.approvedAt || item.createdAt,
    image: deliveryImage,
    thumbnail: {
      url: deliveryImage,
      provider: item.thumbnail?.provider || (isExternalUrl ? "custom" : deliveryImage ? "legacy" : ""),
      publicId: item.thumbnail?.publicId || "",
      alt: item.thumbnail?.alt || item.title || "",
    },
    excerpt: item.excerpt || item.description || "",
    excerptAr: item.excerptAr || item.descriptionAr || "",
    availabilityStatus: item.availabilityStatus || "preorder",
    preordersCount,
    lessons: courseVideosCount > 0 ? courseVideosCount : item.lessons || 0,
  };
};

// ============================================================================
// 1. GET /api/learning - Fetch Public Catalog Cards (Courses, Articles, Videos)
// ============================================================================
router.get("/learning", async (req, res) => {
  try {
    const rawPage = req.query.page;
    const rawLimit = req.query.limit;
    const rawType = req.query.type;
    const rawCategory = req.query.category ?? req.query.tag;
    const rawLevel = req.query.level;
    const rawSearch = req.query.search ?? req.query.q;
    const rawSort = req.query.sort;
    const rawOrder = req.query.order;

    // Validate pagination bounds
    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, 100)
        : 50;

    const skip = (page - 1) * limit;

    // Public safety: ONLY published content is accessible to students
    const andConditions = [{ status: "published" }];

    // Filter by type
    if (rawType && rawType !== "all") {
      const t = String(rawType).toLowerCase().trim();
      if (t.includes("course")) andConditions.push({ type: { $in: ["course", "Courses"] } });
      else if (t.includes("article")) andConditions.push({ type: { $in: ["article", "Articles"] } });
      else if (t.includes("all") || t.includes("ai"))
        andConditions.push({ type: { $in: ["ai-video", "All Vidios", "ai_video"] } });
      else if (t.includes("video")) andConditions.push({ type: { $in: ["video", "Videos"] } });
      else andConditions.push({ type: rawType });
    }

    // Filter by category
    if (rawCategory && rawCategory !== "all" && rawCategory !== "All") {
      andConditions.push({
        $or: [{ category: rawCategory }, { tag: rawCategory }, { tags: rawCategory }],
      });
    }

    // Filter by level
    if (rawLevel && ["Beginner", "Intermediate", "Advanced"].includes(rawLevel)) {
      andConditions.push({ level: rawLevel });
    }

    // Safe Search
    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        andConditions.push({
          $or: [
            { title: regex },
            { titleAr: regex },
            { slug: regex },
            { excerpt: regex },
            { description: regex },
            { descriptionAr: regex },
            { instructor: regex },
            { instructorAr: regex },
            { author: regex },
            { category: regex },
            { tag: regex },
            { tags: regex },
          ],
        });
      }
    }

    const query = andConditions.length === 1 ? andConditions[0] : { $and: andConditions };

    // Sort
    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;
    const sortObj = { [sortField]: sortOrder };

    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query).sort(sortObj).skip(skip).limit(limit).lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    res.status(200).json({
      items: items.map(toPublicCatalogItem),
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
    console.error("Error in GET /api/learning:", err);
    res.status(500).json({ message: "Failed to fetch learning items" });
  }
});

// ============================================================================
// 1B. GET /api/learning/:id/image - Public Cacheable Binary Cover Image
// Serves published learning item cover directly from MongoDB or disk (never 404s on ephemeral hosts)
// ============================================================================
router.get("/learning/:id/image", async (req, res) => {
  try {
    const rawId = String(req.params.id || "").trim();
    if (!mongoose.isValidObjectId(rawId)) {
      return res.status(404).end();
    }

    const item = await Learning.findOne({ _id: rawId, status: "published" })
      .select("image imageDataUrl")
      .lean();

    if (!item) {
      return res.status(404).end();
    }

    if (item.imageDataUrl && sendBase64Image(res, item.imageDataUrl, 86400)) {
      return;
    }

    const rawImg = String(item.image || "").trim();
    if (rawImg.startsWith("/uploads/learning/")) {
      const filename = path.basename(rawImg);
      if (/^[a-zA-Z0-9._-]+$/.test(filename)) {
        const diskPath = path.join(learningUploadsDir, filename);
        if (fs.existsSync(diskPath)) {
          res.setHeader("Cache-Control", "public, max-age=86400");
          res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
          return res.sendFile(diskPath);
        }
      }
    }

    if (
      (rawImg.startsWith("http://") || rawImg.startsWith("https://")) &&
      !rawImg.includes("localhost:")
    ) {
      return res.redirect(302, rawImg);
    }

    return res.status(404).end();
  } catch (err) {
    console.error("Error in GET /api/learning/:id/image:", err);
    return res.status(500).end();
  }
});

// ============================================================================
// 2. GET & POST /api/learning/:id - Fetch Protected Single Learning Item Content
// Strictly protected by userAuth + Confirmed Purchase Check if paid
// ============================================================================
const handleGetProtectedItem = async (req, res) => {
  try {
    const rawId = String(req.params.id || "").trim();
    if (!rawId) {
      return res.status(404).json({ message: "Learning item not found" });
    }
    const identifierFilter = mongoose.isValidObjectId(rawId)
      ? { $or: [{ _id: rawId }, { slug: rawId.toLowerCase() }] }
      : { slug: rawId.toLowerCase() };
    const item = await Learning.findOne({ ...identifierFilter, status: "published" }).lean();

    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    const availability = item.availabilityStatus || "preorder";
    if (availability === "unavailable") {
      return res.status(403).json({
        message: "هذا المنتوج غير متوفر في الوقت الحالي.",
        unavailable: true,
        productId: item._id,
      });
    }
    if (availability === "preorder") {
      return res.status(403).json({
        message: "هذا المنتوج في مرحلة الطلب المسبق حالياً وسيتم إطلاقه قريباً.",
        isPreorder: true,
        productId: item._id,
      });
    }

    const effectivePrice = Number(item.priceAfter ?? item.price ?? 0);

    // STRICT PURCHASE ENFORCEMENT: If paid, verify confirmed order or Users.purchasedProducts in DB
    if (effectivePrice > 0) {
      const isPurchasedInUserDoc =
        Array.isArray(req.dbUser?.purchasedProducts) &&
        req.dbUser.purchasedProducts.some(
          (pid) => String(pid) === String(item._id)
        );
      const approvedOrder = isPurchasedInUserDoc
        ? true
        : await Orders.findOne({
            userId: req.user.userId,
            productId: item._id,
            status: "approved",
          }).lean();

      if (!approvedOrder) {
        const pendingOrder = await Orders.findOne({
          userId: req.user.userId,
          productId: item._id,
          status: "pending",
        })
          .sort({ createdAt: -1 })
          .lean();

        return res.status(403).json({
          message:
            "You must purchase this product and have your payment confirmed to access its content.",
          requiresPurchase: true,
          hasPendingOrder: Boolean(pendingOrder),
          orderCode: pendingOrder?.orderCode || null,
          paymentMethod: pendingOrder?.paymentMethod || null,
          productSummary: {
            id: item._id,
            title: item.title,
            titleAr: item.titleAr,
            type: item.type,
            price: item.price,
            priceAfter: effectivePrice,
            image: item.image,
            imageDataUrl: item.imageDataUrl,
          },
        });
      }
    }

    await Learning.updateOne({ _id: item._id }, { $inc: { views: 1 } });
    await recordUserLearningView(req.user.userId, item._id, item.type);

    const courseVideos = Array.isArray(item.courseVideos)
      ? item.courseVideos.map((v, idx) => ({
          ...v,
          id: v._id || v.id,
          order: v.order ?? idx + 1,
        }))
      : [];

    const { imageDataUrl, source, ...safeItem } = item;
    const isArticleItem = String(item.type || "").toLowerCase().includes("article");
    const deliveryImage =
      item.thumbnail?.url ||
      (item.image && !String(item.image).startsWith("data:")
        ? item.image
        : imageDataUrl
        ? `/api/learning/${item._id}/image`
        : "");
    const resolvedPlayback = resolveVideoPlaybackForUser(item);

    return res.status(200).json({
      item: {
        ...safeItem,
        id: item._id,
        ...(isArticleItem
          ? {
              author: "Almostaqel Academy",
              instructor: "Almostaqel Academy",
              articleType: resolveArticleType(item),
            }
          : {}),
        publishedAt: item.publishedAt || item.approvedAt || item.createdAt,
        image: deliveryImage,
        videoUrl: resolvedPlayback.playbackUrl || item.videoUrl || "",
        videoMedia: resolvedPlayback,
        courseVideos,
        lessons: courseVideos.length > 0 ? courseVideos.length : item.lessons || 0,
      },
    });
  } catch (err) {
    console.error("Error in protected /api/learning/:id:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/item/:id", userAuth, handleGetProtectedItem);
router.post("/learning/item/:id", userAuth, handleGetProtectedItem);
router.get("/learning/:id", userAuth, handleGetProtectedItem);
router.post("/learning/:id", userAuth, handleGetProtectedItem);

// ============================================================================
// 3. PATCH /api/learning/:id/view - Lightweight View Tracking
// ============================================================================
router.patch("/learning/:id/view", async (req, res) => {
  try {
    const rawId = String(req.params.id || "").trim();
    if (!rawId) {
      return res.status(404).json({ message: "Learning item not found" });
    }
    const identifierFilter = mongoose.isValidObjectId(rawId)
      ? { $or: [{ _id: rawId }, { slug: rawId.toLowerCase() }] }
      : { slug: rawId.toLowerCase() };
    const item = await Learning.findOneAndUpdate(
      { ...identifierFilter, status: "published" },
      { $inc: { views: 1 } },
      { new: true, select: "views" }
    ).lean();

    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    res.status(200).json({ message: "View tracked", views: item.views });
  } catch (err) {
    console.error("Error in PATCH /api/learning/:id/view:", err);
    res.status(500).json({ message: "Failed to track view" });
  }
});

export default router;
