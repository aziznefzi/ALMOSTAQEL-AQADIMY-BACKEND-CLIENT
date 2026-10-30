import express from "express";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";
import coursesRouter from "./courses.js";
import articlesRouter from "./articles.js";
import videosRouter from "./videos.js";
import ordersRouter from "./orders.js";

const router = express.Router();

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

// Strip protected media/article body from public catalog cards
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
    content,
    contentAr,
    preorders,
    ...publicFields
  } = item;

  return {
    ...publicFields,
    id: item._id,
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
    const query = { status: "published" };

    // Filter by type
    if (rawType && rawType !== "all") {
      const t = String(rawType).toLowerCase().trim();
      if (t.includes("course")) query.type = { $in: ["course", "Courses"] };
      else if (t.includes("article")) query.type = { $in: ["article", "Articles"] };
      else if (t.includes("all") || t.includes("ai"))
        query.type = { $in: ["ai-video", "All Vidios", "ai_video"] };
      else if (t.includes("video")) query.type = { $in: ["video", "Videos"] };
      else query.type = rawType;
    }

    // Filter by category
    if (rawCategory && rawCategory !== "all" && rawCategory !== "All") {
      query.$or = [{ category: rawCategory }, { tag: rawCategory }];
    }

    // Filter by level
    if (rawLevel && ["Beginner", "Intermediate", "Advanced"].includes(rawLevel)) {
      query.level = rawLevel;
    }

    // Safe Search
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
          { instructorAr: regex },
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
// 2. GET & POST /api/learning/:id - Fetch Protected Single Learning Item Content
// Strictly protected by userAuth + Confirmed Purchase Check if paid
// ============================================================================
const handleGetProtectedItem = async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findOne({ _id: id, status: "published" }).lean();

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

    const courseVideos = Array.isArray(item.courseVideos)
      ? item.courseVideos.map((v, idx) => ({
          ...v,
          id: v._id || v.id,
          order: v.order ?? idx + 1,
        }))
      : [];

    return res.status(200).json({
      item: {
        ...item,
        id: item._id,
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
    const { id } = req.params;
    const item = await Learning.findOneAndUpdate(
      { _id: id, status: "published" },
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
