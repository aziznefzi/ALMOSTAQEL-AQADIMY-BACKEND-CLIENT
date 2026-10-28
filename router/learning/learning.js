import express from "express";
import { Learning } from "../../schema/learning.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const ALLOWED_SORT_FIELDS = ["createdAt", "views", "enrollments", "rating", "price", "title"];

// ============================================================================
// 1. GET /api/learning - Fetch Public Learning Content (Courses, Articles, Videos)
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
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1
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
      else if (t.includes("all") || t.includes("ai")) query.type = { $in: ["ai-video", "All Vidios", "ai_video"] };
      else if (t.includes("video")) query.type = { $in: ["video", "Videos"] };
      else query.type = rawType;
    }

    // Filter by category
    if (rawCategory && rawCategory !== "all" && rawCategory !== "All") {
      query.$or = [
        { category: rawCategory },
        { tag: rawCategory }
      ];
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
    console.error("Error in GET /api/learning:", err);
    res.status(500).json({ message: "Failed to fetch learning items" });
  }
});

// ============================================================================
// 2. GET /api/learning/:id - Fetch Single Learning Item & Track Views
// ============================================================================
router.get("/learning/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findOneAndUpdate(
      { _id: id, status: "published" },
      { $inc: { views: 1 } },
      { new: true }
    ).lean();

    if (!item) {
      return res.status(404).json({ message: "Learning item not found" });
    }

    res.status(200).json({ item: { ...item, id: item._id } });
  } catch (err) {
    console.error("Error in GET /api/learning/:id:", err);
    res.status(500).json({ message: "Failed to fetch item details" });
  }
});

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
