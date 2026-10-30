import express from "express";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "views", "readTime", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "published", "draft", "archived"];

const formatArticleDoc = (doc) => {
  const obj = typeof doc.toObject === "function" ? doc.toObject() : doc;
  return {
    ...obj,
    id: obj._id,
  };
};

// ============================================================================
// 1. GET & POST /admin/learning/articles - Fetch Paginated Articles
// ============================================================================
const handleGetArticles = async (req, res) => {
  try {
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawSearch = req.query.search ?? req.body?.search;
    const rawStatus = req.query.status ?? req.body?.status ?? req.query.filter ?? req.body?.filter;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1 ? Math.min(parsedLimit, 100) : 50;
    const skip = (page - 1) * limit;

    const query = { type: { $in: ["article", "Articles"] } };

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
          { author: regex },
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
      items: items.map(formatArticleDoc),
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
    console.error("Error in handleGetArticles:", err);
    res.status(500).json({ message: "Failed to fetch articles" });
  }
};

router.get("/learning/articles", AdminAuth, handleGetArticles);
router.post("/learning/articles/list", AdminAuth, handleGetArticles);

// ============================================================================
// 2. GET /admin/learning/articles/:id - Get Single Article Details
// ============================================================================
router.get("/learning/articles/:id", AdminAuth, async (req, res) => {
  try {
    const article = await Learning.findById(req.params.id).lean();
    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }
    res.status(200).json({ item: formatArticleDoc(article) });
  } catch (err) {
    console.error("Error in GET /learning/articles/:id:", err);
    res.status(500).json({ message: "Failed to fetch article details" });
  }
});

// ============================================================================
// 3. POST /admin/learning/articles - Create Article
// ============================================================================
router.post("/learning/articles", AdminAuth, async (req, res) => {
  try {
    const {
      title,
      titleAr,
      description,
      descriptionAr,
      content,
      contentAr,
      category,
      tag,
      author,
      instructor,
      readTime,
      price,
      priceAfter,
      status,
      image,
      imageDataUrl,
      stack,
      rating,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "Article title is required" });
    }

    const newArticle = await Learning.create({
      type: "article",
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      description: description?.trim() || "",
      descriptionAr: descriptionAr?.trim() || "",
      content: content?.trim() || description?.trim() || "",
      contentAr: contentAr?.trim() || descriptionAr?.trim() || "",
      category: category?.trim() || "Tech Insights",
      tag: tag?.trim() || category?.trim() || "General",
      author: author?.trim() || instructor?.trim() || "",
      instructor: instructor?.trim() || author?.trim() || "",
      readTime: Number(readTime) || 5,
      price: Number(price) || 0,
      priceAfter: priceAfter !== undefined ? Number(priceAfter) : Number(price) || 0,
      status: ["published", "draft", "archived"].includes(status) ? status : "published",
      rating: Number(rating) || 5.0,
      image: image?.trim() || "",
      imageDataUrl: imageDataUrl || "",
      stack: Array.isArray(stack) ? stack : [],
    });

    res.status(201).json({
      message: "Article created successfully",
      item: formatArticleDoc(newArticle),
    });
  } catch (err) {
    console.error("Error in POST /learning/articles:", err);
    res.status(500).json({ message: "Failed to create article" });
  }
});

// ============================================================================
// 4. PUT /admin/learning/articles/:id - Update Article
// ============================================================================
router.put("/learning/articles/:id", AdminAuth, async (req, res) => {
  try {
    const article = await Learning.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    const updatable = [
      "title",
      "titleAr",
      "description",
      "descriptionAr",
      "content",
      "contentAr",
      "category",
      "tag",
      "author",
      "instructor",
      "readTime",
      "price",
      "priceAfter",
      "status",
      "image",
      "imageDataUrl",
      "stack",
      "rating",
    ];

    for (const key of updatable) {
      if (req.body[key] !== undefined) {
        article[key] = req.body[key];
      }
    }

    await article.save();

    res.status(200).json({
      message: "Article updated successfully",
      item: formatArticleDoc(article),
    });
  } catch (err) {
    console.error("Error in PUT /learning/articles/:id:", err);
    res.status(500).json({ message: "Failed to update article" });
  }
});

// ============================================================================
// 5. PATCH /admin/learning/articles/:id/status - Archive / Hide / Publish Article
// ============================================================================
router.patch("/learning/articles/:id/status", AdminAuth, async (req, res) => {
  try {
    const article = await Learning.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    if (req.body.status && ["published", "draft", "archived"].includes(req.body.status)) {
      article.status = req.body.status;
    } else {
      article.status = article.status === "published" ? "archived" : "published";
    }

    await article.save();

    res.status(200).json({
      message: "Article status updated successfully",
      status: article.status,
      item: formatArticleDoc(article),
    });
  } catch (err) {
    console.error("Error in PATCH /learning/articles/:id/status:", err);
    res.status(500).json({ message: "Failed to update article status" });
  }
});

// ============================================================================
// 6. DELETE /admin/learning/articles/:id - Delete Article
// ============================================================================
router.delete("/learning/articles/:id", AdminAuth, async (req, res) => {
  try {
    const deleted = await Learning.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ message: "Article not found" });
    }
    res.status(200).json({ message: "Article deleted successfully" });
  } catch (err) {
    console.error("Error in DELETE /learning/articles/:id:", err);
    res.status(500).json({ message: "Failed to delete article" });
  }
});

export default router;

