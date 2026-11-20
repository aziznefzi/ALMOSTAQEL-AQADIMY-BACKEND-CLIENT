import express from "express";
import mongoose from "mongoose";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";
import { getMsg } from "../../../utils/messages.js";
import { validateAndNormalizeImageMedia } from "../../../utils/mediaValidation.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "views", "readTime", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "pending", "published", "draft", "archived"];
const ALLOWED_ARTICLE_STATUSES = ["pending", "published", "draft", "archived"];

const formatArticleDoc = (doc) => {
  const obj = typeof doc.toObject === "function" ? doc.toObject() : doc;
  return {
    ...obj,
    id: obj._id,
    source: obj.source || "admin",
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
          { slug: regex },
          { excerpt: regex },
          { description: regex },
          { descriptionAr: regex },
          { author: regex },
          { category: regex },
          { tag: regex },
          { tags: regex },
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
      slug,
      excerpt,
      excerptAr,
      description,
      descriptionAr,
      content,
      contentAr,
      category,
      tag,
      tags,
      author,
      instructor,
      readTime,
      price,
      priceAfter,
      status,
      image,
      thumbnail,
      imageDataUrl,
      stack,
      rating,
      seo,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "Article title is required" });
    }

    const imageCheck = validateAndNormalizeImageMedia({
      image,
      thumbnail,
      imageDataUrl,
      allowExistingLegacyPath: false,
    });
    if (!imageCheck.valid) {
      return res.status(400).json({
        message: getMsg(imageCheck.errorCode || "invalidImageUrl", req),
        details: imageCheck.error,
      });
    }

    const normalizedTags = Array.isArray(tags)
      ? tags.map((t) => String(t).trim()).filter(Boolean)
      : [];
    const cleanSlug = typeof slug === "string" && slug.trim() ? slug.trim().toLowerCase() : undefined;

    const newArticle = await Learning.create({
      type: "article",
      source: "admin",
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      ...(cleanSlug ? { slug: cleanSlug } : {}),
      excerpt: excerpt?.trim() || description?.trim() || "",
      excerptAr: excerptAr?.trim() || descriptionAr?.trim() || "",
      description: description?.trim() || excerpt?.trim() || "",
      descriptionAr: descriptionAr?.trim() || excerptAr?.trim() || "",
      content: content?.trim() || description?.trim() || "",
      contentAr: contentAr?.trim() || descriptionAr?.trim() || "",
      category: category?.trim() || "Tech Insights",
      tag: tag?.trim() || normalizedTags[0] || category?.trim() || "General",
      tags: normalizedTags,
      author: author?.trim() || instructor?.trim() || "",
      instructor: instructor?.trim() || author?.trim() || "",
      readTime: Number(readTime) || 5,
      price: Number(price) || 0,
      priceAfter: priceAfter !== undefined ? Number(priceAfter) : Number(price) || 0,
      status: ALLOWED_ARTICLE_STATUSES.includes(status) ? status : "published",
      rating: Number(rating) || 5.0,
      image: imageCheck.image,
      thumbnail: imageCheck.thumbnail,
      imageDataUrl: "",
      stack: Array.isArray(stack) ? stack : [],
      ...(seo && typeof seo === "object" && !Array.isArray(seo) ? { seo } : {}),
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

    if (
      req.body.image !== undefined ||
      req.body.thumbnail !== undefined ||
      req.body.imageDataUrl !== undefined
    ) {
      const incomingImageDataUrl =
        req.body.imageDataUrl && req.body.imageDataUrl !== article.imageDataUrl
          ? req.body.imageDataUrl
          : undefined;
      const imageCheck = validateAndNormalizeImageMedia({
        image: req.body.image !== undefined ? req.body.image : article.image,
        thumbnail: req.body.thumbnail,
        imageDataUrl: incomingImageDataUrl,
        existingImage: article.image || "",
        allowExistingLegacyPath: true,
      });
      if (!imageCheck.valid) {
        return res.status(400).json({
          message: getMsg(imageCheck.errorCode || "invalidImageUrl", req),
          details: imageCheck.error,
        });
      }
      article.image = imageCheck.image;
      article.thumbnail = imageCheck.thumbnail;
      if (imageCheck.clearLegacyDataUrl) {
        article.imageDataUrl = "";
      }
    }

    const updatable = [
      "title",
      "titleAr",
      "slug",
      "excerpt",
      "excerptAr",
      "description",
      "descriptionAr",
      "content",
      "contentAr",
      "category",
      "tag",
      "tags",
      "author",
      "instructor",
      "readTime",
      "price",
      "priceAfter",
      "status",
      "stack",
      "rating",
      "seo",
    ];

    for (const key of updatable) {
      if (req.body[key] !== undefined) {
        if (key === "slug") {
          const cleanSlug = typeof req.body.slug === "string" ? req.body.slug.trim().toLowerCase() : "";
          article.slug = cleanSlug || undefined;
        } else {
          article[key] = req.body[key];
        }
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

    if (req.body.status && ALLOWED_ARTICLE_STATUSES.includes(req.body.status)) {
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
// 5B. PATCH /api/articles/:id/approve & PATCH /admin/learning/articles/:id/approve
// Admin approval workflow: publishes a pending AI Agent article
// ============================================================================
export const handleApproveArticle = async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({
        success: false,
        message: getMsg("invalidArticleId", req),
      });
    }

    const article = await Learning.findOne({
      _id: id,
      type: { $in: ["article", "Articles"] },
    });

    if (!article) {
      return res.status(404).json({
        success: false,
        message: getMsg("articleNotFound", req),
      });
    }

    article.status = "published";
    if (!article.availabilityStatus || article.availabilityStatus === "preorder") {
      article.availabilityStatus = "available";
    }
    article.approvedAt = new Date();
    if (req.admin?._id) {
      article.approvedBy = req.admin._id;
    }

    await article.save();

    const formatted = formatArticleDoc(article);
    return res.status(200).json({
      success: true,
      message: getMsg("articleApprovedSuccess", req),
      article: formatted,
      item: formatted,
    });
  } catch (err) {
    console.error("Error in PATCH /api/articles/:id/approve:", err);
    return res.status(500).json({
      success: false,
      message: getMsg("serverError", req),
    });
  }
};

router.patch("/learning/articles/:id/approve", AdminAuth, handleApproveArticle);

// Dedicated router mounted at `/api` on adminApp so `PATCH /api/articles/:id/approve`
// is directly accessible to the Admin Dashboard and protected by AdminAuth.
export const articlesAdminApprovalRouter = express.Router();
articlesAdminApprovalRouter.patch("/articles/:id/approve", AdminAuth, handleApproveArticle);

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

