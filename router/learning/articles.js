import express from "express";
import mongoose from "mongoose";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";
import { recordUserLearningView } from "../../utils/trackUserLearningView.js";

const router = express.Router();

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

// ============================================================================
// GET & POST /api/learning/articles/:id - Protected Article Content
// Supports lookup by MongoDB _id or slug; strictly requires status === "published".
// Requires authenticated user + confirmed purchase if paid (priceAfter > 0)
// ============================================================================
const handleGetProtectedArticle = async (req, res) => {
  try {
    const rawId = String(req.params.id || "").trim();
    if (!rawId) {
      return res.status(404).json({ message: getMsg("articleNotFound", req) });
    }

    const identifierFilter = mongoose.isValidObjectId(rawId)
      ? { $or: [{ _id: rawId }, { slug: rawId.toLowerCase() }] }
      : { slug: rawId.toLowerCase() };

    const article = await Learning.findOne({
      ...identifierFilter,
      status: "published",
      type: { $in: ["Articles", "article"] },
    }).lean();

    if (!article) {
      return res.status(404).json({ message: getMsg("articleNotFound", req) });
    }

    const availability = article.availabilityStatus || "preorder";
    if (availability === "unavailable") {
      return res.status(403).json({
        message: "هذا المقال غير متوفر في الوقت الحالي.",
        unavailable: true,
        productId: article._id,
      });
    }
    if (availability === "preorder") {
      return res.status(403).json({
        message: "هذا المقال في مرحلة الطلب المسبق حالياً.",
        isPreorder: true,
        productId: article._id,
      });
    }

    const effectivePrice = Number(article.priceAfter ?? article.price ?? 0);

    if (effectivePrice > 0) {
      const isPurchasedInUserDoc =
        Array.isArray(req.dbUser?.purchasedProducts) &&
        req.dbUser.purchasedProducts.some(
          (pid) => String(pid) === String(article._id)
        );
      const approvedOrder = isPurchasedInUserDoc
        ? true
        : await Orders.findOne({
            userId: req.user.userId,
            productId: article._id,
            status: "approved",
          }).lean();

      if (!approvedOrder) {
        const pendingOrder = await Orders.findOne({
          userId: req.user.userId,
          productId: article._id,
          status: "pending",
        })
          .sort({ createdAt: -1 })
          .lean();

        return res.status(403).json({
          message:
            "You must purchase this item and have your payment confirmed to access its content.",
          requiresPurchase: true,
          hasPendingOrder: Boolean(pendingOrder),
          orderCode: pendingOrder?.orderCode || null,
          paymentMethod: pendingOrder?.paymentMethod || null,
          productSummary: {
            id: article._id,
            title: article.title,
            titleAr: article.titleAr,
            type: article.type,
            price: article.price,
            priceAfter: effectivePrice,
            image: article.image,
            imageDataUrl: article.imageDataUrl,
          },
        });
      }
    }

    await Learning.updateOne({ _id: article._id }, { $inc: { views: 1 } });
    await recordUserLearningView(req.user.userId, article._id, "article");

    const { imageDataUrl, source, ...safeArticle } = article;
    const deliveryImage =
      article.thumbnail?.url ||
      (article.image && !String(article.image).startsWith("data:")
        ? article.image
        : imageDataUrl
        ? `/api/learning/${article._id}/image`
        : "");

    return res.status(200).json({
      item: {
        ...safeArticle,
        id: article._id,
        author: "Almostaqel Academy",
        instructor: "Almostaqel Academy",
        articleType: resolveArticleType(article),
        publishedAt: article.publishedAt || article.approvedAt || article.createdAt,
        image: deliveryImage,
      },
    });
  } catch (err) {
    console.error("Error in protected article route:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/articles/:id", userAuth, handleGetProtectedArticle);
router.post("/learning/articles/:id", userAuth, handleGetProtectedArticle);

export default router;
