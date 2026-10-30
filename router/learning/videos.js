import express from "express";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";

const router = express.Router();

// ============================================================================
// GET & POST /api/learning/videos/:id - Protected Learning Video Content
// Requires authenticated user + confirmed purchase if paid (priceAfter > 0)
// ============================================================================
const handleGetProtectedVideo = async (req, res) => {
  try {
    const { id } = req.params;
    const video = await Learning.findOne({
      _id: id,
      status: "published",
      type: { $in: ["Videos", "video", "All Vidios", "ai-video", "ai_video"] },
    }).lean();

    if (!video) {
      return res.status(404).json({ message: "Learning video not found" });
    }

    const availability = video.availabilityStatus || "preorder";
    if (availability === "unavailable") {
      return res.status(403).json({
        message: "هذا الفيديو التعليمي غير متوفر في الوقت الحالي.",
        unavailable: true,
        productId: video._id,
      });
    }
    if (availability === "preorder") {
      return res.status(403).json({
        message: "هذا الفيديو التعليمي في مرحلة الطلب المسبق حالياً.",
        isPreorder: true,
        productId: video._id,
      });
    }

    const effectivePrice = Number(video.priceAfter ?? video.price ?? 0);

    // STRICT PURCHASE ENFORCEMENT: If paid, verify confirmed order or Users.purchasedProducts in DB
    if (effectivePrice > 0) {
      const isPurchasedInUserDoc =
        Array.isArray(req.dbUser?.purchasedProducts) &&
        req.dbUser.purchasedProducts.some(
          (pid) => String(pid) === String(video._id)
        );
      const approvedOrder = isPurchasedInUserDoc
        ? true
        : await Orders.findOne({
            userId: req.user.userId,
            productId: video._id,
            status: "approved",
          }).lean();

      if (!approvedOrder) {
        const pendingOrder = await Orders.findOne({
          userId: req.user.userId,
          productId: video._id,
          status: "pending",
        })
          .sort({ createdAt: -1 })
          .lean();

        return res.status(403).json({
          message:
            "You must purchase this workshop/video and have your payment confirmed to watch it.",
          requiresPurchase: true,
          hasPendingOrder: Boolean(pendingOrder),
          orderCode: pendingOrder?.orderCode || null,
          paymentMethod: pendingOrder?.paymentMethod || null,
          productSummary: {
            id: video._id,
            title: video.title,
            titleAr: video.titleAr,
            type: video.type,
            price: video.price,
            priceAfter: effectivePrice,
            image: video.image,
            imageDataUrl: video.imageDataUrl,
          },
        });
      }
    }

    await Learning.updateOne({ _id: video._id }, { $inc: { views: 1 } });

    return res.status(200).json({
      item: { ...video, id: video._id },
    });
  } catch (err) {
    console.error("Error in protected video route:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/videos/:id", userAuth, handleGetProtectedVideo);
router.post("/learning/videos/:id", userAuth, handleGetProtectedVideo);

export default router;
