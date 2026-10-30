import express from "express";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";

const router = express.Router();

const formatCourseForStudent = (doc) => {
  if (!doc) return null;
  const obj = typeof doc.toObject === "function" ? doc.toObject() : doc;
  const courseVideos = Array.isArray(obj.courseVideos)
    ? obj.courseVideos.map((v, idx) => ({
        ...v,
        id: v._id || v.id,
        order: v.order ?? idx + 1,
      }))
    : [];

  return {
    ...obj,
    id: obj._id,
    courseVideos,
    lessons: courseVideos.length > 0 ? courseVideos.length : obj.lessons || 0,
  };
};

// ============================================================================
// GET & POST /api/learning/courses/:id - Protected Course Content & Videos
// Requires authenticated user + confirmed purchase if paid (priceAfter > 0)
// ============================================================================
const handleGetProtectedCourse = async (req, res) => {
  try {
    const { id } = req.params;
    const course = await Learning.findOne({
      _id: id,
      status: "published",
      type: { $in: ["Courses", "course"] },
    }).lean();

    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    const availability = course.availabilityStatus || "preorder";
    if (availability === "unavailable") {
      return res.status(403).json({
        message: "هذا الكورس غير متوفر في الوقت الحالي.",
        unavailable: true,
        productId: course._id,
      });
    }
    if (availability === "preorder") {
      return res.status(403).json({
        message: "هذا الكورس في مرحلة الطلب المسبق حالياً.",
        isPreorder: true,
        productId: course._id,
      });
    }

    const effectivePrice = Number(course.priceAfter ?? course.price ?? 0);

    // STRICT PURCHASE ENFORCEMENT: If paid, verify confirmed order or Users.purchasedProducts in DB
    if (effectivePrice > 0) {
      const isPurchasedInUserDoc =
        Array.isArray(req.dbUser?.purchasedProducts) &&
        req.dbUser.purchasedProducts.some(
          (pid) => String(pid) === String(course._id)
        );
      const approvedOrder = isPurchasedInUserDoc
        ? true
        : await Orders.findOne({
            userId: req.user.userId,
            productId: course._id,
            status: "approved",
          }).lean();

      if (!approvedOrder) {
        const pendingOrder = await Orders.findOne({
          userId: req.user.userId,
          productId: course._id,
          status: "pending",
        })
          .sort({ createdAt: -1 })
          .lean();

        return res.status(403).json({
          message:
            "You must purchase this course and have your payment confirmed to access its lessons.",
          requiresPurchase: true,
          hasPendingOrder: Boolean(pendingOrder),
          orderCode: pendingOrder?.orderCode || null,
          paymentMethod: pendingOrder?.paymentMethod || null,
          productSummary: {
            id: course._id,
            title: course.title,
            titleAr: course.titleAr,
            type: course.type,
            price: course.price,
            priceAfter: effectivePrice,
            image: course.image,
            imageDataUrl: course.imageDataUrl,
          },
        });
      }
    }

    await Learning.updateOne({ _id: course._id }, { $inc: { views: 1 } });

    return res.status(200).json({
      item: formatCourseForStudent(course),
    });
  } catch (err) {
    console.error("Error in protected course route:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/courses/:id", userAuth, handleGetProtectedCourse);
router.post("/learning/courses/:id", userAuth, handleGetProtectedCourse);

export default router;
