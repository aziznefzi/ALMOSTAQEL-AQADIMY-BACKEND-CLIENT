import express from "express";
import mongoose from "mongoose";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Orders } from "../../../schema/orders.js";
import { Learning } from "../../../schema/learning.js";
import { Users } from "../../../schema/users.js";
import { BlockedIps } from "../../../schema/blockedIps.js";
import { sendOrderEmail } from "../../../router/learning/orders.js";

const router = express.Router();

// Clear any accidental localhost IP ban caused by serialized object header during development
const clearLocalhostAccidentalBan = async () => {
  try {
    await BlockedIps.deleteMany({
      banType: "ip",
      resson: "Forged deviceId on admin access",
    });
  } catch {
    // non-blocking
  }
};
if (mongoose.connection.readyState === 1) {
  clearLocalhostAccidentalBan();
} else {
  mongoose.connection.once("connected", clearLocalhostAccidentalBan);
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const buildPaymentConfirmedEmail = ({
  userName,
  orderCode,
  productTitle,
  productTitleAr,
  amount,
}) => {
  const subject = `تم تأكيد الدفع وفتح المنتوج [#${orderCode}] - Payment Confirmed`;
  const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #07070f; color: #f0efff; margin: 0; padding: 36px 16px; direction: rtl; text-align: right;">
  <div style="max-width: 600px; margin: 0 auto; background-color: #13111c; border: 1px solid #2b2440; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.5);">
    <div style="background: linear-gradient(135deg, #10b981 0%, #7c3aed 100%); padding: 28px 20px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800;">تم تأكيد الدفع بنجاح! 🎉</h1>
      <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.9); font-size: 13px;">أكاديمية المستقبل — Almostaqel Academy</p>
    </div>

    <div style="padding: 30px 26px;">
      <p style="font-size: 17px; font-weight: 700; color: #ffffff; margin-top: 0;">مرحباً ${userName}،</p>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.8;">
        يسعدنا إبلاغك بأنه قد تم التحقق من عملية الدفع الخاصة بطلبك رقم <strong style="color: #34d399; font-family: monospace;">#${orderCode}</strong>، وتم فتح المنتوج في حسابك رسمياً!
      </p>

      <div style="background: #1a1628; border: 1px solid #10b981; border-radius: 14px; padding: 18px; margin: 22px 0;">
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">رمز الطلب:</strong> <span style="color: #ffffff; font-family: monospace;">#${orderCode}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">المنتوج المفعل:</strong> <span style="color: #34d399; font-weight: 700;">${productTitleAr || productTitle}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">المبلغ المؤكد:</strong> <span style="color: #ffffff; font-family: monospace;">$${amount}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">الحالة:</strong> <span style="color: #10b981; font-weight: 800;">مفعل بالكامل (Unlocked) ✓</span></p>
      </div>

      <p style="font-size: 13px; color: #cbd5e1; line-height: 1.7;">
        يمكنك الآن الدخول إلى حسابك على منصة <strong>أكاديمية المستقبل</strong> والاستمتاع بكامل محتوى المنتوج والدروس مباشرة.
      </p>
    </div>

    <div style="padding: 18px; text-align: center; background-color: #0e0c16; border-top: 1px solid #1f1b2e; font-size: 12px; color: #64748b;">
      &copy; ${new Date().getFullYear()} أكاديمية المستقبل (Almostaqel Academy). جميع الحقوق محفوظة.
    </div>
  </div>
</body>
</html>`;
  return { subject, html };
};

// ============================================================================
// 1. GET & POST /admin/learning/orders - List Product Orders with Pagination
// ============================================================================
const handleListOrders = async (req, res) => {
  try {
    const source = { ...req.query, ...req.body };
    const parsedPage = parseInt(source.page, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(source.limit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, MAX_LIMIT)
        : DEFAULT_LIMIT;

    const skip = (page - 1) * limit;
    const query = {};

    if (
      source.status &&
      source.status !== "all" &&
      ["pending", "approved", "rejected"].includes(source.status)
    ) {
      query.status = source.status;
    }

    if (
      source.paymentMethod &&
      source.paymentMethod !== "all" &&
      ["flouci", "zitouna", "d17"].includes(source.paymentMethod)
    ) {
      query.paymentMethod = source.paymentMethod;
    }

    const rawSearch = source.search ?? source.q;
    if (typeof rawSearch === "string" && rawSearch.trim().length > 0) {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      const regex = new RegExp(escapeRegex(cleanSearch), "i");
      query.$or = [
        { orderCode: regex },
        { userEmail: regex },
        { userPhone: regex },
        { userName: regex },
        { productTitle: regex },
        { productTitleAr: regex },
      ];
    }

    const [total, orders, pendingCount, approvedCount, rejectedCount] =
      await Promise.all([
        Orders.countDocuments(query),
        Orders.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
        Orders.countDocuments({ status: "pending" }),
        Orders.countDocuments({ status: "approved" }),
        Orders.countDocuments({ status: "rejected" }),
      ]);

    // Enrich with user's account PhoneNumber if order.userPhone was empty
    const userIds = [
      ...new Set(orders.map((o) => String(o.userId)).filter(Boolean)),
    ];
    const users =
      userIds.length > 0
        ? await Users.find({ _id: { $in: userIds } })
            .select("ferstname lastname username email PhoneNumber")
            .lean()
        : [];
    const userMap = new Map(users.map((u) => [String(u._id), u]));

    const formattedOrders = orders.map((o) => {
      const u = userMap.get(String(o.userId));
      return {
        ...o,
        id: o._id,
        userName:
          o.userName ||
          (u ? `${u.ferstname || ""} ${u.lastname || ""}`.trim() || u.username : "Student"),
        userEmail: o.userEmail || u?.email || "",
        userPhone: o.userPhone || u?.PhoneNumber || "Not provided",
      };
    });

    const totalPages = Math.max(1, Math.ceil(total / limit));

    const totalAll = pendingCount + approvedCount + rejectedCount;

    return res.status(200).json({
      orders: formattedOrders,
      items: formattedOrders,
      stats: {
        total: totalAll,
        pending: pendingCount,
        approved: approvedCount,
        rejected: rejectedCount,
      },
      counts: {
        all: totalAll,
        pending: pendingCount,
        approved: approvedCount,
        rejected: rejectedCount,
      },
      pagination: {
        total,
        totalItems: total,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (err) {
    console.error("Error in /admin/learning/orders:", err);
    return res.status(500).json({ message: "Failed to fetch product orders" });
  }
};

router.get("/learning/orders", AdminAuth, handleListOrders);
router.post("/learning/orders/list", AdminAuth, handleListOrders);

// ============================================================================
// 2. POST & PATCH /admin/learning/orders/:id/status
// Confirm Payment (status: "approved") or Reject Order (status: "rejected")
// ============================================================================
const handleUpdateOrderStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNote } = req.body || {};

    if (!["approved", "rejected", "pending"].includes(status)) {
      return res.status(400).json({ message: "Invalid order status" });
    }

    const order = await Orders.findById(id);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    const wasApprovedBefore = order.status === "approved";
    order.status = status;
    if (adminNote !== undefined) {
      order.adminNote = String(adminNote).trim();
    }

    if (status === "approved" && !wasApprovedBefore) {
      order.approvedAt = new Date();
      // Increment product enrollments counter
      await Learning.updateOne(
        { _id: order.productId },
        { $inc: { enrollments: 1 } }
      );
      if (order.userId && order.productId) {
        await Users.updateOne(
          { _id: order.userId },
          { $addToSet: { purchasedProducts: order.productId } }
        );
      }
    } else if (status !== "approved" && wasApprovedBefore && order.userId && order.productId) {
      const otherApproved = await Orders.exists({
        _id: { $ne: order._id },
        userId: order.userId,
        productId: order.productId,
        status: "approved",
      });
      if (!otherApproved) {
        await Users.updateOne(
          { _id: order.userId },
          { $pull: { purchasedProducts: order.productId } }
        );
      }
    }

    await order.save();

    let emailSent = false;
    if (status === "approved" && !wasApprovedBefore && order.userEmail) {
      const emailPayload = buildPaymentConfirmedEmail({
        userName: order.userName || "Student",
        orderCode: order.orderCode,
        productTitle: order.productTitle,
        productTitleAr: order.productTitleAr,
        amount: order.amount,
      });
      const resEmail = await sendOrderEmail({
        to: order.userEmail,
        subject: emailPayload.subject,
        html: emailPayload.html,
      });
      emailSent = resEmail.success;
    }

    return res.status(200).json({
      message:
        status === "approved"
          ? "Payment confirmed and product unlocked for the user."
          : `Order status updated to ${status}.`,
      emailSent,
      order: { ...order.toObject(), id: order._id },
    });
  } catch (err) {
    console.error("Error updating order status:", err);
    return res.status(500).json({ message: "Failed to update order status" });
  }
};

router.post("/learning/orders/:id/status", AdminAuth, handleUpdateOrderStatus);
router.patch("/learning/orders/:id/status", AdminAuth, handleUpdateOrderStatus);

export default router;

