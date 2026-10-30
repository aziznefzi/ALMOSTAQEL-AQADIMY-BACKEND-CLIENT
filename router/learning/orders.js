import express from "express";
import crypto from "crypto";
import { Resend } from "resend";
import nodemailer from "nodemailer";
import { Learning } from "../../schema/learning.js";
import { Orders } from "../../schema/orders.js";
import { Users } from "../../schema/users.js";
import { userAuth } from "../../middleware/userAuth.js";
import { getMsg } from "../../utils/messages.js";

const router = express.Router();

const PAYMENT_METHODS_INFO = {
  flouci: {
    nameEn: "Flouci",
    nameAr: "تطبيق فلوسي (Flouci)",
    getRib: () =>
      process.env.RIB_FLOUCI || "TN59 2500 1000 0000 1948 5271 (Flouci Wallet / RIB)",
  },
  zitouna: {
    nameEn: "Banque Zitouna",
    nameAr: "بنك الزيتونة (Banque Zitouna)",
    getRib: () =>
      process.env.RIB_ZITOUNA || "TN59 2500 9000 0000 8492 3164 (Banque Zitouna RIB)",
  },
  d17: {
    nameEn: "D-17 (La Poste Tunisienne)",
    nameAr: "تطبيق D-17 (البريد التونسي)",
    getRib: () =>
      process.env.RIB_D17 || "TN59 1700 0000 0000 5629 1840 (D-17 / e-Dinar RIB)",
  },
};

const generateOrderCode = () => {
  const part1 = Date.now().toString(36).toUpperCase().slice(-6);
  const part2 = crypto.randomInt(1000, 9999);
  return `ORD-${part1}-${part2}`;
};

const buildOrderPaymentEmail = ({
  userName,
  orderCode,
  products,
  totalAmount,
  paymentMethod,
  ribCode,
  isAr,
}) => {
  const methodInfo = PAYMENT_METHODS_INFO[paymentMethod] || PAYMENT_METHODS_INFO.zitouna;
  const productRowsHtml = products
    .map(
      (p) =>
        `<tr>
          <td style="padding: 10px 12px; border-bottom: 1px solid #2d2644; color: #f8fafc; font-weight: 600;">${
            isAr ? p.productTitleAr || p.productTitle : p.productTitle
          }</td>
          <td style="padding: 10px 12px; border-bottom: 1px solid #2d2644; color: #ec4899; font-family: monospace; font-weight: 700; text-align: ${
            isAr ? "left" : "right"
          };">$${p.amount}</td>
        </tr>`
    )
    .join("");

  if (isAr) {
    const subject = `تفاصيل الدفع ورمز الـ RIB للطلب [#${orderCode}] - أكاديمية المستقبل`;
    const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #07070f; color: #f0efff; margin: 0; padding: 36px 16px; direction: rtl; text-align: right;">
  <div style="max-width: 620px; margin: 0 auto; background-color: #13111c; border: 1px solid #2b2440; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.5);">
    <div style="background: linear-gradient(135deg, #7c3aed 0%, #db2777 100%); padding: 28px 20px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800;">أكاديمية المستقبل — Almostaqel Academy</h1>
      <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.9); font-size: 13px;">تعليمات إتمام الدفع وتفعيل المنتوج التعليمي</p>
    </div>

    <div style="padding: 30px 26px;">
      <p style="font-size: 17px; font-weight: 700; color: #ffffff; margin-top: 0;">مرحباً ${userName}،</p>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.8;">
        شكراً لطلبك من <strong>أكاديمية المستقبل</strong>. تم تسجيل طلب الشراء الخاص بك بنجاح. يرجى استخدام <strong>رمز الـ RIB</strong> الموضح أدناه لإتمام عملية الدفع عبر وسيلة الدفع التي اخترتها (<strong>${methodInfo.nameAr}</strong>).
      </p>

      <!-- Order Code Box -->
      <div style="background: rgba(124, 58, 237, 0.14); border: 2px dashed #8b5cf6; border-radius: 14px; padding: 18px; margin: 22px 0; text-align: center;">
        <p style="margin: 0 0 6px 0; font-size: 12px; color: #c4b5fd;">رمز الطلب الخاص بك (احتفظ به لمراجعة الطلب وتأكيد الدفع):</p>
        <p style="margin: 0; font-size: 24px; font-weight: 900; font-family: monospace; color: #ffffff; letter-spacing: 1.5px;">#${orderCode}</p>
      </div>

      <!-- RIB Box -->
      <div style="background: rgba(16, 185, 129, 0.12); border: 2px solid #10b981; border-radius: 14px; padding: 20px; margin: 22px 0;">
        <p style="margin: 0 0 8px 0; font-size: 13px; color: #6ee7b7; font-weight: 700;">وسيلة الدفع المختارة: ${methodInfo.nameAr}</p>
        <p style="margin: 0 0 6px 0; font-size: 12px; color: #94a3b8;">رمز الحساب / الـ RIB للتحويل:</p>
        <div style="background: #090812; border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 10px; padding: 14px; font-family: monospace; font-size: 16px; font-weight: 800; color: #34d399; text-align: center; direction: ltr;">
          ${ribCode}
        </div>
      </div>

      <!-- Products Summary -->
      <div style="background: #1a1628; border: 1px solid #2d2644; border-radius: 14px; padding: 16px; margin: 22px 0;">
        <p style="margin: 0 0 10px 0; font-size: 13px; color: #94a3b8; font-weight: 700;">تفاصيل المنتوجات المطلوبة:</p>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          ${productRowsHtml}
          <tr>
            <td style="padding: 12px; color: #ffffff; font-weight: 800;">الإجمالي المطلوب دفعه</td>
            <td style="padding: 12px; color: #10b981; font-family: monospace; font-size: 16px; font-weight: 900; text-align: left;">$${totalAmount}</td>
          </tr>
        </table>
      </div>

      <!-- Next Steps Warning -->
      <div style="background: rgba(245, 158, 11, 0.1); border-right: 4px solid #f59e0b; border-radius: 10px; padding: 16px; margin-top: 22px;">
        <p style="margin: 0 0 6px 0; font-size: 14px; font-weight: 700; color: #fbbf24;">الخطوة التالية لتفعيل المنتوج:</p>
        <p style="margin: 0; font-size: 13px; color: #e2e8f0; line-height: 1.75;">
          بعد إتمام التحويل إلى رمز الـ RIB أعلاه، سنتواصل معك (أو يمكنك الرد على هذا البريد الإلكتروني) وتزويدنا بـ <strong>رمز الطلب (#${orderCode})</strong> مع <strong>وثيقة إثبات الدفع (وصل التحويل / لقطة شاشة)</strong>، ليقوم المشرف بتأكيد الدفع وفتح المنتوج في حسابك فوراً.
        </p>
      </div>
    </div>

    <div style="padding: 20px; text-align: center; background-color: #0e0c16; border-top: 1px solid #1f1b2e; font-size: 12px; color: #64748b;">
      &copy; ${new Date().getFullYear()} أكاديمية المستقبل (Almostaqel Academy). جميع الحقوق محفوظة.
    </div>
  </div>
</body>
</html>`;
    return { subject, html };
  }

  const subject = `Payment Instructions & RIB Code for Order [#${orderCode}] - Almostaqel Academy`;
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #07070f; color: #f0efff; margin: 0; padding: 36px 16px;">
  <div style="max-width: 620px; margin: 0 auto; background-color: #13111c; border: 1px solid #2b2440; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.5);">
    <div style="background: linear-gradient(135deg, #7c3aed 0%, #db2777 100%); padding: 28px 20px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800;">Almostaqel Academy</h1>
      <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.9); font-size: 13px;">Payment Instructions & RIB Details</p>
    </div>

    <div style="padding: 30px 26px;">
      <p style="font-size: 17px; font-weight: 700; color: #ffffff; margin-top: 0;">Hello ${userName},</p>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.8;">
        Thank you for your order with <strong>Almostaqel Academy</strong>. Please use the <strong>RIB / Account Code</strong> below to complete your payment via <strong>${methodInfo.nameEn}</strong>.
      </p>

      <!-- Order Code Box -->
      <div style="background: rgba(124, 58, 237, 0.14); border: 2px dashed #8b5cf6; border-radius: 14px; padding: 18px; margin: 22px 0; text-align: center;">
        <p style="margin: 0 0 6px 0; font-size: 12px; color: #c4b5fd;">Your Unique Order Code (Keep this code for order verification):</p>
        <p style="margin: 0; font-size: 24px; font-weight: 900; font-family: monospace; color: #ffffff; letter-spacing: 1.5px;">#${orderCode}</p>
      </div>

      <!-- RIB Box -->
      <div style="background: rgba(16, 185, 129, 0.12); border: 2px solid #10b981; border-radius: 14px; padding: 20px; margin: 22px 0;">
        <p style="margin: 0 0 8px 0; font-size: 13px; color: #6ee7b7; font-weight: 700;">Selected Payment Method: ${methodInfo.nameEn}</p>
        <p style="margin: 0 0 6px 0; font-size: 12px; color: #94a3b8;">RIB / Account Number for Transfer:</p>
        <div style="background: #090812; border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 10px; padding: 14px; font-family: monospace; font-size: 16px; font-weight: 800; color: #34d399; text-align: center;">
          ${ribCode}
        </div>
      </div>

      <!-- Products Summary -->
      <div style="background: #1a1628; border: 1px solid #2d2644; border-radius: 14px; padding: 16px; margin: 22px 0;">
        <p style="margin: 0 0 10px 0; font-size: 13px; color: #94a3b8; font-weight: 700;">Order Summary:</p>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          ${productRowsHtml}
          <tr>
            <td style="padding: 12px; color: #ffffff; font-weight: 800;">Total Amount Due</td>
            <td style="padding: 12px; color: #10b981; font-family: monospace; font-size: 16px; font-weight: 900; text-align: right;">$${totalAmount}</td>
          </tr>
        </table>
      </div>

      <!-- Next Steps Warning -->
      <div style="background: rgba(245, 158, 11, 0.1); border-left: 4px solid #f59e0b; border-radius: 10px; padding: 16px; margin-top: 22px;">
        <p style="margin: 0 0 6px 0; font-size: 14px; font-weight: 700; color: #fbbf24;">How to Unlock Your Product:</p>
        <p style="margin: 0; font-size: 13px; color: #e2e8f0; line-height: 1.75;">
          Once you complete the transfer to the RIB above, our team will contact you (or you may reply directly to this email) with your <strong>Order Code (#${orderCode})</strong> and your <strong>payment proof receipt/screenshot</strong> so the Admin can confirm your payment and unlock your product immediately.
        </p>
      </div>
    </div>

    <div style="padding: 20px; text-align: center; background-color: #0e0c16; border-top: 1px solid #1f1b2e; font-size: 12px; color: #64748b;">
      &copy; ${new Date().getFullYear()} Almostaqel Academy. All rights reserved.
    </div>
  </div>
</body>
</html>`;
  return { subject, html };
};

export const sendOrderEmail = async ({ to, subject, html }) => {
  // 1. Try Resend first
  try {
    if (process.env.RESEND_API_KEY) {
      const resend = new Resend(process.env.RESEND_API_KEY);
      const { data, error } = await resend.emails.send({
        from: "almostaqel aQademy <contact@almostaqelaqademy.com>",
        to,
        subject,
        html,
      });
      if (!error && data) {
        return { success: true, provider: "resend" };
      }
      console.warn("Resend order email warning:", error?.message);
    }
  } catch (err) {
    console.warn("Resend order email error:", err.message);
  }

  // 2. Fallback to Nodemailer (Gmail)
  try {
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      const transporter = nodemailer.createTransport({
        service: "gmail",
        port: 587,
        secure: false,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });
      await transporter.sendMail({
        from: `"almostaqel aQademy" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html,
      });
      return { success: true, provider: "nodemailer" };
    }
  } catch (err) {
    console.error("Nodemailer order email error:", err.message);
  }

  return { success: false };
};

// ============================================================================
// 1. GET & POST /api/learning/checkout-info/:id
// Fetch safe product summary for the Checkout page without leaking content
// ============================================================================
const handleGetCheckoutInfo = async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findOne({ _id: id, status: "published" })
      .select(
        "title titleAr description descriptionAr type category tag level levelAr price priceAfter hours duration lessons readTime image imageDataUrl instructor instructorAr author"
      )
      .lean();

    if (!item) {
      return res.status(404).json({ message: "Product not found" });
    }

    const effectivePrice = Number(item.priceAfter ?? item.price ?? 0);

    const existingOrders = await Orders.find({
      userId: req.user.userId,
      productId: item._id,
    })
      .sort({ createdAt: -1 })
      .lean();

    const approvedOrder = existingOrders.find((o) => o.status === "approved");
    const pendingOrder = existingOrders.find((o) => o.status === "pending");

    return res.status(200).json({
      product: {
        ...item,
        id: item._id,
        effectivePrice,
      },
      isPurchased: effectivePrice <= 0 || Boolean(approvedOrder),
      pendingOrder: pendingOrder
        ? {
            orderCode: pendingOrder.orderCode,
            paymentMethod: pendingOrder.paymentMethod,
            amount: pendingOrder.amount,
            createdAt: pendingOrder.createdAt,
          }
        : null,
      userPhone: req.dbUser?.PhoneNumber || "",
      userEmail: req.dbUser?.email || "",
    });
  } catch (err) {
    console.error("Error in /api/learning/checkout-info/:id:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/checkout-info/:id", userAuth, handleGetCheckoutInfo);
router.post("/learning/checkout-info/:id", userAuth, handleGetCheckoutInfo);

// ============================================================================
// 2. POST /api/learning/orders/create
// Create purchase order(s), save in DB, and send RIB + Order Code email
// ============================================================================
router.post("/learning/orders/create", userAuth, async (req, res) => {
  try {
    const { productId, productIds, paymentMethod, phone } = req.body || {};
    const normalizedMethod = String(paymentMethod || "")
      .toLowerCase()
      .trim();

    if (!["flouci", "zitouna", "d17"].includes(normalizedMethod)) {
      return res.status(400).json({
        message: "Please select a valid payment method (Flouci, Banque Zitouna, or D-17).",
      });
    }

    const targetIds = Array.isArray(productIds) && productIds.length > 0
      ? productIds
      : productId
      ? [productId]
      : [];

    if (targetIds.length === 0) {
      return res.status(400).json({ message: "Product ID is required." });
    }

    const dbUser = req.dbUser;
    const userPhone = String(phone || dbUser?.PhoneNumber || "").trim();

    // Update user's PhoneNumber in DB if they didn't have one stored yet
    if (userPhone && !dbUser?.PhoneNumber) {
      await Users.findByIdAndUpdate(dbUser._id, {
        $set: { PhoneNumber: userPhone },
      });
    }

    const fullName =
      `${dbUser.ferstname || ""} ${dbUser.lastname || ""}`.trim() ||
      dbUser.username ||
      "Student";

    const products = await Learning.find({
      _id: { $in: targetIds },
      status: "published",
    })
      .select("title titleAr type price priceAfter image")
      .lean();

    if (!products || products.length === 0) {
      return res.status(404).json({ message: "Requested product(s) not found." });
    }

    const methodInfo = PAYMENT_METHODS_INFO[normalizedMethod];
    const ribCode = methodInfo.getRib();
    const sharedOrderCode = generateOrderCode();

    const createdOrders = [];
    let totalAmount = 0;

    for (let i = 0; i < products.length; i++) {
      const prod = products[i];
      const effectivePrice = Number(prod.priceAfter ?? prod.price ?? 0);

      // Check if already approved
      const alreadyApproved = await Orders.findOne({
        userId: dbUser._id,
        productId: prod._id,
        status: "approved",
      });
      if (alreadyApproved) {
        continue;
      }

      // Check if user already has a pending order for this product
      let existingPending = await Orders.findOne({
        userId: dbUser._id,
        productId: prod._id,
        status: "pending",
      });

      const orderCodeToUse =
        products.length === 1
          ? existingPending?.orderCode || sharedOrderCode
          : `${sharedOrderCode}-${i + 1}`;

      if (existingPending) {
        existingPending.paymentMethod = normalizedMethod;
        existingPending.userPhone = userPhone || existingPending.userPhone;
        existingPending.ribSent = ribCode;
        existingPending.amount = effectivePrice;
        await existingPending.save();
        createdOrders.push(existingPending.toObject());
      } else {
        const newOrder = await Orders.create({
          orderCode: orderCodeToUse,
          userId: dbUser._id,
          userName: fullName,
          userEmail: dbUser.email,
          userPhone: userPhone,
          productId: prod._id,
          productTitle: prod.title,
          productTitleAr: prod.titleAr || prod.title,
          productType: prod.type || "Courses",
          productImage: prod.image || "",
          amount: effectivePrice,
          paymentMethod: normalizedMethod,
          ribSent: ribCode,
          status: "pending",
        });
        createdOrders.push(newOrder.toObject());
      }

      totalAmount += effectivePrice;
    }

    if (createdOrders.length === 0) {
      return res.status(200).json({
        message: "You already own this product.",
        alreadyOwned: true,
      });
    }

    const primaryOrderCode =
      createdOrders.length === 1 ? createdOrders[0].orderCode : sharedOrderCode;

    const isAr =
      (req.headers["x-lang"] || req.headers["accept-language"] || dbUser.lang || "ar")
        .toLowerCase()
        .includes("ar");

    const emailPayload = buildOrderPaymentEmail({
      userName: fullName,
      orderCode: primaryOrderCode,
      products: createdOrders,
      totalAmount,
      paymentMethod: normalizedMethod,
      ribCode,
      isAr,
    });

    const emailResult = await sendOrderEmail({
      to: dbUser.email,
      subject: emailPayload.subject,
      html: emailPayload.html,
    });

    return res.status(201).json({
      message: isAr
        ? "تم تسجيل طلب الشراء وإرسال رمز الـ RIB وتفاصيل الطلب إلى بريدك الإلكتروني بنجاح."
        : "Your purchase request has been created and the RIB details have been sent to your email.",
      orderCode: primaryOrderCode,
      orders: createdOrders,
      paymentMethod: normalizedMethod,
      emailSent: emailResult.success,
    });
  } catch (err) {
    console.error("Error in POST /api/learning/orders/create:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ============================================================================
// 3. GET & POST /api/learning/orders/my-orders
// Fetch logged-in student's orders, unlocked products, and cart products from DB
// ============================================================================
const PRODUCT_CARD_FIELDS =
  "title titleAr description descriptionAr type category tag level levelAr price priceAfter hours duration lessons readTime image imageDataUrl availabilityStatus";

const handleGetMyOrders = async (req, res) => {
  try {
    const orders = await Orders.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .lean();

    const approvedOrderProductIds = orders
      .filter((o) => o.status === "approved")
      .map((o) => String(o.productId));

    const userPurchasedIds = Array.isArray(req.dbUser?.purchasedProducts)
      ? req.dbUser.purchasedProducts.map((id) => String(id))
      : [];

    const unifiedPurchasedIds = [
      ...new Set([...approvedOrderProductIds, ...userPurchasedIds]),
    ].filter((id) => /^[0-9a-fA-F]{24}$/.test(id));

    // Sync any newly approved order product IDs into Users.purchasedProducts
    const missingInUserDoc = approvedOrderProductIds.filter(
      (id) => /^[0-9a-fA-F]{24}$/.test(id) && !userPurchasedIds.includes(id)
    );
    if (missingInUserDoc.length > 0) {
      await Users.updateOne(
        { _id: req.user.userId },
        { $addToSet: { purchasedProducts: { $each: missingInUserDoc } } }
      );
    }

    // Merge any one-time localCartIds passed from browser into Users.cartProducts in DB
    const dbCartIds = Array.isArray(req.dbUser?.cartProducts)
      ? req.dbUser.cartProducts.map((id) => String(id))
      : [];
    const incomingLocalCartIds = Array.isArray(req.body?.localCartIds)
      ? req.body.localCartIds
          .map((id) => String(id))
          .filter((id) => /^[0-9a-fA-F]{24}$/.test(id))
      : [];

    const newLocalCartIds = incomingLocalCartIds.filter(
      (id) => !dbCartIds.includes(id)
    );
    if (newLocalCartIds.length > 0) {
      await Users.updateOne(
        { _id: req.user.userId },
        { $addToSet: { cartProducts: { $each: newLocalCartIds } } }
      );
    }

    const unifiedCartIds = [
      ...new Set([...dbCartIds, ...incomingLocalCartIds]),
    ].filter((id) => /^[0-9a-fA-F]{24}$/.test(id));

    const pendingOrdersMap = {};
    for (const o of orders) {
      if (o.status === "pending" && !pendingOrdersMap[String(o.productId)]) {
        pendingOrdersMap[String(o.productId)] = {
          orderCode: o.orderCode,
          paymentMethod: o.paymentMethod,
          amount: o.amount,
          createdAt: o.createdAt,
        };
      }
    }

    // Fetch full product cards for approved orders and cart products in parallel
    const [unlockedProducts, cartProductsDocs, preorderedDocs] = await Promise.all([
      unifiedPurchasedIds.length > 0
        ? Learning.find({
            _id: { $in: unifiedPurchasedIds },
            status: "published",
          })
            .select(PRODUCT_CARD_FIELDS)
            .lean()
        : [],
      unifiedCartIds.length > 0
        ? Learning.find({
            _id: { $in: unifiedCartIds },
            status: "published",
          })
            .select(PRODUCT_CARD_FIELDS)
            .lean()
        : [],
      Learning.find({
        $or: [
          { "preorders.userId": req.user.userId },
          ...(req.dbUser?.email
            ? [{ "preorders.userEmail": String(req.dbUser.email).toLowerCase() }]
            : []),
        ],
      })
        .select("_id")
        .lean(),
    ]);

    const preorderedProductIds = preorderedDocs.map((d) => String(d._id));
    const formattedCartProducts = cartProductsDocs.map((p) => {
      const itemPrice =
        p.price !== undefined && p.price !== null && p.price !== ""
          ? Number(p.price)
          : 0;
      const itemPriceAfter =
        p.priceAfter !== undefined && p.priceAfter !== null && p.priceAfter !== ""
          ? Number(p.priceAfter)
          : itemPrice;
      return {
        ...p,
        id: String(p._id),
        courseId: String(p._id),
        price: itemPriceAfter,
        priceAfter: itemPriceAfter,
        originalPrice: itemPrice,
        hours: p.hours || p.duration || 10,
        level: p.level || "Intermediate",
        levelAr: p.levelAr || "متوسط",
        tag: p.tag || p.category || "Learning",
        type: p.type || "course",
      };
    });

    return res.status(200).json({
      orders: orders.map((o) => ({ ...o, id: o._id })),
      purchasedProductIds: unifiedPurchasedIds,
      preorderedProductIds,
      pendingOrdersMap,
      unlockedProducts: unlockedProducts.map((p) => ({ ...p, id: p._id })),
      cartProductIds: formattedCartProducts.map((p) => String(p._id)),
      cartProducts: formattedCartProducts,
    });
  } catch (err) {
    console.error("Error in /api/learning/orders/my-orders:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.get("/learning/orders/my-orders", userAuth, handleGetMyOrders);
router.post("/learning/orders/my-orders", userAuth, handleGetMyOrders);

// ============================================================================
// 3B. POST /api/learning/cart/add & POST /api/learning/cart/remove
// Store and manage user's Cart products directly in Users collection in MongoDB
// ============================================================================
router.post("/learning/cart/add", userAuth, async (req, res) => {
  try {
    const productId = String(req.body?.productId || "").trim();
    if (!/^[0-9a-fA-F]{24}$/.test(productId)) {
      return res.status(400).json({ message: "Invalid product ID" });
    }

    const item = await Learning.findOne({ _id: productId, status: "published" })
      .select(PRODUCT_CARD_FIELDS)
      .lean();
    if (!item) {
      return res.status(404).json({ message: "Product not found" });
    }

    const updatedUser = await Users.findByIdAndUpdate(
      req.user.userId,
      { $addToSet: { cartProducts: item._id } },
      { new: true }
    )
      .select("cartProducts")
      .lean();

    const cartProductIds = (updatedUser?.cartProducts || []).map((id) =>
      String(id)
    );

    return res.status(200).json({
      message: "Product added to cart",
      productId: String(item._id),
      cartProductIds,
    });
  } catch (err) {
    console.error("Error in POST /api/learning/cart/add:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

router.post("/learning/cart/remove", userAuth, async (req, res) => {
  try {
    const productId = String(req.body?.productId || "").trim();
    if (!/^[0-9a-fA-F]{24}$/.test(productId)) {
      return res.status(400).json({ message: "Invalid product ID" });
    }

    // Enforce rule: only unpurchased products can be removed from cart
    const isPurchasedInUser = Array.isArray(req.dbUser?.purchasedProducts) &&
      req.dbUser.purchasedProducts.some((id) => String(id) === productId);
    const approvedOrder = await Orders.exists({
      userId: req.user.userId,
      productId,
      status: "approved",
    });

    if (isPurchasedInUser || approvedOrder) {
      return res.status(403).json({
        message: "Purchased products cannot be removed from cart.",
      });
    }

    const updatedUser = await Users.findByIdAndUpdate(
      req.user.userId,
      { $pull: { cartProducts: productId } },
      { new: true }
    )
      .select("cartProducts")
      .lean();

    const cartProductIds = (updatedUser?.cartProducts || []).map((id) =>
      String(id)
    );

    return res.status(200).json({
      message: "Product removed from cart",
      productId,
      cartProductIds,
    });
  } catch (err) {
    console.error("Error in POST /api/learning/cart/remove:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ============================================================================
// 4. POST /api/learning/:id/preorder
// Register logged-in user's Pre-Order for a product in "preorder" state
// ============================================================================
router.post("/learning/:id/preorder", userAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await Learning.findOne({ _id: id, status: "published" });
    if (!item) {
      return res.status(404).json({ message: "Product not found" });
    }

    const dbUser = req.dbUser;
    const userEmail = String(dbUser?.email || req.user?.email || "")
      .trim()
      .toLowerCase();
    if (!userEmail) {
      return res.status(400).json({ message: "Valid user email is required for pre-order" });
    }

    const fullName =
      `${dbUser?.ferstname || ""} ${dbUser?.lastname || ""}`.trim() ||
      dbUser?.username ||
      "Student";

    const rawLang =
      req.body?.lang ||
      req.headers["x-lang"] ||
      req.headers["accept-language"] ||
      "ar";
    const isEn = String(rawLang).trim().toLowerCase().startsWith("en");
    const userLang = isEn ? "en" : "ar";
    const isAr = userLang === "ar";

    if (!Array.isArray(item.preorders)) {
      item.preorders = [];
    }

    const existingEntry = item.preorders.find(
      (p) =>
        String(p.userId) === String(req.user.userId) ||
        String(p.userEmail || "").toLowerCase() === userEmail
    );

    const alreadyPreordered = Boolean(existingEntry);

    if (!existingEntry) {
      item.preorders.push({
        userId: req.user.userId,
        userName: fullName,
        userEmail,
        lang: userLang,
        createdAt: new Date(),
      });
      await item.save();
    } else {
      existingEntry.lang = userLang;
      existingEntry.userName = fullName;
      item.markModified("preorders");
      await item.save();
    }

    return res.status(200).json({
      alreadyPreordered,
      productId: String(item._id),
      message: isAr
        ? "تم تسجيل طلبك المسبق بنجاح! سيصلك إشعار عبر البريد الإلكتروني فور إطلاق هذا المنتوج."
        : "Your pre-order has been registered! We will notify you by email as soon as this product launches.",
    });
  } catch (err) {
    console.error("Error in POST /api/learning/:id/preorder:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;

