import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";
import nodemailer from "nodemailer";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Support } from "../../../schema/support.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const supportUploadDir = path.resolve(__dirname, "../../../uploads/support");

const formatSupportImages = (images) => {
  if (!Array.isArray(images)) return [];
  return images.map((img) => {
    let resolvedDataUrl = img.dataUrl || "";
    if (!resolvedDataUrl) {
      const candidatePath =
        img.path && fs.existsSync(img.path)
          ? img.path
          : img.filename
          ? path.join(supportUploadDir, img.filename)
          : null;
      if (candidatePath && fs.existsSync(candidatePath)) {
        try {
          const buf = fs.readFileSync(candidatePath);
          resolvedDataUrl = `data:${img.mimetype || "image/jpeg"};base64,${buf.toString("base64")}`;
        } catch {
          // ignore read error
        }
      }
    }
    return {
      filename: img.filename,
      originalname: img.originalname,
      mimetype: img.mimetype,
      size: img.size,
      url: img.url || (img.filename ? `/uploads/support/${img.filename}` : ""),
      dataUrl: resolvedDataUrl,
    };
  });
};

const router = express.Router();

const ALLOWED_SORT_FIELDS = [
  "createdAt",
  "updatedAt",
  "name",
  "email",
  "subject",
  "category",
  "status",
  "ticketId",
];
const ALLOWED_STATUS_FILTERS = [
  "all",
  "pending",
  "in-progress",
  "resolved",
  "closed",
  "rejected",
  "unreviewed",
  "under-review",
];
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

// Escape user-supplied regex string to prevent ReDoS / NoSQL Injection
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Normalize UI filter aliases to schema status values
const resolveStatusFilter = (filter) => {
  if (filter === "unreviewed") return "pending";
  if (filter === "under-review") return "in-progress";
  return filter;
};

// Build HTML email for Support Status Updates (Under Review, Resolved, Rejected)
const getStatusUpdateEmailContent = ({
  name,
  ticketId,
  subject,
  status,
  rejectionReason,
  isAr,
}) => {
  const statusConfig = {
    "in-progress": {
      arSubject: `طلب الدعم قيد المراجعة [#${ticketId}] - أكاديمية المستقبل`,
      enSubject: `Your Support Ticket is Under Review [#${ticketId}] - Almostaqel Academy`,
      arBadge: "قيد المراجعة (Under Review)",
      enBadge: "Under Review",
      badgeColor: "#eab308",
      badgeBg: "rgba(234, 179, 8, 0.12)",
      badgeBorder: "rgba(234, 179, 8, 0.35)",
      arHeading: "طلبك قيد المراجعة حالياً 🔍",
      enHeading: "Your Request is Currently Under Review 🔍",
      arBody:
        "نود إعلامك بأن فريق الدعم الفني في أكاديمية المستقبل قد بدأ بمراجعة طلبك/طعنك، وسنقوم بموافاتك بالرد النهائي في أقرب وقت ممكن.",
      enBody:
        "We would like to inform you that our support team at Almostaqel Academy is currently reviewing your ticket/appeal. We will get back to you with a final update shortly.",
    },
    resolved: {
      arSubject: `تم حل طلب الدعم بنجاح [#${ticketId}] - أكاديمية المستقبل`,
      enSubject: `Your Support Ticket Has Been Resolved [#${ticketId}] - Almostaqel Academy`,
      arBadge: "تم الحل (Resolved)",
      enBadge: "Resolved",
      badgeColor: "#22c55e",
      badgeBg: "rgba(34, 197, 94, 0.12)",
      badgeBorder: "rgba(34, 197, 94, 0.35)",
      arHeading: "تمت معالجة وحل طلبك بنجاح ✅",
      enHeading: "Your Support Request Has Been Resolved ✅",
      arBody:
        "يسعدنا إبلاغك بأنه قد تمت مراجعة ومعالجة طلب الدعم الخاص بك بنجاح. نشكرك على تواصلك معنا ونتمنى لك تجربة تعليمية موفقة.",
      enBody:
        "We are pleased to inform you that your support request has been reviewed and resolved. Thank you for reaching out to Almostaqel Academy.",
    },
    rejected: {
      arSubject: `تم رفض الطعن / طلب الدعم [#${ticketId}] - أكاديمية المستقبل`,
      enSubject: `Update Regarding Your Appeal / Support Request [#${ticketId}] - Almostaqel Academy`,
      arBadge: "مرفوض (Rejected)",
      enBadge: "Appeal Rejected",
      badgeColor: "#ef4444",
      badgeBg: "rgba(239, 68, 68, 0.12)",
      badgeBorder: "rgba(239, 68, 68, 0.35)",
      arHeading: "تم رفض الطعن / الطلب ❌",
      enHeading: "Your Appeal / Request Has Been Rejected ❌",
      arBody:
        "بعد مراجعة دقيقة لطلبك/طعنك من قِبل الإدارة وفريق الدعم الفني، نأسف لإبلاغك بأنه قد تقرر رفض الطلب للأسباب الموضحة أدناه:",
      enBody:
        "After a careful review of your appeal/request by our administration team, we regret to inform you that your request has been rejected for the following reason:",
    },
  };

  const cfg = statusConfig[status];
  if (!cfg) return null;

  if (isAr) {
    const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #07070f;
      color: #f0efff;
      margin: 0;
      padding: 40px 20px;
      direction: rtl;
      text-align: right;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #13111c;
      border: 1px solid #1f1b2e;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }
    .header {
      background: linear-gradient(135deg, #7c3aed 0%, #db2777 100%);
      padding: 30px 20px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 24px;
      font-weight: 800;
    }
    .header p {
      margin: 8px 0 0 0;
      color: rgba(255, 255, 255, 0.85);
      font-size: 13px;
    }
    .content {
      padding: 32px 28px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 700;
      color: #f0efff;
      margin-bottom: 12px;
    }
    .status-banner {
      background: ${cfg.badgeBg};
      border: 1px solid ${cfg.badgeBorder};
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 24px;
    }
    .status-title {
      font-size: 16px;
      font-weight: 700;
      color: ${cfg.badgeColor};
      margin: 0 0 8px 0;
    }
    .status-desc {
      font-size: 14px;
      line-height: 1.7;
      color: #e2e8f0;
      margin: 0;
    }
    .card {
      background: #191627;
      border: 1px solid #28243d;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .reason-box {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.35);
      border-radius: 12px;
      padding: 16px;
      margin-top: 14px;
      color: #fecaca;
      font-size: 14px;
      line-height: 1.7;
      white-space: pre-wrap;
    }
    .footer {
      text-align: center;
      padding: 24px;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid #1f1b2e;
      line-height: 1.7;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>أكاديمية المستقبل</h1>
      <p>ALMOSTAQEL ACADEMY - نظام الدعم الفني</p>
    </div>
    <div class="content">
      <div class="greeting">مرحباً ${name}،</div>
      <div class="status-banner">
        <p class="status-title">${cfg.arHeading}</p>
        <p class="status-desc">${cfg.arBody}</p>
      </div>
      <div class="card">
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">رقم التذكرة:</strong> <span style="color: #fff; font-family: monospace;">#${ticketId}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">الموضوع:</strong> <span style="color: #fff;">${subject}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">الحالة الحالية:</strong> <span style="color: ${cfg.badgeColor}; font-weight: 700;">${cfg.arBadge}</span></p>
        ${
          status === "rejected" && rejectionReason
            ? `<p style="margin: 16px 0 6px 0; font-size: 13px;"><strong style="color: #f87171;">سبب رفض الطعن / الطلب:</strong></p>
               <div class="reason-box">${rejectionReason}</div>`
            : ""
        }
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} أكاديمية المستقبل (Almostaqel Academy). جميع الحقوق محفوظة.
    </div>
  </div>
</body>
</html>`;
    return { subject: cfg.arSubject, html };
  }

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #07070f;
      color: #f0efff;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #13111c;
      border: 1px solid #1f1b2e;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }
    .header {
      background: linear-gradient(135deg, #7c3aed 0%, #db2777 100%);
      padding: 30px 20px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 24px;
      font-weight: 800;
    }
    .header p {
      margin: 8px 0 0 0;
      color: rgba(255, 255, 255, 0.85);
      font-size: 13px;
    }
    .content {
      padding: 32px 28px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 700;
      color: #f0efff;
      margin-bottom: 12px;
    }
    .status-banner {
      background: ${cfg.badgeBg};
      border: 1px solid ${cfg.badgeBorder};
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 24px;
    }
    .status-title {
      font-size: 16px;
      font-weight: 700;
      color: ${cfg.badgeColor};
      margin: 0 0 8px 0;
    }
    .status-desc {
      font-size: 14px;
      line-height: 1.7;
      color: #e2e8f0;
      margin: 0;
    }
    .card {
      background: #191627;
      border: 1px solid #28243d;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .reason-box {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.35);
      border-radius: 12px;
      padding: 16px;
      margin-top: 14px;
      color: #fecaca;
      font-size: 14px;
      line-height: 1.7;
      white-space: pre-wrap;
    }
    .footer {
      text-align: center;
      padding: 24px;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid #1f1b2e;
      line-height: 1.7;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Almostaqel Academy</h1>
      <p>Customer Support System</p>
    </div>
    <div class="content">
      <div class="greeting">Hello ${name},</div>
      <div class="status-banner">
        <p class="status-title">${cfg.enHeading}</p>
        <p class="status-desc">${cfg.enBody}</p>
      </div>
      <div class="card">
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Ticket ID:</strong> <span style="color: #fff; font-family: monospace;">#${ticketId}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Subject:</strong> <span style="color: #fff;">${subject}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Current Status:</strong> <span style="color: ${cfg.badgeColor}; font-weight: 700;">${cfg.enBadge}</span></p>
        ${
          status === "rejected" && rejectionReason
            ? `<p style="margin: 16px 0 6px 0; font-size: 13px;"><strong style="color: #f87171;">Reason for Rejection:</strong></p>
               <div class="reason-box">${rejectionReason}</div>`
            : ""
        }
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} Almostaqel Academy. All rights reserved.
    </div>
  </div>
</body>
</html>`;
  return { subject: cfg.enSubject, html };
};

// Send status update email via Resend with Nodemailer fallback
const sendSupportStatusEmail = async ({
  name,
  email,
  ticketId,
  subject,
  message,
  status,
  rejectionReason = "",
}) => {
  // Detect Arabic from ticket fields or rejection reason (default to Arabic if matched)
  const isAr = /[\u0600-\u06FF]/.test(
    `${name || ""} ${subject || ""} ${message || ""} ${rejectionReason || ""}`
  );
  const emailContent = getStatusUpdateEmailContent({
    name,
    ticketId,
    subject,
    status,
    rejectionReason,
    isAr,
  });
  if (!emailContent) return { success: false };

  // 1. Try Resend first
  try {
    if (process.env.RESEND_API_KEY) {
      const resend = new Resend(process.env.RESEND_API_KEY);
      const { data, error } = await resend.emails.send({
        from: "almostaqel aQademy <contact@almostaqelaqademy.com>",
        to: email,
        subject: emailContent.subject,
        html: emailContent.html,
      });

      if (!error && data) {
        console.log(`Support status (${status}) email sent via Resend to:`, email);
        return { success: true, provider: "resend" };
      }
      console.warn("Resend status email error:", error?.message);
    }
  } catch (resendErr) {
    console.warn("Resend status email exception:", resendErr.message);
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
        tls: {
          rejectUnauthorized: false,
        },
      });

      await transporter.sendMail({
        from: `"أكاديمية المستقبل | Almostaqel Academy" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: emailContent.subject,
        html: emailContent.html,
      });
      console.log(`Support status (${status}) email sent via Nodemailer to:`, email);
      return { success: true, provider: "nodemailer" };
    }
  } catch (nmErr) {
    console.error("Nodemailer status email fallback failed:", nmErr.message);
  }

  return { success: false };
};

const handleGetSupportMessages = async (req, res) => {
  try {
    // Source parameters from query (for GET) or body (for POST)
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawSearch = req.query.search ?? req.body?.search ?? req.query.q ?? req.body?.q;
    const rawFilter = req.query.filter ?? req.body?.filter ?? req.query.status ?? req.body?.status;
    const rawCategory = req.query.category ?? req.body?.category;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    // 1. Validate & clamp pagination bounds
    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, MAX_LIMIT)
        : DEFAULT_LIMIT;

    const skip = (page - 1) * limit;

    // 2. Build Base Query
    const query = {};

    // 3. Safe Search Sanitization
    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const searchRegex = new RegExp(escapeRegex(cleanSearch), "i");
        query.$or = [
          { ticketId: searchRegex },
          { name: searchRegex },
          { email: searchRegex },
          { subject: searchRegex },
          { message: searchRegex },
          { category: searchRegex },
        ];
      }
    }

    // 4. Status Filtering (Whitelisted)
    const filter = typeof rawFilter === "string" ? rawFilter.trim() : "all";
    if (ALLOWED_STATUS_FILTERS.includes(filter) && filter !== "all") {
      query.status = resolveStatusFilter(filter);
    }

    // 5. Optional Category Filtering
    if (typeof rawCategory === "string") {
      const cleanCategory = rawCategory.trim().slice(0, 50);
      if (cleanCategory.length > 0 && cleanCategory !== "all") {
        query.category = new RegExp(`^${escapeRegex(cleanCategory)}$`, "i");
      }
    }

    // 6. Sort Field & Order Whitelisting
    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;
    const sortObj = { [sortField]: sortOrder };

    // 7. Execute count and find queries concurrently (excluding sensitive deviceId & ipAddress)
    const [totalMessages, unreviewedCount, messages] = await Promise.all([
      Support.countDocuments(query),
      Support.countDocuments({ status: "pending" }),
      Support.find(query)
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .select(
          "_id ticketId userId name email subject category message images status rejectionReason createdAt updatedAt"
        )
        .lean(),
    ]);

    // 8. Sanitize and format response items
    const formattedMessages = messages.map((msg) => ({
      ...msg,
      id: msg._id,
      receivedAt: msg.createdAt,
      images: formatSupportImages(msg.images),
    }));

    const totalPages = Math.max(1, Math.ceil(totalMessages / limit));

    res.status(200).json({
      messages: formattedMessages,
      unreviewedCount,
      pagination: {
        total: totalMessages,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (err) {
    console.error("Error in getSupport handler:", err);
    res.status(500).json({ message: "Failed to fetch support messages" });
  }
};

router.post("/get-supports-message", AdminAuth, handleGetSupportMessages);

router.post("/update-support-status/:id", AdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const rawStatus = req.body?.status;
    const rawReason = req.body?.reason ?? req.body?.rejectionReason ?? "";

    if (!rawStatus || !ALLOWED_STATUS_FILTERS.includes(rawStatus) || rawStatus === "all") {
      return res.status(400).json({ message: "Invalid support status" });
    }

    const normalizedStatus = resolveStatusFilter(rawStatus);
    const cleanReason = typeof rawReason === "string" ? rawReason.trim() : "";

    if (normalizedStatus === "rejected" && !cleanReason) {
      return res.status(400).json({ message: "Please provide a rejection reason before sending." });
    }

    const updateFields = {
      status: normalizedStatus,
      ...(normalizedStatus === "rejected" ? { rejectionReason: cleanReason } : {}),
    };

    const updated = await Support.findByIdAndUpdate(id, updateFields, { new: true })
      .select(
        "_id ticketId userId name email subject category message images status rejectionReason createdAt updatedAt"
      )
      .lean();

    if (!updated) {
      return res.status(404).json({ message: "Support message not found" });
    }

    // Send email notification when status is Under Review (in-progress), Resolved, or Rejected
    let emailResult = { success: false };
    if (["in-progress", "resolved", "rejected"].includes(normalizedStatus)) {
      emailResult = await sendSupportStatusEmail({
        name: updated.name,
        email: updated.email,
        ticketId: updated.ticketId,
        subject: updated.subject,
        message: updated.message,
        status: normalizedStatus,
        rejectionReason: cleanReason,
      });
    }

    res.status(200).json({
      message: "Support status updated successfully",
      emailSent: emailResult.success,
      support: {
        ...updated,
        id: updated._id,
        receivedAt: updated.createdAt,
      },
    });
  } catch (err) {
    console.error("Error updating support status:", err);
    res.status(500).json({ message: "Failed to update support status" });
  }
});

export default router;
