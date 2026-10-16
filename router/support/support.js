 import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";
import nodemailer from "nodemailer";
import { Support } from "../../schema/support.js";
import {
  checkIsBanned,
  recordAndCheckSpamRate,
  preCheckDeviceBanMiddleware,
} from "../../middleware/spamProtection.js";
import { getMsg } from "../../utils/messages.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// Ensure upload directory exists
const uploadDir = path.join(__dirname, "../../uploads/support");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "support-" + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedMimes = ["image/jpeg", "image/png", "image/webp", "image/jpg", "image/gif"];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("ONLY_IMAGES_ALLOWED"), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max per image
    files: 2 // Max 2 images (optional as requested by user)
  }
});

// HTML Email Generator for Support Confirmation
const getSupportEmailContent = ({ name, email, subject, category, message, ticketId, imagesCount, isAr }) => {
  if (isAr) {
    const emailSubject = `تم استلام طلب الدعم الفني بنجاح [#${ticketId}] - أكاديمية المستقبل`;
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
      letter-spacing: -0.5px;
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
    .intro {
      font-size: 14px;
      line-height: 1.8;
      color: #cbd5e1;
      margin-bottom: 24px;
    }
    .ticket-badge {
      background: rgba(124, 58, 237, 0.12);
      border: 1px dashed rgba(124, 58, 237, 0.4);
      border-radius: 14px;
      padding: 16px;
      text-align: center;
      margin-bottom: 24px;
    }
    .ticket-title {
      font-size: 12px;
      color: #a78bfa;
      font-weight: 600;
      margin: 0 0 4px 0;
    }
    .ticket-number {
      font-size: 22px;
      font-weight: 800;
      color: #ffffff;
      font-family: monospace;
      margin: 0;
      letter-spacing: 1px;
    }
    .card {
      background: #191627;
      border: 1px solid #28243d;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .card-title {
      font-size: 13px;
      font-weight: 700;
      color: #a78bfa;
      margin-top: 0;
      margin-bottom: 12px;
      border-bottom: 1px solid #28243d;
      padding-bottom: 8px;
    }
    .info-row {
      display: flex;
      margin-bottom: 8px;
      font-size: 13px;
    }
    .info-label {
      color: #94a3b8;
      width: 140px;
      font-weight: 600;
    }
    .info-value {
      color: #ffffff;
      flex: 1;
    }
    .message-box {
      background: #110e1c;
      border: 1px solid #28243d;
      border-radius: 10px;
      padding: 14px;
      font-size: 13px;
      line-height: 1.7;
      color: #e2e8f0;
      white-space: pre-wrap;
      margin-top: 10px;
    }
    .response-notice {
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.25);
      border-radius: 12px;
      padding: 14px 18px;
      font-size: 13px;
      color: #86efac;
      line-height: 1.6;
      margin-bottom: 24px;
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
      <div class="intro">
        نشكرك لتواصلك معنا. لقد تم استلام طلبك بنجاح من قِبل فريق الدعم الفني في أكاديمية المستقبل.
      </div>

      <div class="ticket-badge">
        <p class="ticket-title">رقم التذكرة المرجعي</p>
        <p class="ticket-number">${ticketId}</p>
      </div>

      <div class="card">
        <p class="card-title">تفاصيل الطلب المقدم:</p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">الموضوع:</strong> <span style="color: #fff;">${subject}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">التصنيف:</strong> <span style="color: #fff;">${category}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">البريد الإلكتروني للتواصل:</strong> <span style="color: #fff;">${email}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">المرفقات:</strong> <span style="color: #fff;">${imagesCount > 0 ? `${imagesCount} صورة مرفقة` : 'لا توجد مرفقات'}</span></p>
        
        <p style="margin: 14px 0 4px 0; font-size: 13px;"><strong style="color: #94a3b8;">نص الرسالة:</strong></p>
        <div class="message-box">${message}</div>
      </div>

      <div class="response-notice">
        ⚡ <strong>ما هي الخطوة التالية؟</strong><br>
        يقوم فريق الدعم بمراجعة طلبك حالياً، وسنقوم بالرد عليك مباشرة عبر هذا البريد الإلكتروني (عادةً خلال 24 ساعة).
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} أكاديمية المستقبل (Almostaqel Academy). جميع الحقوق محفوظة.<br>
      إذا لم تقم بتقديم هذا الطلب، يرجى التواصل معنا عبر support@almostaqelaqademy.com
    </div>
  </div>
</body>
</html>
    `;
    return { subject: emailSubject, html };
  } else {
    // English version
    const emailSubject = `Support Request Received [#${ticketId}] - Almostaqel Academy`;
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
    .intro {
      font-size: 14px;
      line-height: 1.8;
      color: #cbd5e1;
      margin-bottom: 24px;
    }
    .ticket-badge {
      background: rgba(124, 58, 237, 0.12);
      border: 1px dashed rgba(124, 58, 237, 0.4);
      border-radius: 14px;
      padding: 16px;
      text-align: center;
      margin-bottom: 24px;
    }
    .ticket-title {
      font-size: 12px;
      color: #a78bfa;
      font-weight: 600;
      margin: 0 0 4px 0;
    }
    .ticket-number {
      font-size: 22px;
      font-weight: 800;
      color: #ffffff;
      font-family: monospace;
      margin: 0;
      letter-spacing: 1px;
    }
    .card {
      background: #191627;
      border: 1px solid #28243d;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .card-title {
      font-size: 13px;
      font-weight: 700;
      color: #a78bfa;
      margin-top: 0;
      margin-bottom: 12px;
      border-bottom: 1px solid #28243d;
      padding-bottom: 8px;
    }
    .message-box {
      background: #110e1c;
      border: 1px solid #28243d;
      border-radius: 10px;
      padding: 14px;
      font-size: 13px;
      line-height: 1.7;
      color: #e2e8f0;
      white-space: pre-wrap;
      margin-top: 10px;
    }
    .response-notice {
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.25);
      border-radius: 12px;
      padding: 14px 18px;
      font-size: 13px;
      color: #86efac;
      line-height: 1.6;
      margin-bottom: 24px;
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
      <div class="intro">
        Thank you for contacting us. Your support request has been successfully received by our customer support team.
      </div>

      <div class="ticket-badge">
        <p class="ticket-title">Your Ticket Reference Number</p>
        <p class="ticket-number">${ticketId}</p>
      </div>

      <div class="card">
        <p class="card-title">Inquiry Details:</p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Subject:</strong> <span style="color: #fff;">${subject}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Category:</strong> <span style="color: #fff;">${category}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Contact Email:</strong> <span style="color: #fff;">${email}</span></p>
        <p style="margin: 6px 0; font-size: 13px;"><strong style="color: #94a3b8;">Attachments:</strong> <span style="color: #fff;">${imagesCount > 0 ? `${imagesCount} image(s) attached` : 'None'}</span></p>
        
        <p style="margin: 14px 0 4px 0; font-size: 13px;"><strong style="color: #94a3b8;">Message:</strong></p>
        <div class="message-box">${message}</div>
      </div>

      <div class="response-notice">
        ⚡ <strong>What's Next?</strong><br>
        Our support team is reviewing your ticket and will reply to you directly via this email address (typically within 24 hours).
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} Almostaqel Academy. All rights reserved.<br>
      If you did not submit this request, please contact us at support@almostaqelaqademy.com
    </div>
  </div>
</body>
</html>
    `;
    return { subject: emailSubject, html };
  }
};

// Dispatch Email Function with Resend & Nodemailer fallback
const sendSupportConfirmationEmail = async ({ name, email, subject, category, message, ticketId, imagesCount, lang = "ar" }) => {
  const isAr = String(lang).toLowerCase().includes("ar");
  const emailContent = getSupportEmailContent({ name, email, subject, category, message, ticketId, imagesCount, isAr });

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
        console.log("Support confirmation email sent via Resend successfully to:", email);
        return { success: true, provider: "resend" };
      }
      console.warn("Resend email send error:", error?.message);
    }
  } catch (resendErr) {
    console.warn("Resend exception:", resendErr.message);
  }

  // 2. Nodemailer fallback with Gmail
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
          rejectUnauthorized: false
        }
      });

      await transporter.sendMail({
        from: `"أكاديمية المستقبل | Almostaqel Academy" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: emailContent.subject,
        html: emailContent.html,
      });
      console.log("Support confirmation email sent via Nodemailer successfully to:", email);
      return { success: true, provider: "nodemailer" };
    }
  } catch (nmErr) {
    console.error("Nodemailer fallback failed:", nmErr.message);
  }

  return { success: false };
};

// Helper to cleanup uploaded files if ban or spam triggered
const cleanupUploadedFiles = (files) => {
  if (Array.isArray(files)) {
    files.forEach((f) => {
      try {
        if (f.path && fs.existsSync(f.path)) {
          fs.unlinkSync(f.path);
        }
      } catch (e) {
        console.error("Error removing uploaded file:", e);
      }
    });
  }
};

// GET & POST /api/support/check-ban - Pre-check if email or device is banned before submitting
router.all("/support/check-ban", async (req, res) => {
  try {
    const email = req.query.email || req.body?.email;
    const deviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.query.deviceId ||
      req.body?.deviceId;
    const clientIp =
      req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip;

    const banCheck = await checkIsBanned({
      email,
      deviceId,
      ipAddress: clientIp,
    });

    if (banCheck.isBanned) {
      if (banCheck.matchedOn === "device") {
        return res.status(403).json({
          banned: true,
          matchedOn: "device",
          message: getMsg("devicePermanentBan", req),
        });
      }
      if (banCheck.matchedOn === "email") {
        return res.status(403).json({
          banned: true,
          matchedOn: "email",
          message: getMsg("emailPermanentBan", req),
        });
      }
      return res.status(403).json({
        banned: true,
        matchedOn: banCheck.matchedOn,
        message: getMsg("deviceOrEmailBanned", req),
      });
    }

    return res.json({ banned: false });
  } catch (err) {
    console.error("Error in /support/check-ban:", err);
    return res.status(500).json({ banned: false, error: err.message });
  }
});

// POST /api/support - Submit a new support ticket
router.post("/support", preCheckDeviceBanMiddleware, (req, res) => {
  upload.array("images", 2)(req, res, async (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({
            message: req.headers["x-lang"] === "ar"
              ? "حجم الصورة كبير جداً، الحد الأقصى المسموح به هو 5 ميجابايت لكل صورة."
              : "Image size is too large. Maximum allowed size is 5MB per image."
          });
        }
        if (err.code === "LIMIT_UNEXPECTED_FILE" || err.code === "LIMIT_FILE_COUNT") {
          return res.status(400).json({
            message: req.headers["x-lang"] === "ar"
              ? "يمكنك إرفاق صورتين كحد أقصى."
              : "You can attach a maximum of 2 images."
          });
        }
      }
      return res.status(400).json({
        message: req.headers["x-lang"] === "ar"
          ? "الملفات المرفقة غير صالحة. يُسمح فقط بملفات الصور (PNG, JPG, JPEG, WEBP)."
          : "Invalid files. Only image formats (PNG, JPG, JPEG, WEBP) are allowed."
      });
    }

    try {
      const { name, email, subject, category, message, userId, lang } = req.body;
      const clientLang = (lang || req.headers["x-lang"] || "ar").toLowerCase().includes("ar") ? "ar" : "en";
      const incomingDeviceId = req.headers["x-device-id"] || req.headers["device-id"] || req.body?.deviceId;
      const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip;

      // 1. Mandatory Ban Check (Check in BlockedIps first)
      const banCheck = await checkIsBanned({ email, deviceId: incomingDeviceId, ipAddress: clientIp });
      if (banCheck.isBanned) {
        cleanupUploadedFiles(req.files);
        if (banCheck.matchedOn === "device") {
          return res.status(403).json({ banned: true, message: getMsg("devicePermanentBan", req) });
        }
        if (banCheck.matchedOn === "email") {
          return res.status(403).json({ banned: true, message: getMsg("emailPermanentBan", req) });
        }
        return res.status(403).json({ banned: true, message: getMsg("deviceOrEmailBanned", req) });
      }

      // 2. Spam Attack Protection (Rate Limiter: ban email & device if > 15 requests in 5 minutes)
      const spamCheck = await recordAndCheckSpamRate({ email, deviceId: incomingDeviceId, ipAddress: clientIp });
      if (spamCheck.isSpam) {
        cleanupUploadedFiles(req.files);
        return res.status(403).json({
          banned: true,
          message: getMsg("spamAttackBan", req)
        });
      }

      // 3. Form Validation
      if (!name || !name.trim()) {
        cleanupUploadedFiles(req.files);
        return res.status(400).json({
          message: clientLang === "ar" ? "يرجى إدخال اسمك الكريم." : "Please enter your name."
        });
      }

      if (!email || !email.trim()) {
        cleanupUploadedFiles(req.files);
        return res.status(400).json({
          message: clientLang === "ar" ? "يرجى إدخال البريد الإلكتروني للتواصل." : "Please enter your contact email."
        });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email.trim())) {
        cleanupUploadedFiles(req.files);
        return res.status(400).json({
          message: clientLang === "ar" ? "صيغة البريد الإلكتروني غير صحيحة." : "Invalid email format."
        });
      }

      if (!subject || !subject.trim()) {
        cleanupUploadedFiles(req.files);
        return res.status(400).json({
          message: clientLang === "ar" ? "يرجى كتابة موضوع الاستفسار." : "Please enter inquiry subject."
        });
      }

      if (!message || !message.trim()) {
        cleanupUploadedFiles(req.files);
        return res.status(400).json({
          message: clientLang === "ar" ? "يرجى توضيح تفاصيل رسالتك أو استفسارك." : "Please enter your inquiry details."
        });
      }

      // Format uploaded images (up to 2, optional)
      const uploadedImages = (req.files || []).map((file) => ({
        filename: file.filename,
        originalname: file.originalname,
        path: file.path,
        mimetype: file.mimetype,
        size: file.size,
        url: `/uploads/support/${file.filename}`
      }));

      // Generate unique friendly ticket ID
      const datePart = Date.now().toString(36).toUpperCase();
      const randomPart = Math.floor(1000 + Math.random() * 9000);
      const ticketId = `TKT-${datePart}-${randomPart}`;

      // Save to MongoDB
      const newSupportTicket = new Support({
        ticketId,
        userId: userId || null,
        deviceId: incomingDeviceId || null,
        name: name.trim(),
        email: email.toLowerCase().trim(),
        subject: subject.trim(),
        category: category || "general",
        message: message.trim(),
        images: uploadedImages,
        ipAddress: clientIp || "",
        status: "pending"
      });

      await newSupportTicket.save();
      console.log(`Support ticket ${ticketId} created successfully in DB for ${email}`);

      // Send confirmation email asynchronously (does not block HTTP response)
      sendSupportConfirmationEmail({
        name: name.trim(),
        email: email.toLowerCase().trim(),
        subject: subject.trim(),
        category: category || "general",
        message: message.trim(),
        ticketId,
        imagesCount: uploadedImages.length,
        lang: clientLang
      }).catch((emailErr) => {
        console.error("Async email dispatch error:", emailErr);
      });

      return res.status(201).json({
        success: true,
        message: clientLang === "ar"
          ? "تم إرسال طلب الدعم بنجاح! تم إرسال رسالة تأكيد إلى بريدك الإلكتروني."
          : "Your support request has been submitted successfully! A confirmation email has been sent.",
        ticketId,
        data: {
          ticketId,
          name: newSupportTicket.name,
          email: newSupportTicket.email,
          subject: newSupportTicket.subject,
          category: newSupportTicket.category,
          imagesCount: uploadedImages.length,
          createdAt: newSupportTicket.createdAt
        }
      });
    } catch (dbErr) {
      console.error("Error creating support ticket:", dbErr);
      return res.status(500).json({
        message: req.headers["x-lang"] === "ar"
          ? "حدث خطأ غير متوقع أثناء إرسال الطلب، يرجى المحاولة لاحقاً."
          : "An unexpected error occurred while submitting your ticket. Please try again."
      });
    }
  });
});

export default router;
