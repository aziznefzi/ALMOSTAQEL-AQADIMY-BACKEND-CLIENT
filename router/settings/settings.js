import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";
import nodemailer from "nodemailer";
import { Users } from "../../schema/users.js";
import { Learning } from "../../schema/learning.js";
import { BlockedIps } from "../../schema/blockedIps.js";
import Sessions from "../../schema/sessions.js";
import { userAuth } from "../../middleware/userAuth.js";
import {
  checkIsBanned,
  recordAndCheckSpamRate,
  preCheckDeviceBanMiddleware,
} from "../../middleware/spamProtection.js";
import { getMsg, getLang } from "../../utils/messages.js";
import { recordUserLearningView } from "../../utils/trackUserLearningView.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const avatarsUploadDir = path.resolve(__dirname, "../../uploads/avatars");

if (!fs.existsSync(avatarsUploadDir)) {
  fs.mkdirSync(avatarsUploadDir, { recursive: true });
}

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// 🔒 Security Constants & Helpers
// ─────────────────────────────────────────────────────────────────────────────
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
const RESET_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes
const OTP_COOLDOWN_MS = 60 * 1000; // 60 seconds between OTP emails
const OTP_WINDOW_MS = 15 * 60 * 1000; // 15-minute sliding rate window
const OTP_MAX_REQUESTS_IN_WINDOW = 5;
const OTP_LOCKOUT_MS = 10 * 60 * 1000; // 10 minutes
const OTP_MAX_VERIFY_ATTEMPTS = 5;
const PASSWORD_MAX_FAILED_ATTEMPTS = 5;
const PASSWORD_LOCKOUT_MS = 10 * 60 * 1000; // 10 minutes
const MAX_AVATAR_BYTES = 3 * 1024 * 1024; // 3MB
const MAX_DB_AVATAR_FALLBACK_BYTES = 450 * 1024; // 450KB lean fallback in MongoDB

const escapeHtml = (str = "") =>
  String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const getClientIp = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
  req.socket?.remoteAddress ||
  req.ip ||
  "";

const hashSecuritySecret = (value, userId, purpose) => {
  const secretKey = process.env.ACCESS_TOKEN || "almostaqel-settings-fallback-secret";
  return crypto
    .createHmac("sha256", secretKey)
    .update(`${purpose}:${String(userId)}:${String(value)}`)
    .digest("hex");
};

const timingSafeEqualHex = (hexA, hexB) => {
  if (typeof hexA !== "string" || typeof hexB !== "string") return false;
  if (hexA.length !== hexB.length || hexA.length === 0) return false;
  try {
    const bufA = Buffer.from(hexA, "hex");
    const bufB = Buffer.from(hexB, "hex");
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
};

const maskEmail = (email = "") => {
  if (!email || !email.includes("@")) return "";
  const [local, domain] = email.split("@");
  if (local.length <= 2) return `${local[0] || "*"}*@${domain}`;
  return `${local[0]}${"*".repeat(Math.min(5, Math.max(2, local.length - 2)))}${local[local.length - 1]}@${domain}`;
};

const sanitizePersonName = (raw) => {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/\u0000/g, "")
    .replace(/<[^>]*>/g, "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

// Allows Unicode letters (Arabic, Latin, etc.), spaces, hyphens, apostrophes, periods
const VALID_NAME_REGEX = /^[\p{L}\p{M}][\p{L}\p{M}\s'.-]{0,49}$/u;

const validateEmailStrict = (raw) => {
  if (typeof raw !== "string") return { valid: false, clean: "" };
  const clean = raw.replace(/\u0000/g, "").trim().toLowerCase();
  if (!clean || clean.length > 254 || /[\r\n\s<>]/.test(clean)) {
    return { valid: false, clean: "" };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  return { valid: emailRegex.test(clean), clean };
};

const validatePhoneStrict = (raw) => {
  if (raw === undefined || raw === null) return { valid: true, clean: "" };
  if (typeof raw !== "string") return { valid: false, clean: "" };
  const clean = raw.replace(/\u0000/g, "").trim();
  if (!clean) return { valid: true, clean: "" };
  if (!/^\+?[0-9\s\-()]{8,22}$/.test(clean)) {
    return { valid: false, clean: "" };
  }
  const digitsOnly = clean.replace(/\D/g, "");
  if (digitsOnly.length < 8 || digitsOnly.length > 15) {
    return { valid: false, clean: "" };
  }
  return { valid: true, clean };
};

const validatePasswordStrength = (pw) => {
  if (typeof pw !== "string") return { valid: false, reason: "passwordComplexity" };
  if (pw.length > 72) return { valid: false, reason: "settingsPasswordTooLong" };
  const hasUpperCase = /[A-Z]/.test(pw);
  const hasLowerCase = /[a-z]/.test(pw);
  const hasNumber = /\d/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);
  const isLongEnough = pw.length >= 8;
  if (!isLongEnough || !hasUpperCase || !hasLowerCase || !hasNumber || !hasSymbol) {
    return { valid: false, reason: "passwordComplexity" };
  }
  return { valid: true };
};

/**
 * Inspect binary magic bytes to prevent MIME/extension spoofing & SVG XSS uploads.
 */
const detectSafeImageFromBuffer = (buffer) => {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { mime: "image/jpeg", ext: ".jpg" };
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return { mime: "image/png", ext: ".png" };
  }

  // WEBP: RIFF....WEBP
  if (
    buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
    buffer.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    return { mime: "image/webp", ext: ".webp" };
  }

  // GIF: GIF87a or GIF89a
  const gifHeader = buffer.subarray(0, 6).toString("ascii");
  if (gifHeader === "GIF87a" || gifHeader === "GIF89a") {
    return { mime: "image/gif", ext: ".gif" };
  }

  return null;
};

const removeOldLocalAvatarFile = (avatarPath) => {
  if (typeof avatarPath !== "string" || !avatarPath.startsWith("/uploads/avatars/")) {
    return;
  }
  const filename = path.basename(avatarPath);
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) return;
  const resolved = path.resolve(avatarsUploadDir, filename);
  if (!resolved.startsWith(avatarsUploadDir + path.sep)) return;
  try {
    if (fs.existsSync(resolved)) {
      fs.unlinkSync(resolved);
    }
  } catch (err) {
    console.warn("Could not delete previous avatar file:", err.message);
  }
};

const ensureSettingsSecurity = (user) => {
  if (!user.settingsSecurity) user.settingsSecurity = {};
  if (!user.settingsSecurity.passwordReset) {
    user.settingsSecurity.passwordReset = {
      codeHash: null,
      expiresAt: null,
      attempts: 0,
      deviceId: null,
      lastSentAt: null,
      requestTimestamps: [],
      lockUntil: null,
      resetTokenHash: null,
      resetTokenExpiresAt: null,
    };
  }
  if (!user.settingsSecurity.emailChange) {
    user.settingsSecurity.emailChange = {
      pendingEmail: null,
      codeHash: null,
      expiresAt: null,
      attempts: 0,
      deviceId: null,
      lastSentAt: null,
      requestTimestamps: [],
      lockUntil: null,
    };
  }
  return user.settingsSecurity;
};

const buildSanitizedUser = (user) => ({
  id: user._id,
  role: user.role,
  ferstname: user.ferstname,
  lastname: user.lastname || "",
  username: user.username,
  email: user.email,
  avatar: user.avatar || "",
  phoneNumber: user.PhoneNumber || "",
  PhoneNumber: user.PhoneNumber || "",
  authProvider: user.authProvider || "local",
  hasPassword: Boolean(user.password),
  VerificaionStatus: user.VerificaionStatus,
  lang: user.lang || "ar",
  passwordChangedAt: user.settingsSecurity?.passwordChangedAt || null,
  createdAt: user.createdAt || null,
});

const getCookieOptions = (maxAgeMs) => {
  const isProduction = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    ...(maxAgeMs !== undefined ? { maxAge: maxAgeMs } : {}),
    path: "/",
  };
};

/**
 * Rotate JWT accessToken & Sessions refreshToken when email or password changes.
 * Revokes all other sessions to protect against stolen tokens/devices.
 */
const rotateSessionTokens = async (user, req, res) => {
  const deviceId = req.deviceId;
  const clientIp = getClientIp(req);

  await Sessions.deleteMany({ userID: user._id });

  const refreshToken = jwt.sign(
    {
      userId: user._id,
      email: user.email,
      role: user.role,
      deviceId,
      type: "user-access",
    },
    process.env.REFRESH_TOKEN,
    { expiresIn: "39d" }
  );

  await Sessions.create({
    userID: user._id,
    deviceId,
    ipAddress: clientIp || "unknown",
    refreshToken,
    loginDate: new Date(),
    logoutDate: null,
  });

  const accessToken = jwt.sign(
    {
      userId: user._id,
      email: user.email,
      role: user.role,
      deviceId,
      type: "user-access",
    },
    process.env.ACCESS_TOKEN,
    { expiresIn: "7d" }
  );

  res.cookie("accessToken", accessToken, getCookieOptions(7 * 24 * 60 * 60 * 1000));
  return accessToken;
};

// ─────────────────────────────────────────────────────────────────────────────
// 📧 Bilingual Email Templates & Resilient Sender (Resend + Nodemailer Fallback)
// ─────────────────────────────────────────────────────────────────────────────
const sendEmailWithFallback = async ({ to, subject, html }) => {
  let lastError = null;

  if (process.env.RESEND_API_KEY) {
    try {
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
      lastError = error?.message || "Resend error";
      console.warn("Settings email Resend failed, trying Nodemailer fallback:", lastError);
    } catch (err) {
      lastError = err.message;
      console.warn("Settings email Resend exception, trying Nodemailer fallback:", lastError);
    }
  }

  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
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
        to,
        subject,
        html,
      });
      return { success: true, provider: "nodemailer" };
    } catch (nmErr) {
      lastError = nmErr.message;
      console.error("Settings email Nodemailer fallback failed:", lastError);
    }
  }

  return { success: false, error: lastError || "No email provider configured" };
};

const buildOtpEmailHtml = ({ lang, name, code, purpose, targetEmail }) => {
  const isAr = lang === "ar";
  const safeName = escapeHtml(name || (isAr ? "عزيزي المستخدم" : "Valued Member"));
  const safeEmail = escapeHtml(targetEmail || "");
  const year = new Date().getFullYear();

  if (purpose === "email-change") {
    const subject = isAr
      ? "رمز تأكيد تغيير البريد الإلكتروني — أكاديمية المستقبل"
      : "Verify Your New Email Address — ALMOSTAQEL AQADEMY";

    const html = isAr
      ? `<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',Tahoma,sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;direction:rtl;text-align:right;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:28px 20px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:23px;">أكاديمية المستقبل</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.88);font-size:13px;">تأكيد تغيير البريد الإلكتروني</p>
    </div>
    <div style="padding:34px 28px;">
      <p style="font-size:18px;font-weight:700;margin-top:0;">مرحباً ${safeName}،</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        تلقينا طلباً لربط البريد الإلكتروني <strong style="color:#fff;">${safeEmail}</strong> بحسابك في أكاديمية المستقبل. أدخل رمز التحقق التالي لإتمام التغيير بأمان:
      </p>
      <div style="background:#07070f;border:2px dashed #8b5cf6;border-radius:14px;padding:24px;text-align:center;margin:24px 0;">
        <p style="margin:0 0 8px;color:#94a3b8;font-size:12px;">رمز التحقق (صالح لمدة 5 دقائق)</p>
        <p style="margin:0;font-size:36px;font-weight:800;color:#c084fc;letter-spacing:10px;direction:ltr;font-family:monospace;">${code}</p>
      </div>
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;">
        إذا لم تطلب تغيير بريدك الإلكتروني، يرجى تجاهل هذه الرسالة وتغيير كلمة المرور فوراً لحماية حسابك.
      </p>
    </div>
    <div style="text-align:center;padding:18px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} أكاديمية المستقبل (ALMOSTAQEL AQADEMY). جميع الحقوق محفوظة.
    </div>
  </div>
</body></html>`
      : `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',Tahoma,sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:28px 20px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:23px;">ALMOSTAQEL AQADEMY</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.88);font-size:13px;">Email Change Verification</p>
    </div>
    <div style="padding:34px 28px;">
      <p style="font-size:18px;font-weight:700;margin-top:0;">Hello ${safeName},</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        We received a request to link <strong style="color:#fff;">${safeEmail}</strong> to your Almostaqel Academy account. Enter the verification code below to confirm this change:
      </p>
      <div style="background:#07070f;border:2px dashed #8b5cf6;border-radius:14px;padding:24px;text-align:center;margin:24px 0;">
        <p style="margin:0 0 8px;color:#94a3b8;font-size:12px;text-transform:uppercase;">Verification Code (Valid for 5 minutes)</p>
        <p style="margin:0;font-size:36px;font-weight:800;color:#c084fc;letter-spacing:10px;font-family:monospace;">${code}</p>
      </div>
      <p style="color:#94a3b8;font-size:13px;line-height:1.7;">
        If you did not request this email change, please ignore this message and secure your account password immediately.
      </p>
    </div>
    <div style="text-align:center;padding:18px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} ALMOSTAQEL AQADEMY. All rights reserved.
    </div>
  </div>
</body></html>`;
    return { subject, html };
  }

  // Password reset inside settings
  const subject = isAr
    ? "رمز التحقق لتغيير كلمة المرور — أكاديمية المستقبل"
    : "Password Change Verification Code — ALMOSTAQEL AQADEMY";

  const html = isAr
    ? `<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',Tahoma,sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;direction:rtl;text-align:right;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:28px 20px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:23px;">أكاديمية المستقبل</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.88);font-size:13px;">تأكيد أمان الحساب وتغيير كلمة المرور</p>
    </div>
    <div style="padding:34px 28px;">
      <p style="font-size:18px;font-weight:700;margin-top:0;">مرحباً ${safeName}،</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        لقد طلبت رمز تحقق من إعدادات الأمان لتغيير كلمة مرور حسابك دون الحاجة لكلمة المرور القديمة. استخدم الرمز التالي لإتمام التحقق:
      </p>
      <div style="background:#07070f;border:2px dashed #ec4899;border-radius:14px;padding:24px;text-align:center;margin:24px 0;">
        <p style="margin:0 0 8px;color:#94a3b8;font-size:12px;">رمز الأمان المؤقت (صالح لمدة 5 دقائق)</p>
        <p style="margin:0;font-size:36px;font-weight:800;color:#f472b6;letter-spacing:10px;direction:ltr;font-family:monospace;">${code}</p>
      </div>
      <div style="background:rgba(245,158,11,0.08);border-right:4px solid #f59e0b;border-radius:8px;padding:12px 16px;font-size:13px;color:#fde68a;line-height:1.7;">
        ⚠️ لا تشارك هذا الرمز مع أي شخص إطلاقاً. إذا لم تطلب تغيير كلمة المرور، يرجى مراجعة أمان حسابك فوراً.
      </div>
    </div>
    <div style="text-align:center;padding:18px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} أكاديمية المستقبل (ALMOSTAQEL AQADEMY). جميع الحقوق محفوظة.
    </div>
  </div>
</body></html>`
    : `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',Tahoma,sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:28px 20px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:23px;">ALMOSTAQEL AQADEMY</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.88);font-size:13px;">Account Security & Password Reset</p>
    </div>
    <div style="padding:34px 28px;">
      <p style="font-size:18px;font-weight:700;margin-top:0;">Hello ${safeName},</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        You requested a security code from your Account Settings to change your password without entering your old password. Use the code below to verify your identity:
      </p>
      <div style="background:#07070f;border:2px dashed #ec4899;border-radius:14px;padding:24px;text-align:center;margin:24px 0;">
        <p style="margin:0 0 8px;color:#94a3b8;font-size:12px;text-transform:uppercase;">Security Code (Valid for 5 minutes)</p>
        <p style="margin:0;font-size:36px;font-weight:800;color:#f472b6;letter-spacing:10px;font-family:monospace;">${code}</p>
      </div>
      <div style="background:rgba(245,158,11,0.08);border-left:4px solid #f59e0b;border-radius:8px;padding:12px 16px;font-size:13px;color:#fde68a;line-height:1.7;">
        ⚠️ Never share this code with anyone. If you did not request this, please secure your account immediately.
      </div>
    </div>
    <div style="text-align:center;padding:18px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} ALMOSTAQEL AQADEMY. All rights reserved.
    </div>
  </div>
</body></html>`;

  return { subject, html };
};

const buildSecurityAlertEmailHtml = ({ lang, name, eventType, extraDetail = "" }) => {
  const isAr = lang === "ar";
  const safeName = escapeHtml(name || "");
  const safeExtra = escapeHtml(extraDetail);
  const year = new Date().getFullYear();
  const timestamp = new Date().toUTCString();

  if (eventType === "email-changed") {
    const subject = isAr
      ? "تنبيه أمني: تم تغيير البريد الإلكتروني لحسابك — أكاديمية المستقبل"
      : "Security Alert: Account Email Address Changed — ALMOSTAQEL AQADEMY";
    const html = isAr
      ? `<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;direction:rtl;text-align:right;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:22px;">تنبيه أمان الحساب</h1>
    </div>
    <div style="padding:30px 26px;">
      <p style="font-size:17px;font-weight:700;margin-top:0;">مرحباً ${safeName}،</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        نود إعلامك بأنه تم تغيير البريد الإلكتروني المرتبط بحسابك إلى <strong style="color:#c084fc;">${safeExtra}</strong> بتاريخ <span dir="ltr">${timestamp}</span>، وتم إنهاء الجلسات النشطة على الأجهزة الأخرى لحمايتك.
      </p>
      <p style="color:#fda4af;font-size:13px;line-height:1.7;">
        إذا لم تقم بهذا التغيير بنفسك، يرجى التواصل مع الدعم الفني فوراً عبر support@almostaqelaqademy.com.
      </p>
    </div>
    <div style="text-align:center;padding:16px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} أكاديمية المستقبل. جميع الحقوق محفوظة.
    </div>
  </div>
</body></html>`
      : `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:22px;">Account Security Alert</h1>
    </div>
    <div style="padding:30px 26px;">
      <p style="font-size:17px;font-weight:700;margin-top:0;">Hello ${safeName},</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        This is a confirmation that the email address associated with your Almostaqel Academy account was updated to <strong style="color:#c084fc;">${safeExtra}</strong> on ${timestamp}. All other active device sessions have been signed out for your security.
      </p>
      <p style="color:#fda4af;font-size:13px;line-height:1.7;">
        If you did not authorize this change, please contact support immediately at support@almostaqelaqademy.com.
      </p>
    </div>
    <div style="text-align:center;padding:16px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} ALMOSTAQEL AQADEMY. All rights reserved.
    </div>
  </div>
</body></html>`;
    return { subject, html };
  }

  const subject = isAr
    ? "تنبيه أمني: تم تحديث كلمة مرور حسابك — أكاديمية المستقبل"
    : "Security Alert: Your Password Was Updated — ALMOSTAQEL AQADEMY";
  const html = isAr
    ? `<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;direction:rtl;text-align:right;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:22px;">تم تحديث كلمة المرور</h1>
    </div>
    <div style="padding:30px 26px;">
      <p style="font-size:17px;font-weight:700;margin-top:0;">مرحباً ${safeName}،</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        تم تغيير كلمة المرور الخاصة بحسابك في أكاديمية المستقبل بنجاح بتاريخ <span dir="ltr">${timestamp}</span>، وتم إنهاء كافة الجلسات الأخرى لتعزيز أمان حسابك.
      </p>
      <p style="color:#fda4af;font-size:13px;line-height:1.7;">
        إذا لم تقم بهذا التغيير، يرجى استعادة حسابك فوراً أو التواصل مع فريق الدعم الفني عبر support@almostaqelaqademy.com.
      </p>
    </div>
    <div style="text-align:center;padding:16px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} أكاديمية المستقبل. جميع الحقوق محفوظة.
    </div>
  </div>
</body></html>`
    : `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:36px 16px;">
  <div style="max-width:600px;margin:0 auto;background:#13111c;border:1px solid #2b2440;border-radius:18px;overflow:hidden;">
    <div style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:22px;">Password Updated</h1>
    </div>
    <div style="padding:30px 26px;">
      <p style="font-size:17px;font-weight:700;margin-top:0;">Hello ${safeName},</p>
      <p style="color:#cbd5e1;line-height:1.8;font-size:14px;">
        Your Almostaqel Academy password was updated on ${timestamp}. For your security, all sessions on other devices have been signed out.
      </p>
      <p style="color:#fda4af;font-size:13px;line-height:1.7;">
        If you did not make this change, please recover your account immediately or contact support@almostaqelaqademy.com.
      </p>
    </div>
    <div style="text-align:center;padding:16px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e;">
      &copy; ${year} ALMOSTAQEL AQADEMY. All rights reserved.
    </div>
  </div>
</body></html>`;
  return { subject, html };
};

// ─────────────────────────────────────────────────────────────────────────────
// 🖼️ Multer Memory Storage for Secure Avatar Magic-Byte Validation
// ─────────────────────────────────────────────────────────────────────────────
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_AVATAR_BYTES,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"];
    if (allowedMimes.includes(String(file.mimetype || "").toLowerCase())) {
      cb(null, true);
    } else {
      cb(new Error("INVALID_AVATAR_TYPE"), false);
    }
  },
});

// Fallback binary server for `/uploads/avatars/:filename` (survives ephemeral cloud restarts)
export const serveAvatarUploadFallback = async (req, res) => {
  try {
    const rawFilename = String(req.params.filename || "").trim();
    if (!rawFilename || !/^[a-zA-Z0-9._-]+$/.test(rawFilename)) {
      return res.status(404).end();
    }

    const avatarPath = `/uploads/avatars/${rawFilename}`;
    const user = await Users.findOne({ avatar: avatarPath }).select("avatarDataUrl").lean();
    const dataUrl = user?.avatarDataUrl;
    if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/")) {
      return res.status(404).end();
    }

    const match = dataUrl.match(/^data:(image\/(?:jpeg|png|webp|gif));base64,(.+)$/);
    if (!match) return res.status(404).end();

    const buffer = Buffer.from(match[2], "base64");
    if (!buffer || buffer.length === 0) return res.status(404).end();

    res.setHeader("Content-Type", match[1]);
    res.setHeader("Content-Length", buffer.length);
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
    return res.status(200).send(buffer);
  } catch (err) {
    console.error("Error in serveAvatarUploadFallback:", err);
    return res.status(500).end();
  }
};

// Shared guard to fetch mutable user doc and block admin accounts on client settings
const loadAuthenticatedUser = async (req, res) => {
  const user = await Users.findById(req.user.userId);
  if (!user || user.role === "admin") {
    res.status(404).json({ message: getMsg("accountNotFound", req), accountRestricted: true });
    return null;
  }
  return user;
};

// Shared helper to check OTP request rate limit & cooldown
const checkOtpSendRateLimit = (bucket, req, user) => {
  const now = Date.now();
  if (bucket.lockUntil && new Date(bucket.lockUntil).getTime() > now) {
    const retryAfter = Math.ceil((new Date(bucket.lockUntil).getTime() - now) / 1000);
    return {
      blocked: true,
      status: 429,
      retryAfter,
      message: getMsg("settingsResetCodeRateLimit", req, user),
    };
  }

  if (bucket.lastSentAt) {
    const elapsed = now - new Date(bucket.lastSentAt).getTime();
    if (elapsed < OTP_COOLDOWN_MS) {
      const retryAfter = Math.ceil((OTP_COOLDOWN_MS - elapsed) / 1000);
      return {
        blocked: true,
        status: 429,
        retryAfter,
        message: getMsg("settingsResetCodeCooldown", req, user),
      };
    }
  }

  const recent = (bucket.requestTimestamps || []).filter(
    (ts) => now - new Date(ts).getTime() < OTP_WINDOW_MS
  );
  bucket.requestTimestamps = recent;

  if (recent.length >= OTP_MAX_REQUESTS_IN_WINDOW) {
    bucket.lockUntil = new Date(now + OTP_LOCKOUT_MS);
    return {
      blocked: true,
      status: 429,
      retryAfter: Math.ceil(OTP_LOCKOUT_MS / 1000),
      message: getMsg("settingsResetCodeRateLimit", req, user),
      shouldSave: true,
    };
  }

  return { blocked: false };
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. GET /api/settings/profile — Fetch current authenticated user settings state
// ─────────────────────────────────────────────────────────────────────────────
router.get("/settings/profile", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const now = Date.now();
    const sec = user.settingsSecurity || {};
    const passwordLockSeconds =
      sec.passwordLockUntil && new Date(sec.passwordLockUntil).getTime() > now
        ? Math.ceil((new Date(sec.passwordLockUntil).getTime() - now) / 1000)
        : 0;

    const pendingEmailObj = sec.emailChange;
    const hasPendingEmail = Boolean(
      pendingEmailObj?.pendingEmail &&
        pendingEmailObj?.codeHash &&
        pendingEmailObj?.expiresAt &&
        new Date(pendingEmailObj.expiresAt).getTime() > now &&
        String(pendingEmailObj.deviceId) === String(req.deviceId)
    );

    return res.status(200).json({
      user: buildSanitizedUser(user),
      security: {
        hasPassword: Boolean(user.password),
        authProvider: user.authProvider || "local",
        passwordChangedAt: sec.passwordChangedAt || null,
        passwordLockSeconds,
        pendingEmail: hasPendingEmail ? pendingEmailObj.pendingEmail : null,
        pendingEmailExpiresIn: hasPendingEmail
          ? Math.ceil((new Date(pendingEmailObj.expiresAt).getTime() - now) / 1000)
          : 0,
      },
    });
  } catch (err) {
    console.error("GET /settings/profile error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. PUT /api/settings/profile — Update First Name, Last Name, Phone Number
//    (Email changes go through verified OTP endpoints below for security)
// ─────────────────────────────────────────────────────────────────────────────
router.put("/settings/profile", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    // Strict whitelist — never accept role, email, password, verification, purchases
    const { ferstname, firstname, lastname, phoneNumber, PhoneNumber } = req.body || {};
    const rawFirst = ferstname !== undefined ? ferstname : firstname;
    const rawLast = lastname;
    const rawPhone = phoneNumber !== undefined ? phoneNumber : PhoneNumber;

    const errors = {};

    const cleanFirst = sanitizePersonName(rawFirst);
    if (!cleanFirst || cleanFirst.length < 2 || cleanFirst.length > 50 || !VALID_NAME_REGEX.test(cleanFirst)) {
      errors.ferstname = getMsg("settingsInvalidFirstName", req, user);
    }

    const cleanLast = sanitizePersonName(rawLast);
    if (!cleanLast || cleanLast.length < 2 || cleanLast.length > 50 || !VALID_NAME_REGEX.test(cleanLast)) {
      errors.lastname = getMsg("settingsInvalidLastName", req, user);
    }

    const phoneResult = validatePhoneStrict(rawPhone);
    if (!phoneResult.valid) {
      errors.phoneNumber = getMsg("settingsInvalidPhone", req, user);
    }

    if (Object.keys(errors).length > 0) {
      const firstField = Object.keys(errors)[0];
      return res.status(400).json({
        message: errors[firstField],
        field: firstField,
        errors,
      });
    }

    const clientLang = getLang(req, user);
    const hasChanged =
      user.ferstname !== cleanFirst ||
      (user.lastname || "") !== cleanLast ||
      (user.PhoneNumber || "") !== phoneResult.clean;

    if (!hasChanged) {
      return res.status(200).json({
        unchanged: true,
        message: getMsg("settingsNoChanges", req, user),
        user: buildSanitizedUser(user),
      });
    }

    user.ferstname = cleanFirst;
    user.lastname = cleanLast;
    user.PhoneNumber = phoneResult.clean;
    if (user.lang !== clientLang) user.lang = clientLang;
    await user.save();

    return res.status(200).json({
      message: getMsg("settingsProfileUpdated", req, user),
      user: buildSanitizedUser(user),
    });
  } catch (err) {
    console.error("PUT /settings/profile error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. POST /api/settings/avatar — Upload Profile Picture (Magic Bytes Verified)
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/avatar", preCheckDeviceBanMiddleware, userAuth, (req, res) => {
  avatarUpload.single("avatar")(req, res, async (uploadErr) => {
    if (uploadErr) {
      if (uploadErr instanceof multer.MulterError && uploadErr.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          field: "avatar",
          message: getMsg("settingsAvatarTooLarge", req),
        });
      }
      return res.status(400).json({
        field: "avatar",
        message: getMsg("settingsAvatarInvalidType", req),
      });
    }

    try {
      const user = await loadAuthenticatedUser(req, res);
      if (!user) return;

      const clientIp = getClientIp(req);
      const spamCheck = await recordAndCheckSpamRate({
        email: user.email,
        deviceId: req.deviceId,
        ipAddress: clientIp,
      });
      if (spamCheck.isSpam) {
        return res.status(403).json({
          banned: true,
          accountRestricted: true,
          message: getMsg("spamAttackBan", req, user),
        });
      }

      if (!req.file || !Buffer.isBuffer(req.file.buffer) || req.file.buffer.length === 0) {
        return res.status(400).json({
          field: "avatar",
          message: getMsg("settingsAvatarRequired", req, user),
        });
      }

      // Inspect binary magic bytes — never trust client MIME or filename extension alone
      const detected = detectSafeImageFromBuffer(req.file.buffer);
      if (!detected) {
        return res.status(400).json({
          field: "avatar",
          message: getMsg("settingsAvatarInvalidType", req, user),
        });
      }

      const randomHex = crypto.randomBytes(8).toString("hex");
      const filename = `avatar-${user._id}-${Date.now()}-${randomHex}${detected.ext}`;
      const diskPath = path.join(avatarsUploadDir, filename);

      await fs.promises.writeFile(diskPath, req.file.buffer);

      const previousAvatar = user.avatar;
      const newAvatarUrl = `/uploads/avatars/${filename}`;
      user.avatar = newAvatarUrl;

      // Lean DB fallback so avatars never 404 on ephemeral cloud hosts
      if (req.file.buffer.length <= MAX_DB_AVATAR_FALLBACK_BYTES) {
        user.avatarDataUrl = `data:${detected.mime};base64,${req.file.buffer.toString("base64")}`;
      } else {
        user.avatarDataUrl = "";
      }

      await user.save();

      // Remove old local avatar file after DB commit succeeds
      if (previousAvatar && previousAvatar !== newAvatarUrl) {
        removeOldLocalAvatarFile(previousAvatar);
      }

      return res.status(200).json({
        message: getMsg("settingsAvatarUpdated", req, user),
        avatar: newAvatarUrl,
        user: buildSanitizedUser(user),
      });
    } catch (err) {
      console.error("POST /settings/avatar error:", err);
      return res.status(500).json({ message: getMsg("serverError", req) });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. DELETE /api/settings/avatar — Remove Profile Picture
// ─────────────────────────────────────────────────────────────────────────────
router.delete("/settings/avatar", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const previousAvatar = user.avatar;
    user.avatar = "";
    user.avatarDataUrl = "";
    await user.save();

    if (previousAvatar) {
      removeOldLocalAvatarFile(previousAvatar);
    }

    return res.status(200).json({
      message: getMsg("settingsAvatarRemoved", req, user),
      user: buildSanitizedUser(user),
    });
  } catch (err) {
    console.error("DELETE /settings/avatar error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. POST /api/settings/email/request-change — Step 1 of Secure Email Change
//    Requires current password (if user has one), checks bans & uniqueness,
//    sends 6-digit OTP to the NEW email address.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/email/request-change", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const { newEmail, currentPassword } = req.body || {};
    const emailCheck = validateEmailStrict(newEmail);
    if (!emailCheck.valid) {
      return res.status(400).json({
        field: "email",
        message: getMsg("settingsInvalidEmail", req, user),
      });
    }

    const cleanNewEmail = emailCheck.clean;
    if (cleanNewEmail === String(user.email || "").toLowerCase().trim()) {
      return res.status(400).json({
        field: "email",
        message: getMsg("settingsEmailSameAsCurrent", req, user),
      });
    }

    // Check if the target email is banned platform-wide
    const targetEmailBan = await checkIsBanned({ email: cleanNewEmail });
    if (targetEmailBan.isBanned) {
      return res.status(403).json({
        field: "email",
        message: getMsg("emailPermanentBan", req, user),
      });
    }

    // Ensure target email is not already registered by another user
    const existingEmailOwner = await Users.findOne({
      email: cleanNewEmail,
      _id: { $ne: user._id },
    })
      .select("_id")
      .lean();
    if (existingEmailOwner) {
      return res.status(409).json({
        field: "email",
        message: getMsg("emailAlreadyExists", req, user),
      });
    }

    const sec = ensureSettingsSecurity(user);
    const now = Date.now();

    // If user has a local password, require verifying currentPassword to prevent session-hijack takeover
    if (user.password) {
      if (sec.passwordLockUntil && new Date(sec.passwordLockUntil).getTime() > now) {
        const retryAfter = Math.ceil((new Date(sec.passwordLockUntil).getTime() - now) / 1000);
        return res.status(429).json({
          field: "currentPassword",
          retryAfter,
          message: getMsg("settingsPasswordLockout", req, user),
        });
      }

      if (typeof currentPassword !== "string" || !currentPassword) {
        return res.status(400).json({
          field: "currentPassword",
          code: "CURRENT_PASSWORD_REQUIRED",
          message: getMsg("settingsCurrentPasswordRequired", req, user),
        });
      }

      const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordValid) {
        const nextAttempts = (sec.passwordFailedAttempts || 0) + 1;
        if (nextAttempts >= PASSWORD_MAX_FAILED_ATTEMPTS) {
          sec.passwordFailedAttempts = 0;
          sec.passwordLockUntil = new Date(now + PASSWORD_LOCKOUT_MS);
          user.markModified("settingsSecurity");
          await user.save();
          return res.status(429).json({
            field: "currentPassword",
            code: "PASSWORD_LOCKED",
            retryAfter: Math.ceil(PASSWORD_LOCKOUT_MS / 1000),
            message: getMsg("settingsPasswordLockout", req, user),
          });
        }
        sec.passwordFailedAttempts = nextAttempts;
        user.markModified("settingsSecurity");
        await user.save();
        return res.status(400).json({
          field: "currentPassword",
          code: "INVALID_CURRENT_PASSWORD",
          remainingAttempts: PASSWORD_MAX_FAILED_ATTEMPTS - nextAttempts,
          message: getMsg("settingsCurrentPasswordIncorrect", req, user),
        });
      }

      // Reset password failures on match
      sec.passwordFailedAttempts = 0;
      sec.passwordLockUntil = null;
    }

    // Check email-change OTP rate limit & cooldown
    const rateCheck = checkOtpSendRateLimit(sec.emailChange, req, user);
    if (rateCheck.blocked) {
      if (rateCheck.shouldSave) {
        user.markModified("settingsSecurity");
        await user.save();
      }
      return res.status(rateCheck.status).json({
        retryAfter: rateCheck.retryAfter,
        message: rateCheck.message,
      });
    }

    const otpCode = String(crypto.randomInt(100000, 999999));
    const clientLang = getLang(req, user);
    const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim() || user.username;
    const emailPayload = buildOtpEmailHtml({
      lang: clientLang,
      name: fullName,
      code: otpCode,
      purpose: "email-change",
      targetEmail: cleanNewEmail,
    });

    const emailResult = await sendEmailWithFallback({
      to: cleanNewEmail,
      subject: emailPayload.subject,
      html: emailPayload.html,
    });

    if (!emailResult.success) {
      return res.status(503).json({
        emailFailed: true,
        message: getMsg("settingsEmailSendFailed", req, user),
      });
    }

    sec.emailChange.pendingEmail = cleanNewEmail;
    sec.emailChange.codeHash = hashSecuritySecret(otpCode, user._id, `email-change:${cleanNewEmail}`);
    sec.emailChange.expiresAt = new Date(now + OTP_TTL_MS);
    sec.emailChange.attempts = 0;
    sec.emailChange.deviceId = req.deviceId;
    sec.emailChange.lastSentAt = new Date(now);
    sec.emailChange.requestTimestamps = [...(sec.emailChange.requestTimestamps || []), new Date(now)];
    user.markModified("settingsSecurity");
    await user.save();

    return res.status(200).json({
      sent: true,
      pendingEmail: cleanNewEmail,
      maskedEmail: maskEmail(cleanNewEmail),
      expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
      cooldownSeconds: Math.floor(OTP_COOLDOWN_MS / 1000),
      message: getMsg("settingsEmailCodeSent", req, user),
    });
  } catch (err) {
    console.error("POST /settings/email/request-change error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. POST /api/settings/email/confirm-change — Step 2 of Secure Email Change
//    Verifies OTP, updates email, rotates JWT & Sessions, notifies old email.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/email/confirm-change", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const rawCode = typeof req.body?.code === "string" || typeof req.body?.code === "number"
      ? String(req.body.code).trim()
      : "";

    if (!/^\d{6}$/.test(rawCode)) {
      return res.status(400).json({
        field: "code",
        code: "INVALID_OTP_FORMAT",
        message: getMsg("codeIncorrect", req, user),
      });
    }

    const sec = ensureSettingsSecurity(user);
    const ec = sec.emailChange;
    const now = Date.now();

    if (!ec.pendingEmail || !ec.codeHash || !ec.expiresAt || new Date(ec.expiresAt).getTime() <= now) {
      ec.pendingEmail = null;
      ec.codeHash = null;
      ec.expiresAt = null;
      ec.attempts = 0;
      user.markModified("settingsSecurity");
      await user.save();
      return res.status(400).json({
        field: "code",
        expired: true,
        message: getMsg("settingsEmailChangeExpired", req, user),
      });
    }

    if (String(ec.deviceId) !== String(req.deviceId)) {
      return res.status(403).json({
        field: "code",
        message: getMsg("settingsEmailChangeDeviceMismatch", req, user),
      });
    }

    const incomingHash = hashSecuritySecret(rawCode, user._id, `email-change:${ec.pendingEmail}`);
    if (!timingSafeEqualHex(incomingHash, ec.codeHash)) {
      const nextAttempts = (ec.attempts || 0) + 1;
      if (nextAttempts >= OTP_MAX_VERIFY_ATTEMPTS) {
        ec.pendingEmail = null;
        ec.codeHash = null;
        ec.expiresAt = null;
        ec.attempts = 0;
        user.markModified("settingsSecurity");
        await user.save();
        return res.status(429).json({
          field: "code",
          codeInvalidated: true,
          message: getMsg("settingsResetCodeMaxAttempts", req, user),
        });
      }
      ec.attempts = nextAttempts;
      user.markModified("settingsSecurity");
      await user.save();
      return res.status(400).json({
        field: "code",
        code: "INVALID_OTP",
        remainingAttempts: OTP_MAX_VERIFY_ATTEMPTS - nextAttempts,
        message: getMsg("codeIncorrect", req, user),
      });
    }

    const newEmail = ec.pendingEmail;
    const oldEmail = user.email;

    // Re-check ban & uniqueness right before atomic update
    const targetEmailBan = await checkIsBanned({ email: newEmail });
    if (targetEmailBan.isBanned) {
      return res.status(403).json({
        field: "email",
        message: getMsg("emailPermanentBan", req, user),
      });
    }

    const conflict = await Users.findOne({ email: newEmail, _id: { $ne: user._id } })
      .select("_id")
      .lean();
    if (conflict) {
      return res.status(409).json({
        field: "email",
        message: getMsg("emailAlreadyExists", req, user),
      });
    }

    user.email = newEmail;
    ec.pendingEmail = null;
    ec.codeHash = null;
    ec.expiresAt = null;
    ec.attempts = 0;
    ec.deviceId = null;
    user.markModified("settingsSecurity");
    await user.save();

    // Rotate tokens & revoke sessions on other devices so refreshToken claims match new email
    const accessToken = await rotateSessionTokens(user, req, res);

    // Notify old email address asynchronously
    const clientLang = getLang(req, user);
    const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim() || user.username;
    const alertEmail = buildSecurityAlertEmailHtml({
      lang: clientLang,
      name: fullName,
      eventType: "email-changed",
      extraDetail: maskEmail(newEmail),
    });
    sendEmailWithFallback({
      to: oldEmail,
      subject: alertEmail.subject,
      html: alertEmail.html,
    }).catch((err) => console.warn("Old email security alert failed:", err.message));

    return res.status(200).json({
      message: getMsg("settingsEmailChangedSuccess", req, user),
      accessToken,
      user: buildSanitizedUser(user),
    });
  } catch (err) {
    console.error("POST /settings/email/confirm-change error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. PUT /api/settings/security/change-password — Standard Change Password
//    Verifies old password + complexity + lockout, revokes other sessions.
// ─────────────────────────────────────────────────────────────────────────────
router.put("/settings/security/change-password", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const { currentPassword, newPassword, confirmPassword } = req.body || {};
    const sec = ensureSettingsSecurity(user);
    const now = Date.now();

    if (!user.password) {
      return res.status(400).json({
        code: "NO_LOCAL_PASSWORD",
        message: getMsg("settingsNoLocalPassword", req, user),
      });
    }

    if (sec.passwordLockUntil && new Date(sec.passwordLockUntil).getTime() > now) {
      const retryAfter = Math.ceil((new Date(sec.passwordLockUntil).getTime() - now) / 1000);
      return res.status(429).json({
        field: "currentPassword",
        code: "PASSWORD_LOCKED",
        retryAfter,
        message: getMsg("settingsPasswordLockout", req, user),
      });
    }

    const errors = {};
    if (typeof currentPassword !== "string" || !currentPassword) {
      errors.currentPassword = getMsg("settingsCurrentPasswordRequired", req, user);
    }

    const strengthCheck = validatePasswordStrength(newPassword);
    if (!strengthCheck.valid) {
      errors.newPassword = getMsg(strengthCheck.reason, req, user);
    }

    if (typeof confirmPassword !== "string" || !confirmPassword || newPassword !== confirmPassword) {
      errors.confirmPassword = getMsg("settingsPasswordsMismatch", req, user);
    }

    if (Object.keys(errors).length > 0) {
      const firstField = Object.keys(errors)[0];
      return res.status(400).json({
        message: errors[firstField],
        field: firstField,
        errors,
      });
    }

    // Verify current password
    const isOldValid = await bcrypt.compare(currentPassword, user.password);
    if (!isOldValid) {
      const nextAttempts = (sec.passwordFailedAttempts || 0) + 1;
      if (nextAttempts >= PASSWORD_MAX_FAILED_ATTEMPTS) {
        sec.passwordFailedAttempts = 0;
        sec.passwordLockUntil = new Date(now + PASSWORD_LOCKOUT_MS);
        user.markModified("settingsSecurity");
        await user.save();
        return res.status(429).json({
          field: "currentPassword",
          code: "PASSWORD_LOCKED",
          retryAfter: Math.ceil(PASSWORD_LOCKOUT_MS / 1000),
          message: getMsg("settingsPasswordLockout", req, user),
        });
      }
      sec.passwordFailedAttempts = nextAttempts;
      user.markModified("settingsSecurity");
      await user.save();
      return res.status(400).json({
        field: "currentPassword",
        code: "INVALID_CURRENT_PASSWORD",
        remainingAttempts: PASSWORD_MAX_FAILED_ATTEMPTS - nextAttempts,
        message: getMsg("settingsCurrentPasswordIncorrect", req, user),
      });
    }

    // Prevent reusing exact same password
    const isSameAsOld = await bcrypt.compare(newPassword, user.password);
    if (isSameAsOld) {
      return res.status(400).json({
        field: "newPassword",
        code: "PASSWORD_SAME_AS_OLD",
        message: getMsg("settingsNewPasswordSameAsOld", req, user),
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    sec.passwordFailedAttempts = 0;
    sec.passwordLockUntil = null;
    sec.passwordChangedAt = new Date(now);
    sec.passwordReset.codeHash = null;
    sec.passwordReset.expiresAt = null;
    sec.passwordReset.resetTokenHash = null;
    sec.passwordReset.resetTokenExpiresAt = null;
    user.markModified("settingsSecurity");
    await user.save();

    const accessToken = await rotateSessionTokens(user, req, res);

    // Send security notification email asynchronously
    const clientLang = getLang(req, user);
    const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim() || user.username;
    const alertEmail = buildSecurityAlertEmailHtml({
      lang: clientLang,
      name: fullName,
      eventType: "password-changed",
    });
    sendEmailWithFallback({
      to: user.email,
      subject: alertEmail.subject,
      html: alertEmail.html,
    }).catch((err) => console.warn("Password change alert email failed:", err.message));

    return res.status(200).json({
      message: getMsg("settingsPasswordChangedSuccess", req, user),
      accessToken,
      user: buildSanitizedUser(user),
    });
  } catch (err) {
    console.error("PUT /settings/security/change-password error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. POST /api/settings/security/forgot-password/send-code
//    Sends a 6-digit OTP to the authenticated user's registered email so they
//    can reset their password without entering the old password.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/security/forgot-password/send-code", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const sec = ensureSettingsSecurity(user);
    const pr = sec.passwordReset;
    const now = Date.now();

    const rateCheck = checkOtpSendRateLimit(pr, req, user);
    if (rateCheck.blocked) {
      if (rateCheck.shouldSave) {
        user.markModified("settingsSecurity");
        await user.save();
      }
      return res.status(rateCheck.status).json({
        retryAfter: rateCheck.retryAfter,
        message: rateCheck.message,
      });
    }

    const otpCode = String(crypto.randomInt(100000, 999999));
    const clientLang = getLang(req, user);
    const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim() || user.username;
    const emailPayload = buildOtpEmailHtml({
      lang: clientLang,
      name: fullName,
      code: otpCode,
      purpose: "password-reset",
      targetEmail: user.email,
    });

    const emailResult = await sendEmailWithFallback({
      to: user.email,
      subject: emailPayload.subject,
      html: emailPayload.html,
    });

    if (!emailResult.success) {
      return res.status(503).json({
        emailFailed: true,
        message: getMsg("settingsEmailSendFailed", req, user),
      });
    }

    pr.codeHash = hashSecuritySecret(otpCode, user._id, "settings-pw-reset");
    pr.expiresAt = new Date(now + OTP_TTL_MS);
    pr.attempts = 0;
    pr.deviceId = req.deviceId;
    pr.lastSentAt = new Date(now);
    pr.requestTimestamps = [...(pr.requestTimestamps || []), new Date(now)];
    pr.resetTokenHash = null;
    pr.resetTokenExpiresAt = null;
    user.markModified("settingsSecurity");
    await user.save();

    return res.status(200).json({
      sent: true,
      maskedEmail: maskEmail(user.email),
      expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
      cooldownSeconds: Math.floor(OTP_COOLDOWN_MS / 1000),
      message: getMsg("settingsResetCodeSent", req, user),
    });
  } catch (err) {
    console.error("POST /settings/security/forgot-password/send-code error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. POST /api/settings/security/forgot-password/verify-code
//    Verifies the 6-digit OTP & issues a single-use cryptographic resetToken
//    allowing the user to change their password without the old password.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/security/forgot-password/verify-code", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const rawCode = typeof req.body?.code === "string" || typeof req.body?.code === "number"
      ? String(req.body.code).trim()
      : "";

    if (!/^\d{6}$/.test(rawCode)) {
      return res.status(400).json({
        field: "code",
        code: "INVALID_OTP_FORMAT",
        message: getMsg("codeIncorrect", req, user),
      });
    }

    const sec = ensureSettingsSecurity(user);
    const pr = sec.passwordReset;
    const now = Date.now();

    if (!pr.codeHash || !pr.expiresAt || new Date(pr.expiresAt).getTime() <= now) {
      pr.codeHash = null;
      pr.expiresAt = null;
      pr.attempts = 0;
      user.markModified("settingsSecurity");
      await user.save();
      return res.status(400).json({
        field: "code",
        expired: true,
        message: getMsg("settingsResetCodeExpired", req, user),
      });
    }

    if (String(pr.deviceId) !== String(req.deviceId)) {
      return res.status(403).json({
        field: "code",
        message: getMsg("codeDeviceMismatch", req, user),
      });
    }

    const incomingHash = hashSecuritySecret(rawCode, user._id, "settings-pw-reset");
    if (!timingSafeEqualHex(incomingHash, pr.codeHash)) {
      const nextAttempts = (pr.attempts || 0) + 1;
      if (nextAttempts >= OTP_MAX_VERIFY_ATTEMPTS) {
        pr.codeHash = null;
        pr.expiresAt = null;
        pr.attempts = 0;
        user.markModified("settingsSecurity");
        await user.save();
        return res.status(429).json({
          field: "code",
          codeInvalidated: true,
          message: getMsg("settingsResetCodeMaxAttempts", req, user),
        });
      }
      pr.attempts = nextAttempts;
      user.markModified("settingsSecurity");
      await user.save();
      return res.status(400).json({
        field: "code",
        code: "INVALID_OTP",
        remainingAttempts: OTP_MAX_VERIFY_ATTEMPTS - nextAttempts,
        message: getMsg("codeIncorrect", req, user),
      });
    }

    // OTP verified! Burn OTP immediately and issue single-use cryptographic resetToken
    const jti = crypto.randomBytes(24).toString("hex");
    const resetToken = jwt.sign(
      {
        userId: user._id,
        deviceId: req.deviceId,
        jti,
        type: "settings-password-reset",
      },
      process.env.ACCESS_TOKEN,
      { expiresIn: "5m" }
    );

    pr.codeHash = null;
    pr.expiresAt = null;
    pr.attempts = 0;
    pr.resetTokenHash = hashSecuritySecret(resetToken, user._id, "settings-pw-reset-token");
    pr.resetTokenExpiresAt = new Date(now + RESET_TOKEN_TTL_MS);
    user.markModified("settingsSecurity");
    await user.save();

    res.cookie("settingsResetToken", resetToken, getCookieOptions(RESET_TOKEN_TTL_MS));

    return res.status(200).json({
      verified: true,
      resetToken,
      expiresInSeconds: Math.floor(RESET_TOKEN_TTL_MS / 1000),
      message: getMsg("settingsResetCodeVerified", req, user),
    });
  } catch (err) {
    console.error("POST /settings/security/forgot-password/verify-code error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. POST /api/settings/security/forgot-password/reset-password
//     Sets a new password WITHOUT requiring the old password, authenticated by
//     the single-use verified resetToken bound to userId & deviceId.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/settings/security/forgot-password/reset-password", userAuth, async (req, res) => {
  try {
    const user = await loadAuthenticatedUser(req, res);
    if (!user) return;

    const clientIp = getClientIp(req);
    const spamCheck = await recordAndCheckSpamRate({
      email: user.email,
      deviceId: req.deviceId,
      ipAddress: clientIp,
    });
    if (spamCheck.isSpam) {
      return res.status(403).json({
        banned: true,
        accountRestricted: true,
        message: getMsg("spamAttackBan", req, user),
      });
    }

    const { resetToken: bodyToken, newPassword, confirmPassword } = req.body || {};
    const resetToken = (typeof bodyToken === "string" && bodyToken.trim()) || req.cookies?.settingsResetToken;

    if (!resetToken) {
      return res.status(400).json({
        expired: true,
        code: "RESET_TOKEN_MISSING",
        message: getMsg("settingsResetTokenInvalid", req, user),
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(resetToken, process.env.ACCESS_TOKEN);
    } catch {
      res.clearCookie("settingsResetToken", getCookieOptions());
      return res.status(400).json({
        expired: true,
        code: "RESET_TOKEN_EXPIRED",
        message: getMsg("settingsResetTokenInvalid", req, user),
      });
    }

    if (
      !decoded ||
      decoded.type !== "settings-password-reset" ||
      String(decoded.userId) !== String(user._id) ||
      String(decoded.deviceId) !== String(req.deviceId)
    ) {
      res.clearCookie("settingsResetToken", getCookieOptions());
      return res.status(403).json({
        expired: true,
        message: getMsg("tokenUserMismatch", req, user),
      });
    }

    const sec = ensureSettingsSecurity(user);
    const pr = sec.passwordReset;
    const now = Date.now();

    if (
      !pr.resetTokenHash ||
      !pr.resetTokenExpiresAt ||
      new Date(pr.resetTokenExpiresAt).getTime() <= now
    ) {
      pr.resetTokenHash = null;
      pr.resetTokenExpiresAt = null;
      user.markModified("settingsSecurity");
      await user.save();
      res.clearCookie("settingsResetToken", getCookieOptions());
      return res.status(400).json({
        expired: true,
        message: getMsg("settingsResetTokenInvalid", req, user),
      });
    }

    const incomingTokenHash = hashSecuritySecret(resetToken, user._id, "settings-pw-reset-token");
    if (!timingSafeEqualHex(incomingTokenHash, pr.resetTokenHash)) {
      res.clearCookie("settingsResetToken", getCookieOptions());
      return res.status(400).json({
        expired: true,
        message: getMsg("settingsResetTokenInvalid", req, user),
      });
    }

    // Validate new password & confirm password
    const errors = {};
    const strengthCheck = validatePasswordStrength(newPassword);
    if (!strengthCheck.valid) {
      errors.newPassword = getMsg(strengthCheck.reason, req, user);
    }
    if (typeof confirmPassword !== "string" || !confirmPassword || newPassword !== confirmPassword) {
      errors.confirmPassword = getMsg("settingsPasswordsMismatch", req, user);
    }
    if (Object.keys(errors).length > 0) {
      const firstField = Object.keys(errors)[0];
      return res.status(400).json({
        message: errors[firstField],
        field: firstField,
        errors,
      });
    }

    // Update password & burn resetToken atomically
    user.password = await bcrypt.hash(newPassword, 12);
    sec.passwordFailedAttempts = 0;
    sec.passwordLockUntil = null;
    sec.passwordChangedAt = new Date(now);
    pr.codeHash = null;
    pr.expiresAt = null;
    pr.attempts = 0;
    pr.resetTokenHash = null;
    pr.resetTokenExpiresAt = null;
    user.markModified("settingsSecurity");
    await user.save();

    res.clearCookie("settingsResetToken", getCookieOptions());
    const accessToken = await rotateSessionTokens(user, req, res);

    // Notify user asynchronously
    const clientLang = getLang(req, user);
    const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim() || user.username;
    const alertEmail = buildSecurityAlertEmailHtml({
      lang: clientLang,
      name: fullName,
      eventType: "password-changed",
    });
    sendEmailWithFallback({
      to: user.email,
      subject: alertEmail.subject,
      html: alertEmail.html,
    }).catch((err) => console.warn("Password reset alert email failed:", err.message));

    return res.status(200).json({
      message: getMsg("settingsPasswordResetSuccess", req, user),
      accessToken,
      user: buildSanitizedUser(user),
    });
  } catch (err) {
    console.error("POST /settings/security/forgot-password/reset-password error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. GET /api/profile/stats — Unified Authenticated User Session Hydration
//     Returns user profile, security metadata, real learning view statistics,
//     latest 4 recentActivity items, AND full lightweight watchedItems list so
//     the frontend hydrates sessionStorage in ONE single DB round-trip per session.
//     NOTE: Certificates, Badges, and Awards are intentionally NOT implemented
//     in the backend yet (frontend displays a Coming Soon notice).
// ─────────────────────────────────────────────────────────────────────────────
const buildHydratedWatchedItems = async (activity = {}) => {
  const watchedMap = new Map();

  if (Array.isArray(activity.recentHistory)) {
    for (const entry of activity.recentHistory) {
      if (!entry?.itemId) continue;
      watchedMap.set(String(entry.itemId), {
        itemId: entry.itemId,
        category: entry.category || "course",
        lastViewedAt: entry.lastViewedAt || null,
        viewsCount: entry.viewsCount || 1,
      });
    }
  }

  const addFromArray = (arr, cat) => {
    if (!Array.isArray(arr)) return;
    for (const id of arr) {
      if (!id) continue;
      const key = String(id);
      if (!watchedMap.has(key)) {
        watchedMap.set(key, {
          itemId: id,
          category: cat,
          lastViewedAt: null,
          viewsCount: 1,
        });
      }
    }
  };

  addFromArray(activity.viewedArticles, "article");
  addFromArray(activity.viewedVideos, "video");
  addFromArray(activity.viewedCourses, "course");

  const entries = Array.from(watchedMap.values());
  if (entries.length === 0) return [];

  const learningDocs = await Learning.find({
    _id: { $in: entries.map((e) => e.itemId) },
    status: "published",
  })
    .select(
      "_id title titleAr description descriptionAr type tag category level levelAr image thumbnail slug hours duration lessons createdAt"
    )
    .lean();

  const docMap = new Map(learningDocs.map((d) => [String(d._id), d]));

  return entries
    .map((entry) => {
      const doc = docMap.get(String(entry.itemId));
      if (!doc) return null;
      const deliveryImage =
        doc.thumbnail?.url ||
        (doc.image && !String(doc.image).startsWith("data:") ? doc.image : "");
      return {
        id: String(doc._id),
        slug: doc.slug || "",
        category: entry.category,
        title: doc.title || "",
        titleAr: doc.titleAr || doc.title || "",
        description: doc.description || "",
        descriptionAr: doc.descriptionAr || doc.description || "",
        tag: doc.tag || doc.category || "",
        level: doc.level || "",
        levelAr: doc.levelAr || doc.level || "",
        hours: doc.hours || 0,
        duration: doc.duration || "",
        lessons: doc.lessons || 0,
        image: deliveryImage,
        lastViewedAt: entry.lastViewedAt || doc.createdAt || null,
        viewsCount: entry.viewsCount || 1,
      };
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.lastViewedAt || 0) - new Date(a.lastViewedAt || 0));
};

router.get("/profile/stats", userAuth, async (req, res) => {
  try {
    const user = await Users.findById(req.user.userId)
      .select(
        "role ferstname lastname username email avatar PhoneNumber authProvider password VerificaionStatus lang createdAt purchasedProducts cartProducts settingsSecurity learningActivity"
      )
      .lean();

    if (!user || user.role === "admin") {
      return res.status(404).json({
        message: getMsg("accountNotFound", req),
        accountRestricted: true,
      });
    }

    const activity = user.learningActivity || {};
    const now = Date.now();
    const sec = user.settingsSecurity || {};
    const passwordLockSeconds =
      sec.passwordLockUntil && new Date(sec.passwordLockUntil).getTime() > now
        ? Math.ceil((new Date(sec.passwordLockUntil).getTime() - now) / 1000)
        : 0;
    const pendingEmailObj = sec.emailChange;
    const hasPendingEmail = Boolean(
      pendingEmailObj?.pendingEmail &&
        pendingEmailObj?.codeHash &&
        pendingEmailObj?.expiresAt &&
        new Date(pendingEmailObj.expiresAt).getTime() > now &&
        String(pendingEmailObj.deviceId) === String(req.deviceId)
    );

    const [
      articlesCatalogCount,
      videosCatalogCount,
      coursesCatalogCount,
      watchedItems,
    ] = await Promise.all([
      Learning.countDocuments({
        status: "published",
        type: { $in: ["Articles", "article"] },
      }),
      Learning.countDocuments({
        status: "published",
        type: { $in: ["Videos", "video", "All Vidios", "ai-video", "ai_video"] },
      }),
      Learning.countDocuments({
        status: "published",
        type: { $in: ["Courses", "course"] },
      }),
      buildHydratedWatchedItems(activity),
    ]);

    let articlesViewed = 0;
    let videosViewed = 0;
    let coursesViewed = 0;
    for (const w of watchedItems) {
      if (w.category === "article") articlesViewed += 1;
      else if (w.category === "video") videosViewed += 1;
      else coursesViewed += 1;
    }

    const totalContentViewed = watchedItems.length;
    const totalCatalogCount = articlesCatalogCount + videosCatalogCount + coursesCatalogCount;
    const recentActivity = watchedItems.slice(0, 4);

    return res.status(200).json({
      user: buildSanitizedUser(user),
      security: {
        hasPassword: Boolean(user.password),
        authProvider: user.authProvider || "local",
        passwordChangedAt: sec.passwordChangedAt || null,
        passwordLockSeconds,
        pendingEmail: hasPendingEmail ? pendingEmailObj.pendingEmail : null,
        pendingEmailExpiresIn: hasPendingEmail
          ? Math.ceil((new Date(pendingEmailObj.expiresAt).getTime() - now) / 1000)
          : 0,
      },
      stats: {
        articlesViewed,
        videosViewed,
        coursesViewed,
        totalContentViewed,
        purchasedCount: Array.isArray(user.purchasedProducts) ? user.purchasedProducts.length : 0,
        cartCount: Array.isArray(user.cartProducts) ? user.cartProducts.length : 0,
        catalogTotals: {
          articles: articlesCatalogCount,
          videos: videosCatalogCount,
          courses: coursesCatalogCount,
          total: totalCatalogCount,
        },
      },
      recentActivity,
      watchedItems,
    });
  } catch (err) {
    console.error("GET /profile/stats error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 11b. POST /api/profile/watched/record — Persist a watched learning item in DB
//      Used after optimistic sessionStorage recording (e.g. when content loaded
//      from contentSessionCache without hitting the protected content endpoint).
// ─────────────────────────────────────────────────────────────────────────────
router.post("/profile/watched/record", userAuth, async (req, res) => {
  try {
    const rawItemId = String(req.body?.itemId || "").trim();
    const rawCategory = String(req.body?.category || "").trim();

    if (!rawItemId || !/^[0-9a-fA-F]{24}$/.test(rawItemId)) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    const doc = await Learning.findOne({ _id: rawItemId, status: "published" })
      .select("_id type")
      .lean();
    if (!doc) {
      return res.status(404).json({ message: getMsg("articleNotFound", req) });
    }

    await recordUserLearningView(req.user.userId, doc._id, rawCategory || doc.type);
    return res.status(200).json({ recorded: true, itemId: String(doc._id) });
  } catch (err) {
    console.error("POST /profile/watched/record error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 12. GET /api/profile/watched — Full Paginated Watched Learning Content History
//     Supports category filter (all|article|video|course), safe regex search,
//     sort (recent|oldest|most_viewed), and server-side pagination (max 100).
// ─────────────────────────────────────────────────────────────────────────────
const WATCHED_ALLOWED_CATEGORIES = ["all", "article", "video", "course"];
const WATCHED_ALLOWED_SORTS = ["recent", "oldest", "most_viewed"];
const WATCHED_DEFAULT_LIMIT = 50;
const WATCHED_MAX_LIMIT = 100;
const escapeRegexSafe = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

router.get("/profile/watched", userAuth, async (req, res) => {
  try {
    const user = await Users.findById(req.user.userId)
      .select("role learningActivity")
      .lean();

    if (!user || user.role === "admin") {
      return res.status(404).json({
        message: getMsg("accountNotFound", req),
        accountRestricted: true,
      });
    }

    const parsedPage = parseInt(req.query.page, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(req.query.limit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, WATCHED_MAX_LIMIT)
        : WATCHED_DEFAULT_LIMIT;

    const rawCategory = String(req.query.category || "all").trim().toLowerCase();
    const category = WATCHED_ALLOWED_CATEGORIES.includes(rawCategory) ? rawCategory : "all";

    const rawSort = String(req.query.sort || "recent").trim().toLowerCase();
    const sort = WATCHED_ALLOWED_SORTS.includes(rawSort) ? rawSort : "recent";

    const rawSearch = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";

    // Build unified watched map combining recentHistory timestamps/counts with all viewed arrays
    const activity = user.learningActivity || {};
    const watchedMap = new Map();

    const addFromArray = (arr, cat) => {
      if (!Array.isArray(arr)) return;
      for (const id of arr) {
        if (!id) continue;
        const key = String(id);
        if (!watchedMap.has(key)) {
          watchedMap.set(key, {
            itemId: id,
            category: cat,
            lastViewedAt: null,
            viewsCount: 1,
          });
        }
      }
    };

    if (Array.isArray(activity.recentHistory)) {
      for (const entry of activity.recentHistory) {
        if (!entry?.itemId) continue;
        const key = String(entry.itemId);
        watchedMap.set(key, {
          itemId: entry.itemId,
          category: entry.category || "course",
          lastViewedAt: entry.lastViewedAt || null,
          viewsCount: entry.viewsCount || 1,
        });
      }
    }

    addFromArray(activity.viewedArticles, "article");
    addFromArray(activity.viewedVideos, "video");
    addFromArray(activity.viewedCourses, "course");

    const allWatchedEntries = Array.from(watchedMap.values());
    if (allWatchedEntries.length === 0) {
      return res.status(200).json({
        items: [],
        counts: { all: 0, article: 0, video: 0, course: 0 },
        pagination: {
          total: 0,
          page,
          limit,
          totalPages: 1,
          hasNextPage: false,
          hasPrevPage: false,
        },
      });
    }

    // Fetch only published metadata (least-privilege projection — never exposes content/videos)
    const learningDocs = await Learning.find({
      _id: { $in: allWatchedEntries.map((e) => e.itemId) },
      status: "published",
    })
      .select(
        "_id title titleAr description descriptionAr type tag category level levelAr image thumbnail slug hours duration lessons createdAt"
      )
      .lean();

    const docMap = new Map(learningDocs.map((d) => [String(d._id), d]));

    // Hydrate entries that correspond to existing published items
    const hydratedAll = allWatchedEntries
      .map((entry) => {
        const doc = docMap.get(String(entry.itemId));
        if (!doc) return null;
        const deliveryImage =
          doc.thumbnail?.url ||
          (doc.image && !String(doc.image).startsWith("data:") ? doc.image : "");
        return {
          id: String(doc._id),
          slug: doc.slug || "",
          category: entry.category,
          title: doc.title || "",
          titleAr: doc.titleAr || doc.title || "",
          description: doc.description || "",
          descriptionAr: doc.descriptionAr || doc.description || "",
          tag: doc.tag || doc.category || "",
          level: doc.level || "",
          levelAr: doc.levelAr || doc.level || "",
          hours: doc.hours || 0,
          duration: doc.duration || "",
          lessons: doc.lessons || 0,
          image: deliveryImage,
          lastViewedAt: entry.lastViewedAt || doc.createdAt || null,
          viewsCount: entry.viewsCount || 1,
        };
      })
      .filter(Boolean);

    // Accurate counts per category across all published watched items
    const counts = {
      all: hydratedAll.length,
      article: 0,
      video: 0,
      course: 0,
    };
    for (const item of hydratedAll) {
      if (item.category === "article") counts.article += 1;
      else if (item.category === "video") counts.video += 1;
      else counts.course += 1;
    }

    // Filter by category
    let filtered =
      category === "all"
        ? hydratedAll
        : hydratedAll.filter((item) => item.category === category);

    // Safe regex search across bilingual title, description, and tag
    if (rawSearch.length > 0) {
      const searchRegex = new RegExp(escapeRegexSafe(rawSearch), "i");
      filtered = filtered.filter(
        (item) =>
          searchRegex.test(item.title) ||
          searchRegex.test(item.titleAr) ||
          searchRegex.test(item.description) ||
          searchRegex.test(item.descriptionAr) ||
          searchRegex.test(item.tag)
      );
    }

    // Deterministic sorting
    filtered.sort((a, b) => {
      if (sort === "most_viewed") {
        if (b.viewsCount !== a.viewsCount) return b.viewsCount - a.viewsCount;
      }
      const timeA = a.lastViewedAt ? new Date(a.lastViewedAt).getTime() : 0;
      const timeB = b.lastViewedAt ? new Date(b.lastViewedAt).getTime() : 0;
      if (sort === "oldest") return timeA - timeB;
      return timeB - timeA;
    });

    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, totalPages);
    const skip = (safePage - 1) * limit;
    const paginatedItems = filtered.slice(skip, skip + limit);

    return res.status(200).json({
      items: paginatedItems,
      counts,
      pagination: {
        total,
        page: safePage,
        limit,
        totalPages,
        hasNextPage: safePage < totalPages,
        hasPrevPage: safePage > 1,
      },
    });
  } catch (err) {
    console.error("GET /profile/watched error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;
