import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Resend } from "resend";
import { Users } from "../../schema/users.js";
import { BlockedIps } from "../../schema/blockedIps.js";
import Sessions from "../../schema/sessions.js";
import { getMsg, getLang } from "../../utils/messages.js";
import { verifyCaptchaToken } from "../../jobs/verifyCapchaToken.js";

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// 📧 STEP 1 — Request forgot password (sends OTP + CAPTCHA check)
// ─────────────────────────────────────────────────────────────
router.post("/forgot-password/request", async (req, res) => {
  try {
    const { email, captchaToken, deviceId, lang } = req.body || {};
    const clientLang = getLang(req);
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    // 1. Validate required fields
    if (!email || !captchaToken || !deviceId) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    const cleanEmail = email.toLowerCase().trim();

    // 2. Check Device Permanent Ban
    const deviceBan = await BlockedIps.findOne({
      deviceId,
      StateBan: "permanent-baned",
    });
    if (deviceBan) {
      return res.status(403).json({ message: getMsg("devicePermanentBan", req) });
    }

    // 3. Check Email Permanent Ban
    const emailBan = await BlockedIps.findOne({
      email: cleanEmail,
      StateBan: "permanent-baned",
    });
    if (emailBan) {
      return res.status(403).json({ message: getMsg("emailPermanentBan", req) });
    }

    // 4. ✅ Verify CAPTCHA on backend — permanent ban if forged
    const isHuman = await verifyCaptchaToken(captchaToken);
    if (!isHuman) {
      const banOps = [];

      if (deviceId) {
        banOps.push(
          BlockedIps.findOneAndUpdate(
            { deviceId, banType: "device" },
            {
              $set: {
                deviceId,
                email: cleanEmail,
                ipAddress: clientIp,
                banType: "device",
                resson: "Forged Captcha Token during Forgot Password — Device permanent ban",
                banneDate: Date.now(),
                StateBan: "permanent-baned",
              },
            },
            { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
          )
        );
      }

      if (cleanEmail) {
        banOps.push(
          BlockedIps.findOneAndUpdate(
            { email: cleanEmail, banType: "email" },
            {
              $set: {
                email: cleanEmail,
                deviceId,
                ipAddress: clientIp,
                banType: "email",
                resson: "Forged Captcha Token during Forgot Password — Email permanent ban",
                banneDate: Date.now(),
                StateBan: "permanent-baned",
              },
            },
            { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
          )
        );
      }

      await Promise.all(banOps);
      console.warn(`⚠️ SECURITY: Forged CAPTCHA in forgot-password from IP: ${clientIp}, Device: ${deviceId}, Email: ${cleanEmail}`);
      return res.status(403).json({ message: getMsg("forgedCaptcha", req) });
    }

    // 5. Find user by email
    const user = await Users.findOne({ email: cleanEmail });

    // We always return 200 even if user not found (to prevent email enumeration)
    if (!user) {
      return res.status(200).json({
        message: clientLang === "ar"
          ? "إذا كان البريد الإلكتروني مسجلاً، سيتم إرسال رمز التحقق إليه."
          : "If this email is registered, a verification code will be sent to it.",
        sent: true,
      });
    }

    // 6. Check if user is banned
    const userBan = await BlockedIps.findOne({
      $or: [{ userID: user._id }, { email: user.email }, { deviceId }],
    });
    if (userBan) {
      if (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3) {
        return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
      }
      if (userBan.StateBan === "baned") {
        const isStillLocked =
          userBan.banneDate && userBan.banneDate.getTime() + 10 * 60 * 1000 > Date.now();
        if (isStillLocked) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
        }
      }
    }

    // 7. Rate-limit forgot-password requests per user (5 per 5 min)
    const now = Date.now();
    const windowMs = 5 * 60 * 1000;
    if (!user.forgotPasswordRequests) user.forgotPasswordRequests = [];
    user.forgotPasswordRequests = user.forgotPasswordRequests.filter(
      (ts) => now - new Date(ts).getTime() < windowMs
    );

    if (user.forgotPasswordRequests.length >= 5) {
      return res.status(429).json({
        message: clientLang === "ar"
          ? "لقد تجاوزت الحد المسموح به. يرجى الانتظار 5 دقائق قبل المحاولة مرة أخرى."
          : "Too many requests. Please wait 5 minutes before trying again.",
        retryAfter: 300,
      });
    }

    // 8. Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999);
    user.AuthCode = otp;
    user.forgotPasswordRequests = [...user.forgotPasswordRequests, new Date()];
    await user.save();

    // 9. Send email with OTP
    try {
      const resend = new Resend(process.env.RESEND_API_KEY);
      const isAr = clientLang === "ar";
      const fullName = `${user.ferstname || ""} ${user.lastname || ""}`.trim();

      const subject = isAr
        ? "رمز استعادة كلمة المرور — أكاديمية المستقبل"
        : "Password Recovery Code — ALMOSTAEL AQADIMY";

      const html = isAr
        ? `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head><meta charset="UTF-8">
<style>
  body{font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:40px 20px;direction:rtl}
  .container{max-width:600px;margin:0 auto;background:#13111c;border:1px solid #1f1b2e;border-radius:16px;overflow:hidden}
  .header{background:linear-gradient(to right,#9333ea,#ec4899);padding:30px 20px;text-align:center}
  .header h1{margin:0;color:#fff;font-size:24px}
  .content{padding:40px 30px;text-align:right}
  .greeting{font-size:20px;font-weight:600;margin-bottom:16px}
  .message{color:#cbd5e1;line-height:1.8;margin-bottom:24px;font-size:15px}
  .code-box{background:#07070f;border:1px solid #1f1b2e;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px}
  .code-title{color:#94a3b8;font-size:13px;letter-spacing:1px}
  .code{font-size:36px;font-weight:700;color:#c084fc;letter-spacing:8px;direction:ltr;display:inline-block}
  .footer{text-align:center;padding:20px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e}
</style></head>
<body><div class="container">
<div class="header"><h1>أكاديمية المستقبل</h1></div>
<div class="content">
  <div class="greeting">مرحباً ${fullName || user.username}،</div>
  <div class="message">تلقينا طلباً لاستعادة كلمة مرور حسابك. استخدم الرمز أدناه لاستعادة الوصول.</div>
  <div class="code-box">
    <p class="code-title">رمز الاستعادة</p>
    <p class="code">${otp}</p>
  </div>
  <p style="color:#94a3b8;font-size:13px">هذا الرمز صالح لمدة 3 دقائق. إذا لم تطلب هذا، تجاهل الرسالة.</p>
</div>
<div class="footer">© ${new Date().getFullYear()} أكاديمية المستقبل. جميع الحقوق محفوظة.</div>
</div></body></html>`
        : `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<style>
  body{font-family:'Segoe UI',sans-serif;background:#07070f;color:#f0efff;margin:0;padding:40px 20px}
  .container{max-width:600px;margin:0 auto;background:#13111c;border:1px solid #1f1b2e;border-radius:16px;overflow:hidden}
  .header{background:linear-gradient(to right,#9333ea,#ec4899);padding:30px 20px;text-align:center}
  .header h1{margin:0;color:#fff;font-size:24px}
  .content{padding:40px 30px}
  .greeting{font-size:20px;font-weight:600;margin-bottom:16px}
  .message{color:#cbd5e1;line-height:1.8;margin-bottom:24px}
  .code-box{background:#07070f;border:1px solid #1f1b2e;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px}
  .code-title{color:#64748b;font-size:13px;text-transform:uppercase}
  .code{font-size:36px;font-weight:700;color:#a855f7;letter-spacing:8px}
  .footer{text-align:center;padding:20px;color:#64748b;font-size:12px;border-top:1px solid #1f1b2e}
</style></head>
<body><div class="container">
<div class="header"><h1>ALMOSTAEL AQADIMY</h1></div>
<div class="content">
  <div class="greeting">Hello ${fullName || user.username},</div>
  <div class="message">We received a request to recover access to your account. Use the code below to regain access.</div>
  <div class="code-box">
    <p class="code-title">Recovery Code</p>
    <p class="code">${otp}</p>
  </div>
  <p style="color:#94a3b8;font-size:13px">This code is valid for 3 minutes. If you did not request this, please ignore this email.</p>
</div>
<div class="footer">© ${new Date().getFullYear()} ALMOSTAEL AQADIMY. All rights reserved.</div>
</div></body></html>`;

      await resend.emails.send({
        from: "almostaqel aQademy <contact@almostaqelaqademy.com>",
        to: user.email,
        subject,
        html,
      });
    } catch (emailErr) {
      console.error("Error sending forgot-password email:", emailErr.message);
      return res.status(500).json({
        message: clientLang === "ar"
          ? "حدث خطأ أثناء إرسال البريد الإلكتروني، يرجى المحاولة مرة أخرى."
          : "Error sending email. Please try again.",
      });
    }

    // 10. Issue a short-lived forgotPasswordToken cookie
    const fpToken = jwt.sign(
      { userId: user._id, email: user.email, deviceId, type: "forgot-password" },
      process.env.ACCESS_TOKEN,
      { expiresIn: "3m" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("forgotPasswordToken", fpToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 3 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      sent: true,
      email: user.email,
      message: clientLang === "ar"
        ? "تم إرسال رمز التحقق إلى بريدك الإلكتروني."
        : "Verification code sent to your email.",
    });
  } catch (err) {
    console.error("Forgot password request error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────
// 🔑 STEP 2a — Verify OTP and LOGIN DIRECTLY (without password)
// ─────────────────────────────────────────────────────────────
router.post("/forgot-password/verify-login", async (req, res) => {
  try {
    const { code, deviceId, lang } = req.body || {};
    const clientLang = getLang(req);
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    if (!code || !deviceId) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    // 1. Verify the forgotPasswordToken cookie
    const fpToken = req.cookies?.forgotPasswordToken;
    if (!fpToken) {
      return res.status(401).json({
        message: clientLang === "ar"
          ? "رمز الجلسة منتهي الصلاحية، يرجى البدء من جديد."
          : "Session expired. Please start over.",
        expired: true,
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(fpToken, process.env.ACCESS_TOKEN);
    } catch (jwtErr) {
      return res.status(401).json({
        message: clientLang === "ar"
          ? "انتهت صلاحية الجلسة، يرجى البدء من جديد."
          : "Session expired. Please start over.",
        expired: true,
      });
    }

    if (decoded.type !== "forgot-password" || String(decoded.deviceId) !== String(deviceId)) {
      return res.status(403).json({ message: getMsg("tokenUserMismatch", req) });
    }

    const user = await Users.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: getMsg("accountNotFound", req) });

    // 2. Check ban status
    const userBan = await BlockedIps.findOne({
      $or: [{ userID: user._id }, { email: user.email }, { deviceId }],
    });
    if (userBan && (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3)) {
      return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
    }

    // 3. Validate OTP
    if (String(code).trim() !== String(user.AuthCode).trim()) {
      return res.status(401).json({ message: getMsg("codeIncorrect", req, user) });
    }

    // 4. Clear OTP, update user
    user.AuthCode = null;
    user.AttemptsCount = 0;
    user.lockUntil = null;
    user.deviceId = deviceId;
    user.ipAddress = clientIp;
    if (user.VerificaionStatus !== "verified") {
      user.VerificaionStatus = "verified";
      user.isVerify = true;
    }
    await user.save();

    // 5. Generate session tokens
    const refreshToken = jwt.sign(
      { userId: user._id, email: user.email, role: user.role, deviceId, type: "user-access" },
      process.env.REFRESH_TOKEN,
      { expiresIn: "39d" }
    );

    await Sessions.create({
      userID: user._id,
      deviceId,
      ipAddress: clientIp,
      refreshToken,
      loginDate: new Date(),
      logoutDate: null,
    });

    const accessToken = jwt.sign(
      { userId: user._id, email: user.email, role: user.role, deviceId, type: "user-access" },
      process.env.ACCESS_TOKEN,
      { expiresIn: "7d" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.clearCookie("forgotPasswordToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/",
    });

    return res.status(200).json({
      message: getMsg("loginSuccess", req, user),
      accessToken,
      user: {
        id: user._id,
        role: user.role,
        ferstname: user.ferstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        avatar: user.avatar || "",
        phoneNumber: user.PhoneNumber || "",
        VerificaionStatus: user.VerificaionStatus,
      },
    });
  } catch (err) {
    console.error("Forgot password verify-login error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────
// 🔒 STEP 2b — Verify OTP then RESET PASSWORD
// ─────────────────────────────────────────────────────────────
router.post("/forgot-password/reset-password", async (req, res) => {
  try {
    const { code, newPassword, deviceId, lang } = req.body || {};
    const clientLang = getLang(req);
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    if (!code || !newPassword || !deviceId) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumber = /\d/.test(newPassword);
    const hasSymbol = /[^A-Za-z0-9]/.test(newPassword);
    const isLongEnough = typeof newPassword === "string" && newPassword.length >= 8;

    if (!isLongEnough || !hasUpperCase || !hasLowerCase || !hasNumber || !hasSymbol) {
      return res.status(400).json({ message: getMsg("passwordComplexity", req) });
    }

    // 1. Verify the forgotPasswordToken cookie
    const fpToken = req.cookies?.forgotPasswordToken;
    if (!fpToken) {
      return res.status(401).json({
        message: clientLang === "ar"
          ? "رمز الجلسة منتهي الصلاحية، يرجى البدء من جديد."
          : "Session expired. Please start over.",
        expired: true,
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(fpToken, process.env.ACCESS_TOKEN);
    } catch (jwtErr) {
      return res.status(401).json({
        message: clientLang === "ar"
          ? "انتهت صلاحية الجلسة، يرجى البدء من جديد."
          : "Session expired. Please start over.",
        expired: true,
      });
    }

    if (decoded.type !== "forgot-password" || String(decoded.deviceId) !== String(deviceId)) {
      return res.status(403).json({ message: getMsg("tokenUserMismatch", req) });
    }

    const user = await Users.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: getMsg("accountNotFound", req) });

    // 2. Check ban status
    const userBan = await BlockedIps.findOne({
      $or: [{ userID: user._id }, { email: user.email }, { deviceId }],
    });
    if (userBan && (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3)) {
      return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
    }

    // 3. Validate OTP
    if (String(code).trim() !== String(user.AuthCode).trim()) {
      return res.status(401).json({ message: getMsg("codeIncorrect", req, user) });
    }

    // 4. Hash new password and update user
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.AuthCode = null;
    user.AttemptsCount = 0;
    user.lockUntil = null;
    user.deviceId = deviceId;
    user.ipAddress = clientIp;
    if (user.VerificaionStatus !== "verified") {
      user.VerificaionStatus = "verified";
      user.isVerify = true;
    }
    await user.save();

    // 5. Invalidate all existing sessions (security: password changed)
    await Sessions.deleteMany({ userID: user._id });

    // 6. Create new session + tokens
    const refreshToken = jwt.sign(
      { userId: user._id, email: user.email, role: user.role, deviceId, type: "user-access" },
      process.env.REFRESH_TOKEN,
      { expiresIn: "39d" }
    );

    await Sessions.create({
      userID: user._id,
      deviceId,
      ipAddress: clientIp,
      refreshToken,
      loginDate: new Date(),
      logoutDate: null,
    });

    const accessToken = jwt.sign(
      { userId: user._id, email: user.email, role: user.role, deviceId, type: "user-access" },
      process.env.ACCESS_TOKEN,
      { expiresIn: "7d" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.clearCookie("forgotPasswordToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/",
    });

    return res.status(200).json({
      message: clientLang === "ar"
        ? "تم تغيير كلمة المرور بنجاح وتسجيل دخولك."
        : "Password changed successfully and you are now signed in.",
      accessToken,
      user: {
        id: user._id,
        role: user.role,
        ferstname: user.ferstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        avatar: user.avatar || "",
        phoneNumber: user.PhoneNumber || "",
        VerificaionStatus: user.VerificaionStatus,
      },
    });
  } catch (err) {
    console.error("Forgot password reset error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;
