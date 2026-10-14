import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { Resend } from "resend";
import { Users } from "../../schema/users.js";
import { BlockedIps } from "../../schema/blockedIps.js";
import Sessions from "../../schema/sessions.js";
import { getMsg } from "../../utils/messages.js";
import { getVerificationEmailContent } from "./signup.js";

const router = express.Router();

router.post("/login", async (req, res) => {
  try {
    const { email, password, deviceId, lang } = req.body || {};
    const clientLang = (lang || req.headers['x-lang'] || req.headers['accept-language'] || "en").toLowerCase().includes("ar") ? "ar" : "en";
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    // 1. Validate required fields
    if (!email || !password || !deviceId) {
      return res.status(401).json({ message: getMsg("requiredFields", req) });
    }

    const cleanEmail = email.toLowerCase().trim();

    // 2. Check Device Permanent Ban
    const deviceBan = await BlockedIps.findOne({
      deviceId: deviceId,
      StateBan: "permanent-baned"
    });
    if (deviceBan) {
      return res.status(403).json({ message: getMsg("devicePermanentBan", req) });
    }

    // 3. Check Email Permanent Ban
    const emailBan = await BlockedIps.findOne({
      email: cleanEmail,
      StateBan: "permanent-baned"
    });
    if (emailBan) {
      return res.status(403).json({ message: getMsg("emailPermanentBan", req) });
    }

    // 4. Find user by email or username
    const user = await Users.findOne({
      $or: [
        { email: cleanEmail },
        { username: cleanEmail }
      ]
    });

    if (!user) {
      return res.status(404).json({ message: getMsg("accountNotFound", req) });
    }

    // 5. Check User-specific Ban in BlockedIps
    let blockedIps = await BlockedIps.findOne({
      $or: [
        { userID: user._id },
        { email: user.email },
        { deviceId: deviceId }
      ]
    });

    if (blockedIps) {
      if (blockedIps.StateBan === "permanent-baned" || blockedIps.BannedCount >= 3) {
        blockedIps.StateBan = "permanent-baned";
        blockedIps.banneDate = Date.now();
        await blockedIps.save();
        return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
      }

      if (blockedIps.StateBan === "baned") {
        if (blockedIps.banneDate && (blockedIps.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
        } else {
          blockedIps.StateBan = "not-baned";
          await blockedIps.save();
          user.AttemptsCount = 0;
          user.lockUntil = null;
          await user.save();
        }
      }
    }

    // 6. Check lockUntil (temporary 10-minute lockout)
    if (user.lockUntil && user.lockUntil > new Date()) {
      return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
    }

    // 7. Verify Password
    if (!user.password) {
      return res.status(400).json({
        message: clientLang === "ar"
          ? "تم إنشاء هذا الحساب عبر Google. يرجى تسجيل الدخول باستخدام حساب Google."
          : "This account was registered with Google. Please sign in with Google."
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      let currentAttempts = user.AttemptsCount || 0;
      let newAttemptsCount = currentAttempts + 1;
      user.AttemptsCount = newAttemptsCount;

      // 5 failed attempts -> 10 minutes lock
      if (newAttemptsCount >= 5 && newAttemptsCount < 10) {
        user.lockUntil = new Date(Date.now() + 10 * 60 * 1000);
      }

      // 10 failed attempts -> Trigger BlockedIps ban
      if (newAttemptsCount >= 10) {
        let banRecord = await BlockedIps.findOneAndUpdate(
          { userID: user._id },
          {
            $set: {
              deviceId: deviceId,
              ipAddress: clientIp,
              email: user.email,
              resson: "Maximum number of login attempts reached (temporary ban)",
              banneDate: Date.now()
            },
            $inc: { BannedCount: 1 }
          },
          { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
        );

        if (banRecord.BannedCount >= 3) {
          banRecord.StateBan = "permanent-baned";
          await banRecord.save();
          await user.save();
          return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
        } else {
          banRecord.StateBan = "baned";
          await banRecord.save();
          user.lockUntil = new Date(Date.now() + 10 * 60 * 1000);
          await user.save();
          return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
        }
      }

      await user.save();
      return res.status(401).json({ message: getMsg("invalidCredentials", req, user) });
    }

    // 8. Password matches! Check if account is verified
    if (user.VerificaionStatus !== "verified" && user.isVerify !== true) {
      const AuthCode = crypto.randomInt(100000, 999999);
      user.AuthCode = AuthCode;
      user.VerificaionStatus = "check";
      user.deviceId = deviceId;
      user.ipAddress = clientIp;
      await user.save();

      try {
        const resend = new Resend(process.env.RESEND_API_KEY);
        const emailContent = getVerificationEmailContent({
          type: "welcome",
          lang: clientLang,
          ferstname: user.ferstname,
          lastname: user.lastname,
          username: user.username,
          email: user.email,
          phoneNumber: user.PhoneNumber,
          code: AuthCode
        });

        await resend.emails.send({
          from: 'almostaqel aQademy <contact@almostaqelaqademy.com>',
          to: user.email,
          subject: emailContent.subject,
          html: emailContent.html,
        });
      } catch (emailErr) {
        console.error("Error sending verification email during login:", emailErr.message);
      }

      const verificationToken = jwt.sign(
        {
          userId: user._id,
          email: user.email,
          deviceId: deviceId,
          type: "email-verification"
        },
        process.env.ACCESS_TOKEN,
        { expiresIn: "15m" }
      );

      const isProduction = process.env.NODE_ENV === "production";
      res.cookie("verificationToken", verificationToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 15 * 60 * 1000,
        path: "/"
      });

      return res.status(200).json({
        message: getMsg("signupSuccess", req, user),
        requireVerification: true,
        verificationToken,
        user: {
          id: user._id,
          email: user.email,
          deviceId: deviceId,
          role: user.role,
          ferstname: user.ferstname,
          lastname: user.lastname,
          username: user.username,
          AttemptsCount: user.AttemptsCount,
          phoneNumber: user.PhoneNumber || "",
          VerificaionStatus: user.VerificaionStatus,
          ResendCount: user.ResendCount,
          VerificationCount: user.VerificationCount
        }
      });
    }

    // 9. Account is verified: Reset attempts and unlock
    user.AttemptsCount = 0;
    user.lockUntil = null;
    user.deviceId = deviceId;
    user.ipAddress = clientIp;
    if (user.lang !== clientLang) user.lang = clientLang;
    await user.save();

    // 10. Generate Session & Tokens
    const refreshToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        deviceId: deviceId,
        type: "user-access"
      },
      process.env.REFRESH_TOKEN,
      { expiresIn: "39d" }
    );

    await Sessions.create({
      userID: user._id,
      deviceId: deviceId,
      ipAddress: clientIp,
      refreshToken: refreshToken,
      loginDate: new Date(),
      logoutDate: null
    });

    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        deviceId: deviceId,
        type: "user-access"
      },
      process.env.ACCESS_TOKEN,
      { expiresIn: "7d" }
    );

    const isProduction = process.env.NODE_ENV === "production";

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/"
    });

    res.clearCookie("verificationToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/"
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
        VerificaionStatus: user.VerificaionStatus
      }
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

router.post("/logout", async (req, res) => {
  try {
    const isProduction = process.env.NODE_ENV === "production";

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/"
    });

    res.clearCookie("verificationToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/"
    });

    const token = req.cookies?.accessToken || req.headers?.authorization?.replace("Bearer ", "");
    if (token) {
      try {
        const decoded = jwt.decode(token);
        if (decoded?.userId) {
          await Sessions.updateMany(
            { userID: decoded.userId, logoutDate: null },
            { $set: { logoutDate: new Date() } }
          );
        }
      } catch (err) {
        console.log("Error updating session logout date:", err.message);
      }
    }

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    return res.status(500).json({ message: "Logout failed" });
  }
});

export default router;