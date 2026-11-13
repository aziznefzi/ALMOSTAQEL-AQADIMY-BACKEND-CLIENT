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
        { username: cleanEmail },
        { username: email.trim() }
      ]
    });

    if (!user || user.role === "admin") {
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

// ─────────────────────────────────────────────────────────────
// 📱 Get accounts logged in on this specific device
// ─────────────────────────────────────────────────────────────
router.get("/device-accounts", async (req, res) => {
  try {
    const deviceId = req.query.deviceId || req.headers['x-device-id'] || req.headers['device-id'];

    if (!deviceId) {
      return res.status(400).json({ message: getMsg("deviceIdRequired", req), accounts: [] });
    }

    // 1. Check if device is permanently banned
    const deviceBan = await BlockedIps.findOne({
      deviceId: deviceId,
      StateBan: "permanent-baned"
    });
    if (deviceBan) {
      return res.status(403).json({ message: getMsg("devicePermanentBan", req), accounts: [] });
    }

    // 2. Fetch all sessions matching this deviceId
    const sessions = await Sessions.find({ deviceId: deviceId }).sort({ updatedAt: -1, createdAt: -1 });

    if (!sessions || sessions.length === 0) {
      return res.status(200).json({ accounts: [] });
    }

    // 3. Keep latest session per unique user
    const userSessionMap = new Map();
    for (const s of sessions) {
      const uid = String(s.userID);
      if (!userSessionMap.has(uid)) {
        userSessionMap.set(uid, s);
      }
    }

    const accounts = [];

    // 4. Validate each user & verify refreshToken
    for (const [userId, session] of userSessionMap.entries()) {
      const user = await Users.findById(userId);
      if (!user) continue;

      // Skip banned users
      const userBan = await BlockedIps.findOne({
        $or: [
          { userID: user._id },
          { email: user.email }
        ],
        StateBan: "permanent-baned"
      });
      if (userBan) continue;

      // Validate refreshToken
      try {
        jwt.verify(session.refreshToken, process.env.REFRESH_TOKEN);

        accounts.push({
          userId: user._id,
          ferstname: user.ferstname,
          lastname: user.lastname || "",
          username: user.username,
          email: user.email,
          avatar: user.avatar || "",
          lastLogin: session.loginDate || session.createdAt
        });
      } catch (jwtErr) {
        // If refreshToken expired, clean up session from DB
        if (jwtErr.name === "TokenExpiredError") {
          await Sessions.deleteMany({ userID: user._id, deviceId: deviceId });
        }
      }
    }

    return res.status(200).json({ accounts });
  } catch (err) {
    console.error("Get device accounts error:", err);
    return res.status(500).json({ message: getMsg("serverError", req), accounts: [] });
  }
});

// ─────────────────────────────────────────────────────────────
// 🔄 Switch Account with RefreshToken validation from DB & Ban Protection
// ─────────────────────────────────────────────────────────────
router.post("/switch-account", async (req, res) => {
  try {
    const { userId, deviceId, lang, refreshToken: incomingToken } = req.body || {};
    const clientLang = (lang || req.headers['x-lang'] || req.headers['accept-language'] || "en").toLowerCase().includes("ar") ? "ar" : "en";
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    // 1. Validate required fields
    if (!userId || !deviceId) {
      return res.status(401).json({ message: getMsg("requiredFields", req) });
    }

    // 2. Check Device Permanent Ban
    const deviceBan = await BlockedIps.findOne({
      deviceId: deviceId,
      StateBan: "permanent-baned"
    });
    if (deviceBan) {
      return res.status(403).json({ message: getMsg("devicePermanentBan", req) });
    }

    // 3. Check Device Temporary Ban
    const tempDeviceBan = await BlockedIps.findOne({
      deviceId: deviceId,
      StateBan: "baned"
    });
    if (tempDeviceBan && tempDeviceBan.banneDate && (tempDeviceBan.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
      return res.status(403).json({ message: getMsg("accountTempSuspension", req) });
    }

    // 4. Find user by userId
    const user = await Users.findById(userId);
    if (!user) {
      return res.status(404).json({ message: getMsg("accountNotFound", req) });
    }

    // 5. Check User Bans
    const userBan = await BlockedIps.findOne({
      $or: [
        { userID: user._id },
        { email: user.email }
      ]
    });
    if (userBan) {
      if (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3) {
        return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
      }
      if (userBan.StateBan === "baned") {
        if (userBan.banneDate && (userBan.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
        }
      }
    }

    // 6. Check lockUntil (temporary lockout)
    if (user.lockUntil && user.lockUntil > new Date()) {
      return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
    }

    // 7. Check if user is verified
    if (user.VerificaionStatus !== "verified" && user.isVerify !== true) {
      return res.status(403).json({ message: getMsg("alreadyVerified", req, user) });
    }

    // 8. Find session in database for this user and device
    const session = await Sessions.findOne({
      userID: user._id,
      deviceId: deviceId
    }).sort({ updatedAt: -1, createdAt: -1 });

    if (!session || !session.refreshToken) {
      return res.status(401).json({ message: getMsg("tokenInvalid", req, user) });
    }

    // Security check: If request included an incoming refreshToken that doesn't match DB or is forged
    if (incomingToken && incomingToken !== session.refreshToken) {
      console.warn(`SECURITY ALERT: Forged refreshToken payload in request from IP: ${clientIp}, DeviceId: ${deviceId}`);
      await BlockedIps.findOneAndUpdate(
        { deviceId: deviceId, banType: "device" },
        {
          $set: {
            deviceId: deviceId,
            ipAddress: clientIp,
            email: user.email,
            userID: user._id,
            banType: "device",
            resson: "Forged or tampered refreshToken during switch account",
            banneDate: Date.now(),
            StateBan: "permanent-baned"
          },
          $inc: { BannedCount: 1 }
        },
        { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
      );
      return res.status(403).json({ message: getMsg("forgedToken", req) });
    }

    // 9. Cryptographically verify the session's refreshToken from DB
    let decoded;
    try {
      decoded = jwt.verify(session.refreshToken, process.env.REFRESH_TOKEN);
    } catch (jwtErr) {
      if (jwtErr.name === "TokenExpiredError") {
        // Expired token -> remove session
        await Sessions.deleteMany({ userID: user._id, deviceId: deviceId });
        return res.status(401).json({
          message: getMsg("sessionExpired", req, user),
          sessionExpired: true
        });
      }

      // Corrupted / tampered refreshToken in DB session
      console.warn(`SECURITY ALERT: Invalid refreshToken in session for user: ${user._id}`);
      await Sessions.deleteMany({ userID: user._id, deviceId: deviceId });
      return res.status(401).json({ message: getMsg("tokenInvalid", req, user) });
    }

    // 10. Verify token claims match user and device
    if (
      String(decoded.userId) !== String(user._id) ||
      String(decoded.deviceId) !== String(deviceId) ||
      decoded.type !== "user-access"
    ) {
      console.warn(`SECURITY ALERT: Token claims mismatch during switch account from IP: ${clientIp}`);
      await Sessions.deleteMany({ userID: user._id, deviceId: deviceId });
      return res.status(403).json({ message: getMsg("tokenUserMismatch", req, user) });
    }

    // 11. Reset attempts, update user and session
    user.AttemptsCount = 0;
    user.lockUntil = null;
    user.deviceId = deviceId;
    user.ipAddress = clientIp;
    if (user.lang !== clientLang) user.lang = clientLang;
    await user.save();

    session.loginDate = new Date();
    session.logoutDate = null;
    session.ipAddress = clientIp;
    await session.save();

    // 12. Generate fresh accessToken
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
      message: getMsg("switchAccountSuccess", req, user) || getMsg("loginSuccess", req, user),
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
    console.error("Switch account error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────
// 🔐 Automatic Access Token Renewal using Refresh Token
// Verifies account restrictions, bans, device binding, and DB refreshToken
// ─────────────────────────────────────────────────────────────
router.post("/refresh-token", async (req, res) => {
  const isProduction = process.env.NODE_ENV === "production";
  const clearAccessCookie = () => {
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      path: "/",
    });
  };

  try {
    const incomingDeviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.body?.deviceId ||
      req.query?.deviceId;
    const clientIp =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress;
    const clientLang = (
      req.body?.lang ||
      req.headers["x-lang"] ||
      req.headers["accept-language"] ||
      "en"
    )
      .toLowerCase()
      .includes("ar")
      ? "ar"
      : "en";

    // 1. Enforce strict Device ID presence
    if (!incomingDeviceId) {
      return res.status(403).json({
        message: getMsg("deviceIdRequired", req),
        accountRestricted: true,
      });
    }
    const cleanDeviceId = String(incomingDeviceId).trim();

    // 2. Pre-check Device Ban in BlockedIps (Permanent or Active Temporary Ban)
    const deviceBanRecord = await BlockedIps.findOne({
      deviceId: cleanDeviceId,
      StateBan: { $in: ["baned", "permanent-baned"] },
    });

    if (deviceBanRecord) {
      if (
        deviceBanRecord.StateBan === "permanent-baned" ||
        deviceBanRecord.BannedCount >= 3
      ) {
        clearAccessCookie();
        return res.status(403).json({
          message: getMsg("devicePermanentBan", req),
          accountRestricted: true,
        });
      }
      if (
        deviceBanRecord.banneDate &&
        deviceBanRecord.banneDate.getTime() + 10 * 60 * 1000 > Date.now()
      ) {
        return res.status(403).json({
          message: getMsg("accountTempSuspension", req),
          accountRestricted: true,
        });
      }
    }

    // 3. Extract expired accessToken (from Cookie, Authorization header, or Body) & verify signature
    let rawAccessToken = req.cookies?.accessToken;
    if (!rawAccessToken && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      rawAccessToken = authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : authHeader;
    }
    if (!rawAccessToken && req.body?.accessToken) {
      rawAccessToken = req.body.accessToken;
    }

    let decodedAccess = null;
    if (
      rawAccessToken &&
      rawAccessToken !== "null" &&
      rawAccessToken !== "undefined"
    ) {
      try {
        // Verify cryptographic signature while ignoring expiration
        decodedAccess = jwt.verify(rawAccessToken, process.env.ACCESS_TOKEN, {
          ignoreExpiration: true,
        });
      } catch (sigErr) {
        console.warn(
          `SECURITY ALERT: Invalid/tampered accessToken signature during refresh from IP: ${clientIp}, DeviceId: ${cleanDeviceId}`
        );
        clearAccessCookie();
        return res.status(401).json({
          message: getMsg("tokenInvalid", req),
          sessionExpired: true,
        });
      }

      if (decodedAccess.type !== "user-access" || !decodedAccess.userId) {
        clearAccessCookie();
        return res.status(403).json({
          message: getMsg("tokenTypeInvalid", req),
          accountRestricted: true,
        });
      }

      if (
        decodedAccess.deviceId &&
        String(decodedAccess.deviceId).trim() !== cleanDeviceId
      ) {
        console.warn(
          `SECURITY ALERT: Device mismatch on accessToken refresh from IP: ${clientIp}`
        );
        clearAccessCookie();
        return res.status(403).json({
          message: getMsg("deviceMismatch", req),
          accountRestricted: true,
        });
      }
    }

    // 4. Resolve and validate target userId
    const bodyUserId = req.body?.userId;
    if (
      decodedAccess?.userId &&
      bodyUserId &&
      String(decodedAccess.userId) !== String(bodyUserId)
    ) {
      clearAccessCookie();
      return res.status(403).json({
        message: getMsg("tokenUserMismatch", req),
        accountRestricted: true,
      });
    }

    const targetUserId = decodedAccess?.userId || bodyUserId;
    if (!targetUserId) {
      clearAccessCookie();
      return res.status(401).json({
        message: getMsg("tokenMissing", req),
        sessionExpired: true,
      });
    }

    // 5. Fetch user and verify account exists & is not restricted/locked/unverified
    const user = await Users.findById(targetUserId);
    if (!user || user.role === "admin") {
      await Sessions.deleteMany({ userID: targetUserId, deviceId: cleanDeviceId });
      clearAccessCookie();
      return res.status(404).json({
        message: getMsg("accountNotFound", req),
        accountRestricted: true,
      });
    }

    // 6. Check User & Email Ban in BlockedIps
    const userBan = await BlockedIps.findOne({
      $or: [
        { userID: user._id },
        { email: user.email },
        { deviceId: cleanDeviceId },
      ],
    });

    if (userBan) {
      if (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3) {
        if (userBan.StateBan !== "permanent-baned") {
          userBan.StateBan = "permanent-baned";
          userBan.banneDate = new Date();
          await userBan.save();
        }
        await Sessions.deleteMany({ userID: user._id, deviceId: cleanDeviceId });
        clearAccessCookie();
        return res.status(403).json({
          message: getMsg("accountPermanentBan", req, user),
          accountRestricted: true,
        });
      }

      if (userBan.StateBan === "baned") {
        if (
          userBan.banneDate &&
          userBan.banneDate.getTime() + 10 * 60 * 1000 > Date.now()
        ) {
          return res.status(403).json({
            message: getMsg("accountTempSuspension", req, user),
            accountRestricted: true,
          });
        } else {
          userBan.StateBan = "not-baned";
          await userBan.save();
          user.AttemptsCount = 0;
          user.lockUntil = null;
          await user.save();
        }
      }
    }

    // 7. Check temporary account lockouts (lockUntil / blockedUntil)
    if (
      (user.lockUntil && new Date(user.lockUntil) > new Date()) ||
      (user.blockedUntil && new Date(user.blockedUntil) > new Date())
    ) {
      return res.status(403).json({
        message: getMsg("accountTempSuspension", req, user),
        accountRestricted: true,
      });
    }

    // 8. Verify account verification status
    if (user.VerificaionStatus !== "verified" && user.isVerify !== true) {
      clearAccessCookie();
      return res.status(403).json({
        message: getMsg("tokenInvalid", req, user),
        accountRestricted: true,
      });
    }

    // 9. Locate active session in DB for this user and device (must not be logged out)
    const session = await Sessions.findOne({
      userID: user._id,
      deviceId: cleanDeviceId,
      logoutDate: null,
    }).sort({ updatedAt: -1, createdAt: -1 });

    if (!session || !session.refreshToken) {
      clearAccessCookie();
      return res.status(401).json({
        message: getMsg("sessionExpired", req, user),
        sessionExpired: true,
      });
    }

    // 10. Detect tampered/forged incoming refreshToken if provided in body
    const incomingRefreshToken = req.body?.refreshToken;
    if (
      incomingRefreshToken &&
      incomingRefreshToken !== session.refreshToken
    ) {
      console.warn(
        `SECURITY ALERT: Forged refreshToken in /refresh-token from IP: ${clientIp}, DeviceId: ${cleanDeviceId}`
      );
      await BlockedIps.findOneAndUpdate(
        { deviceId: cleanDeviceId, banType: "device" },
        {
          $set: {
            deviceId: cleanDeviceId,
            ipAddress: clientIp,
            email: user.email,
            userID: user._id,
            banType: "device",
            resson: "Forged or tampered refreshToken during token refresh",
            banneDate: new Date(),
            StateBan: "permanent-baned",
          },
          $inc: { BannedCount: 1 },
        },
        { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
      );
      await Sessions.deleteMany({ userID: user._id, deviceId: cleanDeviceId });
      clearAccessCookie();
      return res.status(403).json({
        message: getMsg("forgedToken", req, user),
        accountRestricted: true,
      });
    }

    // 11. Cryptographically verify the session's refreshToken
    let decodedRefresh;
    try {
      decodedRefresh = jwt.verify(
        session.refreshToken,
        process.env.REFRESH_TOKEN
      );
    } catch (refreshErr) {
      await Sessions.deleteMany({ userID: user._id, deviceId: cleanDeviceId });
      clearAccessCookie();

      if (refreshErr.name === "TokenExpiredError") {
        return res.status(401).json({
          message: getMsg("sessionExpired", req, user),
          sessionExpired: true,
        });
      }

      console.warn(
        `SECURITY ALERT: Corrupted refreshToken in session for user: ${user._id}`
      );
      return res.status(401).json({
        message: getMsg("tokenInvalid", req, user),
        sessionExpired: true,
      });
    }

    // 12. Verify refreshToken claims strictly match user, email, role, and deviceId
    if (
      !decodedRefresh ||
      String(decodedRefresh.userId) !== String(user._id) ||
      String(decodedRefresh.deviceId).trim() !== cleanDeviceId ||
      decodedRefresh.type !== "user-access" ||
      (decodedRefresh.email &&
        String(decodedRefresh.email).toLowerCase().trim() !==
          String(user.email).toLowerCase().trim())
    ) {
      console.warn(
        `SECURITY ALERT: RefreshToken claims mismatch for user ${user._id} from IP: ${clientIp}`
      );
      await Sessions.deleteMany({ userID: user._id, deviceId: cleanDeviceId });
      clearAccessCookie();
      return res.status(403).json({
        message: getMsg("tokenUserMismatch", req, user),
        accountRestricted: true,
      });
    }

    // 13. All security & restriction checks passed! Update session & user metadata
    session.ipAddress = clientIp;
    session.loginDate = new Date();
    session.logoutDate = null;
    await session.save();

    if (user.lang !== clientLang) {
      user.lang = clientLang;
      await user.save();
    }

    // 14. Issue new accessToken
    const newAccessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        deviceId: cleanDeviceId,
        type: "user-access",
      },
      process.env.ACCESS_TOKEN,
      { expiresIn: "7d" }
    );

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      message: getMsg("tokenRefreshedSuccess", req, user),
      refreshed: true,
      accessToken: newAccessToken,
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
    console.error("Refresh token error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ─────────────────────────────────────────────────────────────
// 🗑️ Remove account from this device's sessions
// ─────────────────────────────────────────────────────────────
router.post("/remove-device-account", async (req, res) => {
  try {
    const { userId, deviceId } = req.body || {};

    if (!userId || !deviceId) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    await Sessions.deleteMany({ userID: userId, deviceId: deviceId });

    return res.status(200).json({ message: getMsg("accountRemovedSuccess", req) });
  } catch (err) {
    console.error("Remove device account error:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;