import express from "express";
import { OAuth2Client } from "google-auth-library";
import axios from "axios";
import jwt from "jsonwebtoken";
import { Users } from "../../schema/users.js";
import { BlockedIps } from "../../schema/blockedIps.js";
import Sessions from "../../schema/sessions.js";
import { getMsg } from "../../utils/messages.js";

const router = express.Router();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post("/google", async (req, res) => {
  try {
    const { credential, accessToken: googleToken, deviceId, lang } = req.body || {};

    if (!credential && !googleToken) {
      return res.status(400).json({ message: getMsg("requiredFields", req) });
    }

    let googleUser = null;

    try {
      if (credential) {
        // Verify Google ID Token (JWT)
        const ticket = await client.verifyIdToken({
          idToken: credential,
          audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        if (!payload) {
          return res.status(401).json({ message: getMsg("invalidGoogleToken", req) });
        }
        googleUser = {
          sub: payload.sub,
          email: payload.email,
          email_verified: payload.email_verified,
          name: payload.name,
          given_name: payload.given_name,
          family_name: payload.family_name,
          picture: payload.picture
        };
      } else if (googleToken) {
        // Verify and fetch profile using Access Token
        const response = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
          headers: { Authorization: `Bearer ${googleToken}` },
          timeout: 10000
        });
        googleUser = response.data;
      }
    } catch (googleApiErr) {
      console.error("Google API verification error:", googleApiErr);
      const errMsg = (googleApiErr.message || "").toLowerCase();
      const isNetworkErr = 
        googleApiErr.code === 'ENOTFOUND' ||
        googleApiErr.code === 'ETIMEDOUT' ||
        googleApiErr.code === 'ECONNRESET' ||
        googleApiErr.code === 'ECONNREFUSED' ||
        googleApiErr.code === 'ENETUNREACH' ||
        googleApiErr.code === 'EAI_AGAIN' ||
        googleApiErr.code === 'ERR_NETWORK' ||
        errMsg.includes('enotfound') ||
        errMsg.includes('network') ||
        errMsg.includes('timeout') ||
        errMsg.includes('fetch failed');

      if (isNetworkErr) {
        return res.status(503).json({ message: getMsg("networkConnectionError", req) });
      }

      if (googleApiErr.response?.status === 401 || errMsg.includes("invalid token") || errMsg.includes("token used too late") || errMsg.includes("wrong number of segments")) {
        return res.status(401).json({ message: getMsg("invalidGoogleToken", req) });
      }

      return res.status(400).json({ message: getMsg("googleAuthFailed", req) });
    }

    if (!googleUser || !googleUser.email) {
      return res.status(400).json({ message: getMsg("googleAuthFailed", req) });
    }

    if (googleUser.email_verified === false) {
      return res.status(400).json({ message: "Google email is not verified." });
    }

    const userEmail = googleUser.email.toLowerCase().trim();
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    // Check if user or device is banned
    const userBan = await BlockedIps.findOne({
      $or: [
        { email: userEmail },
        ...(deviceId ? [{ deviceId }] : [])
      ]
    });

    if (userBan) {
      if (userBan.StateBan === "permanent-baned" || userBan.BannedCount >= 3) {
        return res.status(403).json({ message: getMsg("accountPermanentBan", req) });
      }
      if (userBan.StateBan === "baned") {
        if (userBan.banneDate && (userBan.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req) });
        } else {
          userBan.StateBan = "not-baned";
          await userBan.save();
        }
      }
    }

    const targetLang = (lang || req.headers['x-lang'] || req.headers['accept-language'] || "en").toLowerCase().includes("ar") ? "ar" : "en";

    // Find or create user
    let user = await Users.findOne({
      $or: [
        { email: userEmail },
        { googleId: googleUser.sub }
      ]
    });

    if (user) {
      if (!user.googleId) {
        user.googleId = googleUser.sub;
      }
      if (!user.avatar && googleUser.picture) {
        user.avatar = googleUser.picture;
      }
      user.isVerify = true;
      user.VerificaionStatus = "verified";
      user.authProvider = user.authProvider || "google";
      if (deviceId) user.deviceId = deviceId;
      user.ipAddress = clientIp;
      await user.save();
    } else {
      let baseUsername = (googleUser.name || googleUser.given_name || userEmail.split('@')[0])
        .replace(/[^\w\s\u0600-\u06FF]/gi, '')
        .trim()
        .replace(/\s+/g, '_')
        .slice(0, 15);

      if (!baseUsername || baseUsername.length < 2) {
        baseUsername = "user_" + Math.floor(1000 + Math.random() * 9000);
      }

      let username = baseUsername;
      let counter = 1;
      while (await Users.findOne({ username })) {
        username = `${baseUsername.slice(0, 10)}_${Math.floor(100 + Math.random() * 900)}`;
        counter++;
        if (counter > 10) break;
      }

      const ferstname = (googleUser.given_name || googleUser.name?.split(' ')[0] || "User").slice(0, 30);
      const lastname = (googleUser.family_name || googleUser.name?.split(' ').slice(1).join(' ') || "").slice(0, 30);

      user = await Users.create({
        ferstname,
        lastname,
        username,
        email: userEmail,
        googleId: googleUser.sub,
        avatar: googleUser.picture || "",
        authProvider: "google",
        isVerify: true,
        VerificaionStatus: "verified",
        role: "user",
        deviceId: deviceId || "",
        ipAddress: clientIp,
        lang: targetLang
      });
    }

    // Generate tokens & session
    const refreshToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        deviceId: deviceId || user.deviceId,
        type: "user-access"
      },
      process.env.REFRESH_TOKEN,
      { expiresIn: "39d" }
    );

    await Sessions.create({
      userID: user._id,
      deviceId: deviceId || user.deviceId || "unknown",
      ipAddress: clientIp,
      refreshToken,
      loginDate: new Date(),
      logoutDate: null
    });

    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role,
        deviceId: deviceId || user.deviceId,
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
      message: getMsg("verifySuccess", req, user),
      accessToken,
      user: {
        id: user._id,
        role: user.role,
        ferstname: user.ferstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        avatar: user.avatar || googleUser.picture || "",
        authProvider: user.authProvider || "google",
        phoneNumber: user.PhoneNumber || "",
        VerificaionStatus: user.VerificaionStatus
      }
    });

  } catch (err) {
    console.error("Error in Google Auth:", err);
    const errMsg = (err.message || "").toLowerCase();
    const isNetworkErr = 
      err.code === 'ENOTFOUND' ||
      err.code === 'ETIMEDOUT' ||
      err.code === 'ECONNRESET' ||
      err.code === 'ECONNREFUSED' ||
      err.code === 'ENETUNREACH' ||
      err.code === 'EAI_AGAIN' ||
      err.code === 'ERR_NETWORK' ||
      err.name === 'MongooseServerSelectionError' ||
      errMsg.includes('enotfound') ||
      errMsg.includes('network') ||
      errMsg.includes('timeout');

    if (isNetworkErr) {
      return res.status(503).json({ message: getMsg("networkConnectionError", req) });
    }
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;
