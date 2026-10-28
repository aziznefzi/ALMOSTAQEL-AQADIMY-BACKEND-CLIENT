import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { AdminFailedAccess } from "../../schema/adminFailedAccess.js";
import { Users } from "../../schema/users.js";
import { BlockedIps } from "../../schema/blockedIps.js";

const logFailedAccess = async (req, reason, extra = {}) => {
    try {
      await AdminFailedAccess.create({
        reason,
        ipAddress: req.ip,
        deviceId: req.headers["x-device-id"],
        userAgent: req.headers["user-agent"],
        path: req.originalUrl,
        method: req.method,
        attemptedEmail: req.body?.email,
        ...extra,
      });
    }catch(logError){
      console.log("Failed to log admin access attempt:", logError.message);
    }
};

// High-performance in-memory cache for verified admin deviceId sessions (5 min TTL)
// Drastically speeds up admin dashboard by avoiding CPU-blocking bcrypt.compare on every single request
const deviceAuthCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

export const AdminAuth = async (req, res, next) => {
    try{
      // Check first: is this IP banned from the Admin section?
      const ipBan = await BlockedIps.findOne({
        ipAddress: req.ip,
        banType: "ip",
        StateBan: { $in: ["baned", "permanent-baned"] },
      });
      if(ipBan){
        return res.status(403).json({message: "Forbidden"});
      }

      const ADMIN_TOKEN = req.headers.authorization;
      const deviceId = req.headers["x-device-id"];

      if(!ADMIN_TOKEN || !deviceId){
        await logFailedAccess(req, "missing-token");
        return res.status(401).json({message: "Unauthorized: Missing token or device ID"});
      }

      // Admin Token Authentication
      const tokenParts = ADMIN_TOKEN.split(" ");
      const Token = tokenParts.length === 2 ? tokenParts[1] : ADMIN_TOKEN;
      if (!Token || Token === "null" || Token === "undefined") {
        await logFailedAccess(req, "missing-token");
        return res.status(401).json({message: "Unauthorized: Invalid token format"});
      }

      let decoded;
      try{
        decoded = jwt.verify(Token, process.env.ADMIN_TOKEN_SECRET);
      }catch(jwtError){
        const reason = jwtError.name === "TokenExpiredError" ? "expired-token" : "forged-token";
        await logFailedAccess(req, reason, { errorMessage: jwtError.message });
        return res.status(401).json({message: "Unauthorized: Token expired or invalid"});
      }

      const email = decoded?.email;
      if(!decoded || decoded.role !== "admin" || !email){
        await logFailedAccess(req, "invalid-claims", { tokenEmail: decoded?.email });
        return res.status(403).json({message: "Forbidden: Not an admin"});
      }

      // If client also passed email in body, ensure it matches the token
      if(req.body?.email && req.body.email !== email){
        await logFailedAccess(req, "invalid-claims", { tokenEmail: email, attemptedEmail: req.body.email });
        return res.status(403).json({message: "Forbidden: Email mismatch"});
      }
      
      // Verify the User Existence in DB
      const user = await Users.findOne({ email });
      if(!user || user.role !== "admin"){
        await logFailedAccess(req, "user-not-found", { attemptedEmail: email });
        return res.status(404).json({message: "Admin user not found"});
      }

      // device Id Authentication with In-Memory Session Cache
      const cacheKey = `${Token}:${deviceId}`;
      const cachedExpiry = deviceAuthCache.get(cacheKey);
      let isDeviceIdValid = false;

      if (cachedExpiry && cachedExpiry > Date.now()) {
        isDeviceIdValid = true;
      } else {
        isDeviceIdValid = await bcrypt.compare(deviceId, user.deviceId);
        if (isDeviceIdValid) {
          deviceAuthCache.set(cacheKey, Date.now() + CACHE_TTL_MS);
          if (deviceAuthCache.size > 500) {
            const now = Date.now();
            for (const [k, exp] of deviceAuthCache.entries()) {
              if (exp <= now) deviceAuthCache.delete(k);
            }
          }
        }
      }

      if(!isDeviceIdValid){
        await logFailedAccess(req, "invalid-device-id", { attemptedEmail: email });
        // Forged deviceId: permanently ban this IP from the Admin section
        await BlockedIps.findOneAndUpdate(
          { ipAddress: req.ip, banType: "ip" },
          {
            $set: {
              StateBan: "permanent-baned",
              resson: "Forged deviceId on admin access",
              banneDate: new Date(),
            },
            $inc: { BannedCount: 1 },
          },
          { upsert: true }
        );
        return res.status(401).json({message: "Unauthorized: Invalid device ID"});
      }

      req.admin = user;
      next();
    }catch(error){
        console.log(error);
        res.status(500).json({message: error.message});
    }
};