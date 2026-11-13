import jwt from "jsonwebtoken";
import { BlockedIps } from "../schema/blockedIps.js";
import { Users } from "../schema/users.js";
import { getMsg } from "../utils/messages.js";

/**
 * User Authentication Middleware for Protected Client Routes
 * Verifies:
 * 1. Valid JWT accessToken (from HTTP-only cookie or Authorization Bearer header)
 * 2. Token type === "user-access"
 * 3. Valid hardware/browser x-device-id header
 * 4. Device / Email / Account not banned in BlockedIps
 * 5. User exists in MongoDB and VerificaionStatus === "verified"
 */
export const userAuth = async (req, res, next) => {
  try {
    // 1. Extract token from Cookie or Authorization header
    let token = req.cookies?.accessToken;
    if (!token && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      token = authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : authHeader;
    }

    if (!token || token === "null" || token === "undefined") {
      return res.status(401).json({
        message: getMsg("tokenMissing", req),
        tokenMissing: true,
        code: "TOKEN_MISSING",
      });
    }

    // 2. Cryptographic verification of JWT signature & expiration
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN);
    } catch (jwtErr) {
      if (jwtErr.name === "TokenExpiredError") {
        return res.status(401).json({
          message: getMsg("tokenInvalid", req),
          tokenExpired: true,
          code: "TOKEN_EXPIRED",
        });
      }
      return res.status(401).json({
        message: getMsg("tokenInvalid", req),
        tokenExpired: false,
        code: "TOKEN_INVALID",
      });
    }

    if (!decoded || decoded.type !== "user-access" || !decoded.userId) {
      return res.status(403).json({ message: getMsg("tokenTypeInvalid", req) });
    }

    // 3. Enforce x-device-id presence & strict device binding
    const incomingDeviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.body?.deviceId ||
      req.query?.deviceId;

    if (!incomingDeviceId) {
      return res.status(403).json({ message: getMsg("deviceIdRequired", req) });
    }

    if (
      decoded.deviceId &&
      String(decoded.deviceId).trim() !== String(incomingDeviceId).trim()
    ) {
      return res.status(403).json({
        message: getMsg("deviceMismatch", req),
        accountRestricted: true,
      });
    }

    // 4. Check Device or User Ban in BlockedIps
    const banRecord = await BlockedIps.findOne({
      $or: [
        { deviceId: incomingDeviceId },
        { userID: decoded.userId },
        ...(decoded.email ? [{ email: decoded.email }] : []),
      ],
      StateBan: { $in: ["baned", "permanent-baned"] },
    });

    if (banRecord) {
      if (
        banRecord.StateBan === "permanent-baned" ||
        banRecord.BannedCount >= 3
      ) {
        return res.status(403).json({
          message: getMsg("accountPermanentBan", req),
          accountRestricted: true,
        });
      }
      if (
        banRecord.banneDate &&
        banRecord.banneDate.getTime() + 10 * 60 * 1000 > Date.now()
      ) {
        return res.status(403).json({
          message: getMsg("accountTempSuspension", req),
          accountRestricted: true,
        });
      }
    }

    // 5. Verify user exists in DB, is not locked/restricted, and is verified
    const userInDb = await Users.findById(decoded.userId).lean();
    if (!userInDb) {
      return res.status(404).json({
        message: getMsg("accountNotFound", req),
        accountRestricted: true,
      });
    }

    if (
      (userInDb.lockUntil && new Date(userInDb.lockUntil) > new Date()) ||
      (userInDb.blockedUntil && new Date(userInDb.blockedUntil) > new Date())
    ) {
      return res.status(403).json({
        message: getMsg("accountTempSuspension", req, userInDb),
        accountRestricted: true,
      });
    }

    if (
      userInDb.VerificaionStatus !== "verified" &&
      userInDb.isVerify !== true
    ) {
      return res.status(403).json({
        message: getMsg("tokenInvalid", req, userInDb),
        accountRestricted: true,
      });
    }

    req.user = decoded;
    req.dbUser = userInDb;
    req.deviceId = incomingDeviceId;
    next();
  } catch (err) {
    console.error("Error in userAuth middleware:", err.message);
    return res.status(401).json({ message: getMsg("tokenInvalid", req) });
  }
};

export default userAuth;

