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
      return res.status(401).json({ message: getMsg("tokenMissing", req) });
    }

    // 2. Cryptographic verification of JWT signature & expiration
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN);
    } catch (jwtErr) {
      return res.status(401).json({ message: getMsg("tokenInvalid", req) });
    }

    if (!decoded || decoded.type !== "user-access" || !decoded.userId) {
      return res.status(403).json({ message: getMsg("tokenTypeInvalid", req) });
    }

    // 3. Enforce x-device-id presence
    const incomingDeviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.body?.deviceId ||
      req.query?.deviceId;

    if (!incomingDeviceId) {
      return res.status(403).json({ message: getMsg("deviceIdRequired", req) });
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
      if (banRecord.StateBan === "permanent-baned") {
        return res
          .status(403)
          .json({ message: getMsg("accountPermanentBan", req) });
      }
      if (
        banRecord.banneDate &&
        banRecord.banneDate.getTime() + 10 * 60 * 1000 > Date.now()
      ) {
        return res
          .status(403)
          .json({ message: getMsg("accountTempSuspension", req) });
      }
    }

    // 5. Verify user exists in DB and is verified
    const userInDb = await Users.findById(decoded.userId).lean();
    if (!userInDb) {
      return res.status(404).json({ message: getMsg("accountNotFound", req) });
    }

    if (
      userInDb.VerificaionStatus !== "verified" &&
      userInDb.isVerify !== true
    ) {
      return res.status(403).json({ message: getMsg("tokenInvalid", req) });
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

