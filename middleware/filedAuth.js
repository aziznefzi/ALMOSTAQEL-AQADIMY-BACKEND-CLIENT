import jwt from "jsonwebtoken"
import { BlockedIps } from "../schema/blockedIps.js"
import { Users } from "../schema/users.js"
import { getMsg } from "../utils/messages.js"

const filedAuth = async (req, res, next) => {
    try {
      // 1. Extract token from Cookie or Authorization header
      let token = req.cookies?.verificationToken || req.cookies?.accessToken;
      if (!token && req.headers.authorization) {
        const authHeader = req.headers.authorization;
        token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
      }

      if (!token) {
        return res.status(401).json({ message: getMsg("tokenMissing", req) });
      }

      // 2. 100% Cryptographic verification of token signature & expiration
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN);
      if (decoded.type !== "email-verification") {
        return res.status(403).json({ message: getMsg("tokenTypeInvalid", req) });
      }

      // 3. 100% Strict DeviceId Binding Protection
      const incomingDeviceId = req.headers['x-device-id'] || req.headers['device-id'] || req.body?.deviceId || req.query?.deviceId;
      if (!incomingDeviceId) {
        return res.status(403).json({ message: getMsg("deviceIdRequired", req) });
      }

      if (!decoded.deviceId || String(decoded.deviceId).trim() !== String(incomingDeviceId).trim()) {
        return res.status(403).json({ message: getMsg("deviceMismatch", req) });
      }

      // 4. Verify that the incoming device is not banned or permanently banned
      const deviceBan = await BlockedIps.findOne({
        deviceId: incomingDeviceId,
        StateBan: { $in: ['baned', 'permanent-baned'] }
      });
      if (deviceBan) {
        if (deviceBan.StateBan === "permanent-baned") {
          return res.status(403).json({ message: getMsg("devicePermanentBan", req) });
        }
        if (deviceBan.banneDate && (deviceBan.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req) });
        }
      }

      // 5. Verify the user exists and deviceId matches the registered user record in DB
      if (decoded.userId) {
        const userInDb = await Users.findById(decoded.userId);
        if (!userInDb) {
          return res.status(404).json({ message: getMsg("accountNotFound", req) });
        }
        if (userInDb.deviceId && String(userInDb.deviceId).trim() !== String(incomingDeviceId).trim()) {
          return res.status(403).json({ message: getMsg("deviceDbMismatch", req) });
        }
        req.dbUser = userInDb;
      }

      // 6. Verify User ID matches target in request if provided
      const targetUserId = req.params?.userId || req.body?.userId;
      if (targetUserId && decoded.userId && String(targetUserId) !== String(decoded.userId)) {
        return res.status(403).json({ message: getMsg("tokenUserMismatch", req) });
      }

      req.user = decoded;
      req.deviceId = incomingDeviceId;
      next();
    } catch(err) {
        console.log("invalid or expired token: ", err);
        return res.status(401).json({ message: getMsg("tokenInvalid", req) });
    }
}

export default filedAuth;