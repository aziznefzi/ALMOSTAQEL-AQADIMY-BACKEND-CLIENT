import { BlockedIps } from "../schema/blockedIps.js";
import { getMsg } from "../utils/messages.js";

// Sliding window in-memory tracking
// 15 requests per 5 minutes limit
const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_REQUESTS = 15; // Max allowed requests within 5 minutes

const emailTracker = new Map();
const deviceTracker = new Map();
const ipTracker = new Map();

// Periodic cleanup to avoid memory leaks (runs every 5 minutes)
setInterval(() => {
  const threshold = Date.now() - WINDOW_MS;

  const prune = (map) => {
    for (const [key, timestamps] of map.entries()) {
      const valid = timestamps.filter((t) => t > threshold);
      if (valid.length === 0) {
        map.delete(key);
      } else {
        map.set(key, valid);
      }
    }
  };

  prune(emailTracker);
  prune(deviceTracker);
  prune(ipTracker);
}, WINDOW_MS);

/**
 * Check if a deviceId, email, or IP address is currently banned in MongoDB BlockedIps.
 */
export const checkIsBanned = async ({ email, deviceId, ipAddress }) => {
  const cleanEmail = email ? String(email).toLowerCase().trim() : null;
  const cleanDeviceId = deviceId ? String(deviceId).trim() : null;
  const cleanIp = ipAddress ? String(ipAddress).trim() : null;

  const conditions = [];

  if (cleanDeviceId) {
    conditions.push({
      deviceId: cleanDeviceId,
      StateBan: { $in: ["baned", "permanent-baned"] },
    });
  }

  if (cleanEmail) {
    conditions.push({
      email: cleanEmail,
      StateBan: { $in: ["baned", "permanent-baned"] },
    });
  }

  if (cleanIp && cleanIp !== "::1" && cleanIp !== "127.0.0.1") {
    conditions.push({
      ipAddress: cleanIp,
      StateBan: "permanent-baned",
    });
  }

  if (conditions.length === 0) {
    return { isBanned: false };
  }

  const banRecord = await BlockedIps.findOne({ $or: conditions });
  if (!banRecord) {
    return { isBanned: false };
  }

  // Determine ban type & matching target
  const isDeviceMatch = cleanDeviceId && banRecord.deviceId === cleanDeviceId;
  const isEmailMatch = cleanEmail && banRecord.email === cleanEmail;

  return {
    isBanned: true,
    stateBan: banRecord.StateBan,
    banType: banRecord.banType,
    matchedOn: isDeviceMatch ? "device" : isEmailMatch ? "email" : "ip",
    reason: banRecord.resson || "نشاط مشبوه أو هجوم سبام",
    record: banRecord,
  };
};

/**
 * Track request count and trigger automatic ban if > 15 requests in 5 minutes.
 */
export const recordAndCheckSpamRate = async ({ email, deviceId, ipAddress }) => {
  const now = Date.now();
  const threshold = now - WINDOW_MS;

  const cleanEmail = email ? String(email).toLowerCase().trim() : null;
  const cleanDeviceId = deviceId ? String(deviceId).trim() : null;
  const cleanIp = ipAddress ? String(ipAddress).trim() : null;

  let isSpam = false;
  let spamKeyType = null;
  let spamKeyVal = null;
  let currentCount = 0;

  // Helper to record and evaluate sliding window
  const recordTimestamp = (map, key) => {
    if (!key) return 0;
    const existing = (map.get(key) || []).filter((t) => t > threshold);
    existing.push(now);
    map.set(key, existing);
    return existing.length;
  };

  // 1. Check & track by Email
  if (cleanEmail) {
    const count = recordTimestamp(emailTracker, cleanEmail);
    if (count > MAX_REQUESTS) {
      isSpam = true;
      spamKeyType = "email";
      spamKeyVal = cleanEmail;
      currentCount = count;
    }
  }

  // 2. Check & track by DeviceId
  if (!isSpam && cleanDeviceId) {
    const count = recordTimestamp(deviceTracker, cleanDeviceId);
    if (count > MAX_REQUESTS) {
      isSpam = true;
      spamKeyType = "device";
      spamKeyVal = cleanDeviceId;
      currentCount = count;
    }
  }

  // 3. Check & track by IP (skip localhost during dev)
  if (!isSpam && cleanIp && cleanIp !== "::1" && cleanIp !== "127.0.0.1") {
    const count = recordTimestamp(ipTracker, cleanIp);
    if (count > MAX_REQUESTS * 2) {
      isSpam = true;
      spamKeyType = "ip";
      spamKeyVal = cleanIp;
      currentCount = count;
    }
  }

  // If spam attack threshold exceeded -> BAN EMAIL & DEVICE IN DATABASE
  if (isSpam) {
    const reasonText = `Spam Attack: Exceeded ${MAX_REQUESTS} requests within 5 minutes (${currentCount} attempts on ${spamKeyType})`;

    const banOps = [];

    if (cleanEmail) {
      banOps.push(
        BlockedIps.findOneAndUpdate(
          { email: cleanEmail },
          {
            $set: {
              email: cleanEmail,
              deviceId: cleanDeviceId || null,
              ipAddress: cleanIp,
              resson: reasonText,
              banneDate: new Date(),
              StateBan: "baned",
              banType: "all",
            },
            $inc: { BannedCount: 1 },
          },
          { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
        )
      );
    }

    if (cleanDeviceId) {
      banOps.push(
        BlockedIps.findOneAndUpdate(
          { deviceId: cleanDeviceId },
          {
            $set: {
              deviceId: cleanDeviceId,
              email: cleanEmail || null,
              ipAddress: cleanIp,
              resson: reasonText,
              banneDate: new Date(),
              StateBan: "baned",
              banType: "all",
            },
            $inc: { BannedCount: 1 },
          },
          { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
        )
      );
    }

    await Promise.all(banOps);

    return {
      isSpam: true,
      count: currentCount,
      keyType: spamKeyType,
      value: spamKeyVal,
    };
  }

  return { isSpam: false, count: currentCount };
};

/**
 * Pre-check deviceId header middleware before Multer file upload.
 * If incoming deviceId header is banned, abort immediately before receiving files.
 */
export const preCheckDeviceBanMiddleware = async (req, res, next) => {
  try {
    const deviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.query?.deviceId;

    if (deviceId) {
      const banCheck = await checkIsBanned({ deviceId });
      if (banCheck.isBanned) {
        return res.status(403).json({
          banned: true,
          message: getMsg("devicePermanentBan", req),
        });
      }
    }
    next();
  } catch (err) {
    console.error("preCheckDeviceBanMiddleware error:", err);
    next();
  }
};
