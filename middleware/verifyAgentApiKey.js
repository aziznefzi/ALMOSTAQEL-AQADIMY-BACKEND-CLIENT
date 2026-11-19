import crypto from "crypto";
import { getMsg } from "../utils/messages.js";

/**
 * Middleware to authenticate external AI Agent (Creao) requests.
 * Validates the `x-api-key` header against `process.env.AI_AGENT_API_KEY`
 * using SHA-256 digests + `crypto.timingSafeEqual` to prevent timing attacks
 * and avoid leaking key length.
 */
export const verifyAgentApiKey = (req, res, next) => {
  try {
    const expectedKey = process.env.AI_AGENT_API_KEY;
    if (
      !expectedKey ||
      typeof expectedKey !== "string" ||
      expectedKey.trim().length === 0
    ) {
      console.error(
        "[verifyAgentApiKey] AI_AGENT_API_KEY is not configured in environment variables."
      );
      return res.status(401).json({
        success: false,
        message: getMsg("agentApiKeyUnauthorized", req),
      });
    }

    const incomingKey = req.headers["x-api-key"];
    if (
      !incomingKey ||
      typeof incomingKey !== "string" ||
      incomingKey.trim().length === 0
    ) {
      return res.status(401).json({
        success: false,
        message: getMsg("agentApiKeyMissing", req),
      });
    }

    // Hash both values to fixed-length 32-byte buffers before timingSafeEqual
    // so mismatched lengths never throw RangeError or leak expected key length.
    const expectedDigest = crypto
      .createHash("sha256")
      .update(expectedKey.trim(), "utf8")
      .digest();
    const incomingDigest = crypto
      .createHash("sha256")
      .update(incomingKey.trim(), "utf8")
      .digest();

    const isValid = crypto.timingSafeEqual(incomingDigest, expectedDigest);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: getMsg("agentApiKeyUnauthorized", req),
      });
    }

    req.isAiAgent = true;
    return next();
  } catch (err) {
    console.error("[verifyAgentApiKey] Verification error:", err);
    return res.status(401).json({
      success: false,
      message: getMsg("agentApiKeyUnauthorized", req),
    });
  }
};

export default verifyAgentApiKey;
