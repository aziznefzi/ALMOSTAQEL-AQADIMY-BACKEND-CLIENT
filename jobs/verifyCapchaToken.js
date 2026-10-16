import axios from "axios";

/**
 * Verifies a Google reCAPTCHA token and returns a structured diagnosis:
 * - success: true | false
 * - status: 'success' | 'network_error' | 'expired_or_duplicate' | 'forged' | 'missing'
 * - errorCodes: array of codes from Google
 */
export const verifyCaptchaToken = async (token) => {
    if (!token || typeof token !== "string" || !token.trim()) {
        return {
            success: false,
            status: "missing",
            message: "Missing captcha token"
        };
    }

    // Allow test bypass tokens in development
    if (process.env.NODE_ENV === "development" && (token === "dev-bypass" || token === "test")) {
        return {
            success: true,
            status: "success",
            devBypass: true
        };
    }

    try {
        const secretKey = process.env.RECAPTION_SECRET_KEY;
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${encodeURIComponent(token.trim())}`,
            null,
            { timeout: 5000 }
        );

        const data = response.data || {};
        const isSuccess = data.success === true;
        const errorCodes = Array.isArray(data["error-codes"]) ? data["error-codes"] : [];

        if (isSuccess) {
            return {
                success: true,
                status: "success",
                challenge_ts: data.challenge_ts,
                hostname: data.hostname
            };
        }

        // Differentiate between expired/duplicate vs malicious/forged
        if (errorCodes.includes("timeout-or-duplicate")) {
            return {
                success: false,
                status: "expired_or_duplicate",
                errorCodes,
                message: "Captcha token expired or was already used"
            };
        }

        if (errorCodes.includes("missing-input-response")) {
            return {
                success: false,
                status: "missing",
                errorCodes,
                message: "Missing captcha token"
            };
        }

        // If Google explicitly rejected the response parameter as invalid or bad-request
        if (errorCodes.includes("invalid-input-response") || errorCodes.includes("bad-request")) {
            return {
                success: false,
                status: "forged",
                errorCodes,
                message: "Forged or tampered captcha token"
            };
        }

        // Generic failure from Google
        return {
            success: false,
            status: "forged",
            errorCodes,
            message: "Invalid captcha response"
        };

    } catch (error) {
        console.error("Error connecting to Google reCAPTCHA:", error?.message);

        // Network / connectivity issues (timeout, unreachable, DNS, Google downtime)
        const isNetworkIssue =
            !error.response ||
            error.code === "ETIMEDOUT" ||
            error.code === "ENETUNREACH" ||
            error.code === "ECONNREFUSED" ||
            error.code === "ENOTFOUND" ||
            error.code === "ECONNRESET" ||
            error.message?.includes("timeout") ||
            error.message?.includes("Network Error");

        if (isNetworkIssue) {
            if (process.env.NODE_ENV === "development") {
                console.warn("⚠️ Development environment: Google reCAPTCHA unreachable. Allowing dev bypass.");
                return {
                    success: true,
                    status: "success",
                    devBypass: true
                };
            }
            return {
                success: false,
                status: "network_error",
                error: error.message
            };
        }

        return {
            success: false,
            status: "network_error",
            error: error.message
        };
    }
};