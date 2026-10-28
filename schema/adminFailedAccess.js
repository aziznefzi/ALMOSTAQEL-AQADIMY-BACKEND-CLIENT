import mongoose from "mongoose";

const AdminFailedAccessSchema = mongoose.Schema({
    reason: {
      type: String,
      enum: ["forged-token", "expired-token", "missing-token", "invalid-claims", "user-not-found", "invalid-device-id"],
      required: true
    },
    ipAddress: { type: String },
    deviceId: { type: String },
    userAgent: { type: String },
    path: { type: String },
    method: { type: String },
    attemptedEmail: { type: String },
    tokenEmail: { type: String },
    errorMessage: { type: String },
    attemptTime: {
      type: Date,
      required: true,
      default: Date.now
    }
});

export const AdminFailedAccess = mongoose.model("AdminFailedAccess", AdminFailedAccessSchema);
