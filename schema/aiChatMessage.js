import mongoose from "mongoose";

const aiChatMessageSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      trim: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    email: {
      type: String,
      default: null,
      lowercase: true,
      trim: true,
    },
    ipAddress: {
      type: String,
      default: null,
    },
    clientMessageId: {
      type: String,
      default: null,
      trim: true,
    },
    userMessage: {
      type: String,
      required: true,
      trim: true,
      maxLength: 1000,
    },
    aiResponse: {
      type: String,
      default: "",
      trim: true,
    },
    lang: {
      type: String,
      enum: ["ar", "en"],
      default: "ar",
    },
    status: {
      type: String,
      enum: ["pending", "completed", "failed"],
      default: "pending",
    },
    modelUsed: {
      type: String,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

aiChatMessageSchema.index({ deviceId: 1, createdAt: -1 });
aiChatMessageSchema.index({ clientMessageId: 1, deviceId: 1 });
aiChatMessageSchema.index({ createdAt: -1 });

export const AiChatMessage =
  mongoose.models.AiChatMessage ||
  mongoose.model("AiChatMessage", aiChatMessageSchema);

export default AiChatMessage;
