import mongoose from "mongoose";

const chatMessageItemSchema = new mongoose.Schema(
  {
    clientMessageId: {
      type: String,
      default: null,
      trim: true,
    },
    sender: {
      type: String,
      enum: ["user", "ai"],
      required: true,
    },
    text: {
      type: String,
      required: true,
      trim: true,
    },
    lang: {
      type: String,
      enum: ["ar", "en"],
      default: "ar",
    },
    modelUsed: {
      type: String,
      default: "",
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: true }
);

const aiChatConversationSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    ipAddress: {
      type: String,
      default: null,
    },
    messages: {
      type: [chatMessageItemSchema],
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

aiChatConversationSchema.index({ updatedAt: -1 });

export const AiChatConversation =
  mongoose.models.AiChatConversation ||
  mongoose.model("AiChatConversation", aiChatConversationSchema);

export const AiChatMessage = AiChatConversation;
export default AiChatConversation;
