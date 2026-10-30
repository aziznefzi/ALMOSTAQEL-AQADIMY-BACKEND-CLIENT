import mongoose from "mongoose";

const supportImageSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalname: { type: String, required: true },
  path: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  url: { type: String },
  dataUrl: { type: String, default: "" }
}, { _id: false });

const supportSchema = new mongoose.Schema({
  ticketId: {
    type: String,
    unique: true,
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  subject: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    default: "general"
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  images: [supportImageSchema],
  status: {
    type: String,
    enum: ["pending", "in-progress", "resolved", "closed", "rejected"],
    default: "pending"
  },
  rejectionReason: {
    type: String,
    default: ""
  },
  ipAddress: {
    type: String,
    default: ""
  },
  deviceId: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

supportSchema.index({ createdAt: -1 });
supportSchema.index({ status: 1, createdAt: -1 });
supportSchema.index({ email: 1 });

export const Support = mongoose.model("Support", supportSchema);
export default Support;
