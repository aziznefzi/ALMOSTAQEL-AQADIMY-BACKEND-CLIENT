import mongoose from "mongoose";

const servicesSchema = new mongoose.Schema(
  {
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
    phone: {
      type: String,
      required: true,
      trim: true
    },
    serviceType: {
      type: String,
      default: "web",
      required: true
    },
    subject: {
      type: String,
      required: true,
      trim: true
    },
    details: {
      type: String,
      required: true,
      trim: true
    },
    budget: {
      type: String,
      default: ""
    },
    deviceId: {
      type: String,
      default: null
    },
    ipAddress: {
      type: String,
      default: null
    },
    status: {
      type: String,
      enum: ["pending", "contacted", "in-progress", "completed", "cancelled"],
      default: "pending"
    }
  },
  {
    timestamps: true
  }
);

export const Services = mongoose.models.Service || mongoose.model("Service", servicesSchema);
export default Services;