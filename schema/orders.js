import mongoose from "mongoose";

const orderSchema = new mongoose.Schema(
  {
    orderCode: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
      required: true,
      index: true,
    },
    userName: {
      type: String,
      default: "",
      trim: true,
    },
    userEmail: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true,
    },
    userPhone: {
      type: String,
      default: "",
      trim: true,
    },
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Learning",
      required: true,
      index: true,
    },
    productTitle: {
      type: String,
      required: true,
      trim: true,
    },
    productTitleAr: {
      type: String,
      default: "",
      trim: true,
    },
    productType: {
      type: String,
      default: "Courses",
    },
    productImage: {
      type: String,
      default: "",
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    paymentMethod: {
      type: String,
      enum: ["flouci", "zitouna", "d17"],
      required: true,
    },
    ribSent: {
      type: String,
      default: "",
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true,
    },
    adminNote: {
      type: String,
      default: "",
    },
    approvedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

orderSchema.index({ userId: 1, productId: 1, status: 1 });
orderSchema.index({ status: 1, createdAt: -1 });

export const Orders = mongoose.model("Orders", orderSchema);
export default Orders;

