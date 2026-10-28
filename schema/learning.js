import mongoose from "mongoose";

const learningSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true,
      enum: ["course", "article", "video", "ai-video", "Courses", "Articles", "Videos", "All Vidios"],
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxLength: 200,
    },
    titleAr: {
      type: String,
      default: "",
      trim: true,
      maxLength: 200,
    },
    description: {
      type: String,
      default: "",
      trim: true,
    },
    descriptionAr: {
      type: String,
      default: "",
      trim: true,
    },
    category: {
      type: String,
      default: "General",
      trim: true,
      index: true,
    },
    tag: {
      type: String,
      default: "General",
      trim: true,
    },
    status: {
      type: String,
      enum: ["published", "draft", "archived"],
      default: "published",
      index: true,
    },
    level: {
      type: String,
      enum: ["Beginner", "Intermediate", "Advanced"],
      default: "Beginner",
    },
    levelAr: {
      type: String,
      default: "مبتدئ",
    },
    instructor: {
      type: String,
      default: "",
      trim: true,
    },
    instructorAr: {
      type: String,
      default: "",
      trim: true,
    },
    author: {
      type: String,
      default: "",
      trim: true,
    },
    tool: {
      type: String,
      default: "",
      trim: true,
    },
    platform: {
      type: String,
      default: "Native",
      trim: true,
    },
    duration: {
      type: String,
      default: "0h",
    },
    hours: {
      type: Number,
      default: 0,
      min: 0,
    },
    lessons: {
      type: Number,
      default: 0,
      min: 0,
    },
    readTime: {
      type: Number,
      default: 0,
      min: 0,
    },
    enrollments: {
      type: Number,
      default: 0,
      min: 0,
    },
    views: {
      type: Number,
      default: 0,
      min: 0,
    },
    rating: {
      type: Number,
      default: 5.0,
      min: 1,
      max: 5,
    },
    price: {
      type: Number,
      default: 0,
      min: 0,
    },
    priceAfter: {
      type: Number,
      default: 0,
      min: 0,
    },
    image: {
      type: String,
      default: "",
    },
    stack: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true }
);

// Performance Indexes for Pagination, Search, and Filtering
learningSchema.index({ type: 1, status: 1, createdAt: -1 });
learningSchema.index({ type: 1, category: 1, status: 1 });
learningSchema.index({ status: 1, views: -1 });
learningSchema.index({ status: 1, enrollments: -1 });

export const Learning = mongoose.model("Learning", learningSchema);
export default Learning;
