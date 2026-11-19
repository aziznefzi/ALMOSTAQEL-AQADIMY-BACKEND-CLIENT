import mongoose from "mongoose";

const courseVideoSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    titleAr: {
      type: String,
      default: "",
      trim: true,
    },
    description: {
      type: String,
      default: "",
      trim: true,
    },
    videoUrl: {
      type: String,
      required: true,
      trim: true,
    },
    duration: {
      type: String,
      default: "0:00",
      trim: true,
    },
    order: {
      type: Number,
      default: 0,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

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
    slug: {
      type: String,
      trim: true,
      lowercase: true,
      maxLength: 160,
    },
    excerpt: {
      type: String,
      default: "",
      trim: true,
      maxLength: 600,
    },
    excerptAr: {
      type: String,
      default: "",
      trim: true,
      maxLength: 600,
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
    content: {
      type: String,
      default: "",
      trim: true,
    },
    contentAr: {
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
    tags: {
      type: [String],
      default: [],
    },
    source: {
      type: String,
      enum: ["admin", "ai_agent"],
      default: "admin",
      index: true,
    },
    status: {
      type: String,
      enum: ["pending", "published", "draft", "archived"],
      default: "published",
      index: true,
    },
    approvedAt: {
      type: Date,
      default: null,
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
      default: null,
    },
    seo: {
      metaTitle: {
        type: String,
        default: "",
        trim: true,
        maxLength: 160,
      },
      metaDescription: {
        type: String,
        default: "",
        trim: true,
        maxLength: 320,
      },
      keywords: {
        type: [String],
        default: [],
      },
      canonicalUrl: {
        type: String,
        default: "",
        trim: true,
        maxLength: 500,
      },
      ogImage: {
        type: String,
        default: "",
        trim: true,
        maxLength: 500,
      },
    },
    availabilityStatus: {
      type: String,
      enum: ["preorder", "available", "unavailable"],
      default: "preorder",
      index: true,
    },
    preorders: {
      type: [
        {
          userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Users",
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
          },
          lang: {
            type: String,
            enum: ["ar", "en"],
            default: "ar",
          },
          notifiedAt: {
            type: Date,
            default: null,
          },
          createdAt: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      default: [],
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
    imageDataUrl: {
      type: String,
      default: "",
    },
    videoUrl: {
      type: String,
      default: "",
      trim: true,
    },
    courseVideos: {
      type: [courseVideoSchema],
      default: [],
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
learningSchema.index({ type: 1, source: 1, status: 1, createdAt: -1 });
learningSchema.index({ type: 1, category: 1, status: 1 });
learningSchema.index({ status: 1, views: -1 });
learningSchema.index({ status: 1, enrollments: -1 });
learningSchema.index(
  { slug: 1 },
  {
    unique: true,
    partialFilterExpression: { slug: { $type: "string", $gt: "" } },
  }
);

export const Learning = mongoose.model("Learning", learningSchema);
export default Learning;
