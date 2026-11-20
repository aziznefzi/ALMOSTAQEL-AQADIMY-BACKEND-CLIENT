import express from "express";
import crypto from "crypto";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import { Learning } from "../../schema/learning.js";
import { verifyAgentApiKey } from "../../middleware/verifyAgentApiKey.js";
import { getMsg } from "../../utils/messages.js";
import { detectImageProvider, extractCloudinaryPublicId } from "../../utils/mediaValidation.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const ALLOWED_PUBLIC_SORT_FIELDS = [
  "createdAt",
  "views",
  "readTime",
  "rating",
  "title",
];

const RESERVED_SLUGS = new Set(["agent", "approve", "new", "create", "list"]);

// ============================================================================
// Rate Limiting for External AI Agent Submissions
// 30 requests per 15 minutes per IP
// ============================================================================
export const agentArticleRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      message: getMsg("agentRateLimitExceeded", req),
    });
  },
});

// ============================================================================
// Input Sanitization & Validation Utilities
// ============================================================================
const stripDangerousSchemes = (str) =>
  str
    .replace(/javascript\s*:/gi, "")
    .replace(/vbscript\s*:/gi, "")
    .replace(/data\s*:\s*text\/html/gi, "");

const sanitizePlainText = (raw, maxLength = 500) => {
  if (typeof raw !== "string") return "";
  let cleaned = raw
    .replace(/\u0000/g, "")
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, " ")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, " ")
    .replace(/<[^>]*>/g, " ");
  cleaned = stripDangerousSchemes(cleaned)
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.slice(0, maxLength);
};

const sanitizeArticleContent = (raw, maxLength = 100000) => {
  if (typeof raw !== "string") return "";
  let cleaned = raw
    .replace(/\u0000/g, "")
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "")
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "")
    .replace(/<embed\b[^>]*>/gi, "")
    .replace(/<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi, "")
    .replace(/<meta\b[^>]*>/gi, "")
    .replace(/<link\b[^>]*>/gi, "")
    .replace(/<base\b[^>]*>/gi, "")
    .replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
  cleaned = stripDangerousSchemes(cleaned).trim();
  return cleaned.slice(0, maxLength);
};

const sanitizeSafeUrl = (raw, { allowRelativeUploads = false, maxLength = 500 } = {}) => {
  if (raw === undefined || raw === null || raw === "") {
    return { valid: true, value: "" };
  }
  if (typeof raw !== "string") {
    return { valid: false, value: "" };
  }
  const trimmed = raw.replace(/\u0000/g, "").trim();
  if (!trimmed) return { valid: true, value: "" };
  if (trimmed.length > maxLength) return { valid: false, value: "" };

  if (allowRelativeUploads && /^\/uploads\/[a-zA-Z0-9._/-]+$/.test(trimmed)) {
    return { valid: true, value: trimmed };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, value: "" };
    }
    return { valid: true, value: parsed.toString() };
  } catch {
    return { valid: false, value: "" };
  }
};

const normalizeSlug = (raw) => {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/\u0000/g, "")
    .toLowerCase()
    .trim()
    .replace(/[\s_]+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 150);
};

const generateAutoSlug = (title) => {
  const base = normalizeSlug(title).slice(0, 120);
  const suffix = crypto.randomBytes(3).toString("hex");
  return base && base.length >= 3 ? `${base}-${suffix}` : `article-${Date.now().toString(36)}-${suffix}`;
};

const estimateReadTime = (text) => {
  const words = String(text || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean).length;
  return Math.max(1, Math.min(180, Math.ceil(words / 200)));
};

const validateAndSanitizeAgentPayload = (body) => {
  const errors = [];

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { errors: ["Request body must be a valid JSON object."] };
  }

  // 1. title (required)
  if (typeof body.title !== "string" || !body.title.trim()) {
    errors.push("title is required and must be a non-empty string.");
  }
  const title = sanitizePlainText(body.title, 200);
  if (typeof body.title === "string" && body.title.trim() && title.length < 3) {
    errors.push("title must be at least 3 characters after sanitization.");
  }

  // 2. titleAr (optional)
  let titleAr = "";
  if (body.titleAr !== undefined && body.titleAr !== null) {
    if (typeof body.titleAr !== "string") {
      errors.push("titleAr must be a string.");
    } else {
      titleAr = sanitizePlainText(body.titleAr, 200);
    }
  }

  // 3. content (required)
  if (typeof body.content !== "string" || !body.content.trim()) {
    errors.push("content is required and must be a non-empty string.");
  }
  const content = sanitizeArticleContent(body.content, 100000);
  if (typeof body.content === "string" && body.content.trim() && content.length < 20) {
    errors.push("content must be at least 20 characters after sanitization.");
  }

  // 4. contentAr (optional)
  let contentAr = "";
  if (body.contentAr !== undefined && body.contentAr !== null) {
    if (typeof body.contentAr !== "string") {
      errors.push("contentAr must be a string.");
    } else {
      contentAr = sanitizeArticleContent(body.contentAr, 100000);
    }
  }

  // 5. excerpt (validated if provided; falls back to content snippet if omitted)
  let excerpt = "";
  if (body.excerpt !== undefined && body.excerpt !== null) {
    if (typeof body.excerpt !== "string") {
      errors.push("excerpt must be a string.");
    } else {
      excerpt = sanitizePlainText(body.excerpt, 600);
      if (excerpt.length < 5) {
        errors.push("excerpt must be at least 5 characters when provided.");
      }
    }
  } else if (content) {
    const plainContent = sanitizePlainText(content, 240);
    excerpt = plainContent.length > 217 ? `${plainContent.slice(0, 217)}...` : plainContent;
  }

  // 6. excerptAr (optional)
  let excerptAr = "";
  if (body.excerptAr !== undefined && body.excerptAr !== null) {
    if (typeof body.excerptAr !== "string") {
      errors.push("excerptAr must be a string.");
    } else {
      excerptAr = sanitizePlainText(body.excerptAr, 600);
    }
  }

  // 7. slug (validated if provided; auto-generated if omitted)
  let slug = "";
  let slugWasExplicit = false;
  if (body.slug !== undefined && body.slug !== null && body.slug !== "") {
    slugWasExplicit = true;
    if (typeof body.slug !== "string") {
      errors.push("slug must be a string.");
    } else {
      slug = normalizeSlug(body.slug);
      if (slug.length < 3 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
        errors.push(
          "slug must contain at least 3 lowercase alphanumeric characters separated by hyphens (e.g. 'my-article-slug')."
        );
      } else if (RESERVED_SLUGS.has(slug)) {
        errors.push(`slug '${slug}' is reserved and cannot be used.`);
      }
    }
  }

  // 8. tags (optional array of strings)
  let tags = [];
  if (body.tags !== undefined && body.tags !== null) {
    if (!Array.isArray(body.tags)) {
      errors.push("tags must be an array of strings.");
    } else {
      if (body.tags.length > 15) {
        errors.push("tags cannot contain more than 15 items.");
      }
      const seen = new Set();
      for (const rawTag of body.tags.slice(0, 15)) {
        if (typeof rawTag !== "string") {
          errors.push("Every item in tags must be a string.");
          break;
        }
        const cleanedTag = sanitizePlainText(rawTag, 40);
        if (cleanedTag) {
          const lowerKey = cleanedTag.toLowerCase();
          if (!seen.has(lowerKey)) {
            seen.add(lowerKey);
            tags.push(cleanedTag);
          }
        }
      }
    }
  }

  // 9. category & author (optional)
  let category = "";
  if (body.category !== undefined && body.category !== null) {
    if (typeof body.category !== "string") {
      errors.push("category must be a string.");
    } else {
      category = sanitizePlainText(body.category, 60);
    }
  }
  if (!category) {
    category = tags[0] || "Tech Insights";
  }

  let author = "AI Agent";
  if (body.author !== undefined && body.author !== null && body.author !== "") {
    if (typeof body.author !== "string") {
      errors.push("author must be a string.");
    } else {
      author = sanitizePlainText(body.author, 80) || "AI Agent";
    }
  }

  // 10. readTime (optional positive integer)
  let readTime = estimateReadTime(content || contentAr);
  if (body.readTime !== undefined && body.readTime !== null && body.readTime !== "") {
    const parsedReadTime = Number(body.readTime);
    if (!Number.isFinite(parsedReadTime) || parsedReadTime < 1 || parsedReadTime > 180) {
      errors.push("readTime must be a number between 1 and 180.");
    } else {
      readTime = Math.round(parsedReadTime);
    }
  }

  // 11. image (optional safe HTTPS URL, up to 1000 chars for external CDNs)
  const imageCheck = sanitizeSafeUrl(body.image, {
    allowRelativeUploads: false,
    maxLength: 1000,
  });
  if (!imageCheck.valid) {
    errors.push("image must be a valid external http(s) URL.");
  }

  // 12. seo (optional metadata object)
  const seo = {
    metaTitle: "",
    metaDescription: "",
    keywords: [],
    canonicalUrl: "",
    ogImage: "",
  };

  if (body.seo !== undefined && body.seo !== null) {
    if (typeof body.seo !== "object" || Array.isArray(body.seo)) {
      errors.push("seo must be an object.");
    } else {
      if (body.seo.metaTitle !== undefined && body.seo.metaTitle !== null) {
        if (typeof body.seo.metaTitle !== "string") {
          errors.push("seo.metaTitle must be a string.");
        } else {
          seo.metaTitle = sanitizePlainText(body.seo.metaTitle, 160);
        }
      }

      if (body.seo.metaDescription !== undefined && body.seo.metaDescription !== null) {
        if (typeof body.seo.metaDescription !== "string") {
          errors.push("seo.metaDescription must be a string.");
        } else {
          seo.metaDescription = sanitizePlainText(body.seo.metaDescription, 320);
        }
      }

      if (body.seo.keywords !== undefined && body.seo.keywords !== null) {
        if (!Array.isArray(body.seo.keywords)) {
          errors.push("seo.keywords must be an array of strings.");
        } else {
          const seenKw = new Set();
          for (const rawKw of body.seo.keywords.slice(0, 20)) {
            if (typeof rawKw !== "string") {
              errors.push("Every item in seo.keywords must be a string.");
              break;
            }
            const cleanedKw = sanitizePlainText(rawKw, 50);
            if (cleanedKw && !seenKw.has(cleanedKw.toLowerCase())) {
              seenKw.add(cleanedKw.toLowerCase());
              seo.keywords.push(cleanedKw);
            }
          }
        }
      }

      const canonicalCheck = sanitizeSafeUrl(body.seo.canonicalUrl);
      if (!canonicalCheck.valid) {
        errors.push("seo.canonicalUrl must be a valid http(s) URL.");
      } else {
        seo.canonicalUrl = canonicalCheck.value;
      }

      const ogImageCheck = sanitizeSafeUrl(body.seo.ogImage);
      if (!ogImageCheck.valid) {
        errors.push("seo.ogImage must be a valid http(s) URL.");
      } else {
        seo.ogImage = ogImageCheck.value;
      }
    }
  }

  return {
    errors,
    slugWasExplicit,
    data: {
      title,
      titleAr,
      slug,
      excerpt,
      excerptAr,
      description: excerpt,
      descriptionAr: excerptAr,
      content,
      contentAr,
      tags,
      tag: tags[0] || category,
      category,
      author,
      instructor: author,
      readTime,
      image: imageCheck.value,
      seo,
    },
  };
};

// ============================================================================
// Helper: Format Public Article (strictly hides paid body & internal fields)
// ============================================================================
const toPublicArticleCard = (item) => {
  const effectivePrice = Number(item.priceAfter ?? item.price ?? 0);
  const {
    courseVideos,
    videoUrl,
    videoMedia,
    content,
    contentAr,
    preorders,
    approvedBy,
    imageDataUrl,
    ...publicFields
  } = item;

  const deliveryImage =
    item.thumbnail?.url ||
    (item.image && !String(item.image).startsWith("data:")
      ? item.image
      : imageDataUrl
      ? `/api/learning/${item._id}/image`
      : "");

  return {
    ...publicFields,
    id: item._id,
    image: deliveryImage,
    thumbnail: {
      url: deliveryImage,
      provider: item.thumbnail?.provider || "",
      publicId: item.thumbnail?.publicId || "",
      alt: item.thumbnail?.alt || item.title || "",
    },
    source: item.source || "admin",
    excerpt: item.excerpt || item.description || "",
    excerptAr: item.excerptAr || item.descriptionAr || "",
    tags: Array.isArray(item.tags) && item.tags.length > 0 ? item.tags : item.tag ? [item.tag] : [],
    availabilityStatus: item.availabilityStatus || "preorder",
    requiresPurchase: effectivePrice > 0,
  };
};

const toPublicArticleDetail = (item) => {
  const effectivePrice = Number(item.priceAfter ?? item.price ?? 0);
  const base = toPublicArticleCard(item);
  if (effectivePrice > 0) {
    return base;
  }
  return {
    ...base,
    content: item.content || "",
    contentAr: item.contentAr || "",
  };
};

// ============================================================================
// 1. POST /api/articles/agent - External AI Agent (Creao) Article Draft Submission
// Strictly protected by Rate Limiter + verifyAgentApiKey.
// Strictly forces source: "ai_agent" and status: "pending" on server side.
// ============================================================================
router.post(
  "/articles/agent",
  agentArticleRateLimiter,
  verifyAgentApiKey,
  async (req, res) => {
    try {
      const { errors, slugWasExplicit, data } = validateAndSanitizeAgentPayload(
        req.body
      );

      if (errors.length > 0) {
        return res.status(400).json({
          success: false,
          message: getMsg("articleValidationFailed", req),
          errors,
        });
      }

      // Resolve unique slug
      let finalSlug = data.slug;
      if (slugWasExplicit && finalSlug) {
        const existingSlug = await Learning.exists({ slug: finalSlug });
        if (existingSlug) {
          return res.status(409).json({
            success: false,
            message: getMsg("articleSlugExists", req),
          });
        }
      } else {
        finalSlug = generateAutoSlug(data.title);
        while (await Learning.exists({ slug: finalSlug })) {
          finalSlug = generateAutoSlug(data.title);
        }
      }

      // CRITICAL SECURITY ENFORCEMENT:
      // Server strictly forces type="article", source="ai_agent", status="pending",
      // price=0, priceAfter=0 regardless of what req.body contains.
      const createdArticle = await Learning.create({
        type: "article",
        title: data.title,
        titleAr: data.titleAr,
        slug: finalSlug,
        excerpt: data.excerpt,
        excerptAr: data.excerptAr,
        description: data.description,
        descriptionAr: data.descriptionAr,
        content: data.content,
        contentAr: data.contentAr,
        category: data.category,
        tag: data.tag,
        tags: data.tags,
        author: data.author,
        instructor: data.instructor,
        readTime: data.readTime,
        image: data.image,
        thumbnail: {
          url: data.image,
          provider: data.image ? detectImageProvider(data.image) : "",
          publicId: data.image ? extractCloudinaryPublicId(data.image) : "",
          alt: data.title,
        },
        imageDataUrl: "",
        seo: data.seo,
        source: "ai_agent",
        status: "pending",
        availabilityStatus: "available",
        price: 0,
        priceAfter: 0,
        approvedAt: null,
        approvedBy: null,
      });

      const obj = createdArticle.toObject();
      return res.status(201).json({
        success: true,
        message: getMsg("articleCreatedPending", req),
        article: {
          id: obj._id,
          _id: obj._id,
          title: obj.title,
          titleAr: obj.titleAr,
          slug: obj.slug,
          excerpt: obj.excerpt,
          tags: obj.tags,
          category: obj.category,
          readTime: obj.readTime,
          seo: obj.seo,
          source: obj.source,
          status: obj.status,
          createdAt: obj.createdAt,
        },
      });
    } catch (err) {
      if (err?.code === 11000 && err?.keyPattern?.slug) {
        return res.status(409).json({
          success: false,
          message: getMsg("articleSlugExists", req),
        });
      }
      console.error("Error in POST /api/articles/agent:", err);
      return res.status(500).json({
        success: false,
        message: getMsg("serverError", req),
      });
    }
  }
);

// ============================================================================
// 2. GET /api/articles - Public Paginated List of Published Articles ONLY
// ============================================================================
router.get("/articles", async (req, res) => {
  try {
    const parsedPage = parseInt(req.query.page, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(req.query.limit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, 100)
        : 50;
    const skip = (page - 1) * limit;

    // Public safety: STRICTLY return only published articles
    const andConditions = [
      { type: { $in: ["article", "Articles"] } },
      { status: "published" },
    ];

    const rawCategory = req.query.category ?? req.query.tag;
    if (typeof rawCategory === "string") {
      const cleanCat = rawCategory.trim().slice(0, 60);
      if (cleanCat && cleanCat.toLowerCase() !== "all") {
        andConditions.push({
          $or: [
            { category: cleanCat },
            { tag: cleanCat },
            { tags: cleanCat },
          ],
        });
      }
    }

    const rawSearch = req.query.search ?? req.query.q;
    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        andConditions.push({
          $or: [
            { title: regex },
            { titleAr: regex },
            { slug: regex },
            { excerpt: regex },
            { description: regex },
            { descriptionAr: regex },
            { author: regex },
            { category: regex },
            { tag: regex },
            { tags: regex },
          ],
        });
      }
    }

    const query = { $and: andConditions };
    const sortField = ALLOWED_PUBLIC_SORT_FIELDS.includes(req.query.sort)
      ? req.query.sort
      : "createdAt";
    const sortOrder = String(req.query.order).toLowerCase() === "asc" ? 1 : -1;

    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query)
        .sort({ [sortField]: sortOrder })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    return res.status(200).json({
      items: items.map(toPublicArticleCard),
      pagination: {
        total,
        page,
        limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    });
  } catch (err) {
    console.error("Error in GET /api/articles:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

// ============================================================================
// 3. GET /api/articles/:identifier - Public Single Published Article (by ID or Slug)
// Pending, draft, and archived articles are NEVER returned (always 404).
// ============================================================================
router.get("/articles/:identifier", async (req, res) => {
  try {
    const rawIdentifier = String(req.params.identifier || "").trim();
    if (!rawIdentifier) {
      return res.status(404).json({ message: getMsg("articleNotFound", req) });
    }

    const isObjectId = mongoose.isValidObjectId(rawIdentifier);
    const identifierFilter = isObjectId
      ? { $or: [{ _id: rawIdentifier }, { slug: rawIdentifier.toLowerCase() }] }
      : { slug: rawIdentifier.toLowerCase() };

    const article = await Learning.findOne({
      ...identifierFilter,
      type: { $in: ["article", "Articles"] },
      status: "published",
    }).lean();

    if (!article) {
      return res.status(404).json({ message: getMsg("articleNotFound", req) });
    }

    return res.status(200).json({
      article: toPublicArticleDetail(article),
      item: toPublicArticleDetail(article),
    });
  } catch (err) {
    console.error("Error in GET /api/articles/:identifier:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

export default router;
