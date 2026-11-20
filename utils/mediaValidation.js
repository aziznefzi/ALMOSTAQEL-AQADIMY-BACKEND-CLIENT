/**
 * Centralized Server-Side External Media Validation & Normalization Utility
 * Supports external image CDNs (Cloudinary, Cloudflare R2, custom HTTPS),
 * external video hosting (Cloudflare Stream, Bunny Stream, Vimeo, YouTube, HLS/MP4),
 * and strict YouTube validation for Courses.
 *
 * Security guarantees:
 * - Never trusts frontend validation alone
 * - Rejects Base64/binary image data on new writes (keeps MongoDB lean)
 * - Blocks unsafe schemes (javascript:, data:, blob:, file:) & raw HTML injection
 * - Enforces HTTPS for external URLs and blocks private/loopback SSRF hosts
 * - Designed with a clean hook for future signed playback URLs / provider tokens
 */

export const IMAGE_PROVIDERS = [
  "cloudinary",
  "cloudflare_r2",
  "unsplash",
  "custom",
  "legacy",
];

export const VIDEO_PROVIDERS = [
  "cloudflare_stream",
  "bunny_stream",
  "vimeo",
  "youtube",
  "custom_hls",
  "custom",
  "legacy",
];

const BLOCKED_HOSTS_REGEX =
  /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+)$/i;

const stripHtmlText = (raw, maxLen = 200) => {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/\u0000/g, "")
    .replace(/<[^>]*>/g, "")
    .replace(/javascript\s*:/gi, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
};

const parseStrictHttpsUrl = (rawUrl, maxLength = 1000) => {
  if (typeof rawUrl !== "string") {
    return { valid: false, error: "URL must be a string." };
  }
  const trimmed = rawUrl.replace(/\u0000/g, "").trim();
  if (!trimmed) {
    return { valid: true, url: "" };
  }
  if (trimmed.length > maxLength) {
    return { valid: false, error: `URL exceeds maximum length of ${maxLength} characters.` };
  }
  if (/[<>"'`]/.test(trimmed)) {
    return { valid: false, error: "URL contains unsafe HTML characters." };
  }
  if (/^(data|javascript|vbscript|blob|file):/i.test(trimmed)) {
    return { valid: false, error: "Unsupported or unsafe URL scheme. Only HTTPS URLs are allowed." };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") {
      return { valid: false, error: "External media URLs must use HTTPS." };
    }
    if (BLOCKED_HOSTS_REGEX.test(parsed.hostname)) {
      return { valid: false, error: "Local or private network URLs are not allowed." };
    }
    return { valid: true, url: parsed.toString(), parsed };
  } catch {
    return { valid: false, error: "Invalid URL format." };
  }
};

export const detectImageProvider = (urlString) => {
  if (!urlString) return "";
  if (urlString.startsWith("/uploads/")) return "legacy";
  try {
    const { hostname } = new URL(urlString);
    const host = hostname.toLowerCase();
    if (host === "res.cloudinary.com" || host.endsWith(".cloudinary.com")) {
      return "cloudinary";
    }
    if (
      host.endsWith(".r2.dev") ||
      host.endsWith(".r2.cloudflarestorage.com") ||
      host === "imagedelivery.net" ||
      host.endsWith(".imagedelivery.net")
    ) {
      return "cloudflare_r2";
    }
    if (host === "images.unsplash.com" || host.endsWith(".unsplash.com")) {
      return "unsplash";
    }
    return "custom";
  } catch {
    return "custom";
  }
};

export const extractCloudinaryPublicId = (urlString) => {
  try {
    const parsed = new URL(urlString);
    if (!parsed.hostname.toLowerCase().includes("cloudinary.com")) return "";
    // Match /image/upload/(optional transforms)/(optional v12345)/(public_id).ext
    const match = parsed.pathname.match(
      /\/upload\/(?:[^/]+,[^/]+\/)*(?:v\d+\/)?(.+?)(?:\.[a-zA-Z0-9]+)?$/
    );
    return match?.[1] ? match[1].slice(0, 300) : "";
  } catch {
    return "";
  }
};

/**
 * Validate and normalize external image URL + optional metadata (`thumbnail`).
 * Rejects Base64 `data:` strings on new writes so MongoDB never stores image binaries.
 * Preserves existing legacy `/uploads/...` path ONLY when `allowExistingLegacyPath` is true
 * and the URL matches the document's existing legacy image path.
 */
export const validateAndNormalizeImageMedia = ({
  image,
  thumbnail,
  imageDataUrl,
  existingImage = "",
  allowExistingLegacyPath = false,
} = {}) => {
  // Reject new Base64 binary image submissions explicitly
  if (
    typeof imageDataUrl === "string" &&
    imageDataUrl.trim().startsWith("data:")
  ) {
    return {
      valid: false,
      errorCode: "noBase64ImagesAllowed",
      error:
        "Storing Base64 or binary image data in MongoDB is not allowed. Please upload the image to an external host (e.g. Cloudinary or Cloudflare R2) and provide its HTTPS URL.",
    };
  }

  const rawUrl =
    typeof thumbnail?.url === "string" && thumbnail.url.trim() !== ""
      ? thumbnail.url.trim()
      : typeof image === "string"
      ? image.trim()
      : "";

  if (rawUrl.startsWith("data:")) {
    return {
      valid: false,
      errorCode: "noBase64ImagesAllowed",
      error:
        "Storing Base64 or binary image data in MongoDB is not allowed. Please provide an external HTTPS image URL.",
    };
  }

  // Empty image is permitted (frontend uses fallback cover)
  if (!rawUrl) {
    return {
      valid: true,
      isLegacy: false,
      image: "",
      thumbnail: {
        url: "",
        provider: "",
        publicId: "",
        alt: stripHtmlText(thumbnail?.alt || "", 200),
      },
      clearLegacyDataUrl: true,
    };
  }

  // Transition backward compatibility: preserve unchanged legacy `/uploads/...` path on existing docs
  if (
    allowExistingLegacyPath &&
    rawUrl.startsWith("/uploads/") &&
    existingImage &&
    rawUrl === existingImage
  ) {
    return {
      valid: true,
      isLegacy: true,
      image: rawUrl,
      thumbnail: {
        url: rawUrl,
        provider: "legacy",
        publicId: "",
        alt: stripHtmlText(thumbnail?.alt || "", 200),
      },
      clearLegacyDataUrl: false,
    };
  }

  const urlCheck = parseStrictHttpsUrl(rawUrl, 1000);
  if (!urlCheck.valid) {
    return {
      valid: false,
      errorCode: "invalidImageUrl",
      error: `Invalid image URL: ${urlCheck.error}`,
    };
  }

  const detectedProvider = detectImageProvider(urlCheck.url);
  const requestedProvider =
    typeof thumbnail?.provider === "string" ? thumbnail.provider.trim().toLowerCase() : "";
  const provider =
    requestedProvider && IMAGE_PROVIDERS.includes(requestedProvider) && requestedProvider !== "legacy"
      ? requestedProvider
      : detectedProvider;

  const publicId =
    stripHtmlText(thumbnail?.publicId || "", 300) ||
    (provider === "cloudinary" ? extractCloudinaryPublicId(urlCheck.url) : "");

  return {
    valid: true,
    isLegacy: false,
    image: urlCheck.url,
    thumbnail: {
      url: urlCheck.url,
      provider,
      publicId,
      alt: stripHtmlText(thumbnail?.alt || "", 200),
    },
    // Switching to an external HTTPS URL clears any legacy Base64 data from MongoDB!
    clearLegacyDataUrl: true,
  };
};

/**
 * Strictly validate YouTube URLs for Courses and extract canonical 11-char ID & safe embed URL.
 */
export const validateYouTubeVideo = (rawUrl) => {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return {
      valid: false,
      errorCode: "invalidYoutubeUrl",
      error: "A valid YouTube video URL is required.",
    };
  }

  const trimmed = rawUrl.replace(/\u0000/g, "").trim();
  const urlCheck = parseStrictHttpsUrl(trimmed, 500);
  if (!urlCheck.valid) {
    return {
      valid: false,
      errorCode: "invalidYoutubeUrl",
      error: `Invalid YouTube URL: ${urlCheck.error}`,
    };
  }

  const { parsed } = urlCheck;
  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const allowedHosts = new Set([
    "youtube.com",
    "m.youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
  ]);

  if (!allowedHosts.has(host)) {
    return {
      valid: false,
      errorCode: "invalidYoutubeUrl",
      error:
        "Course lessons must use a valid YouTube URL (youtube.com/watch?v=..., youtu.be/..., youtube.com/embed/..., or youtube.com/shorts/...).",
    };
  }

  let youtubeId = "";
  if (host === "youtu.be") {
    youtubeId = parsed.pathname.replace(/^\/+/, "").split("/")[0] || "";
  } else if (parsed.pathname === "/watch") {
    youtubeId = parsed.searchParams.get("v") || "";
  } else {
    const pathMatch = parsed.pathname.match(/^\/(?:embed|shorts|live|v)\/([a-zA-Z0-9_-]{11})(?:\/|$)/);
    if (pathMatch?.[1]) {
      youtubeId = pathMatch[1];
    }
  }

  if (!/^[a-zA-Z0-9_-]{11}$/.test(youtubeId)) {
    return {
      valid: false,
      errorCode: "invalidYoutubeUrl",
      error: "Could not extract a valid 11-character YouTube video ID from the provided URL.",
    };
  }

  const embedUrl = `https://www.youtube-nocookie.com/embed/${youtubeId}`;
  const canonicalUrl = `https://www.youtube.com/watch?v=${youtubeId}`;

  return {
    valid: true,
    provider: "youtube",
    youtubeId,
    embedUrl,
    videoUrl: canonicalUrl,
  };
};

const detectVideoProviderFromUrl = (urlString) => {
  if (!urlString) return "";
  if (urlString.startsWith("/uploads/")) return "legacy";
  try {
    const { hostname, pathname } = new URL(urlString);
    const host = hostname.toLowerCase();
    if (
      host.includes("cloudflarestream.com") ||
      host.includes("videodelivery.net")
    ) {
      return "cloudflare_stream";
    }
    if (
      host.includes("mediadelivery.net") ||
      host.endsWith(".b-cdn.net") ||
      host.includes("bunnycdn.com")
    ) {
      return "bunny_stream";
    }
    if (host.includes("vimeo.com")) {
      return "vimeo";
    }
    if (
      host.includes("youtube.com") ||
      host === "youtu.be" ||
      host.includes("youtube-nocookie.com")
    ) {
      return "youtube";
    }
    if (pathname.toLowerCase().endsWith(".m3u8")) {
      return "custom_hls";
    }
    return "custom";
  } catch {
    return "custom";
  }
};

/**
 * Validate and normalize external regular educational video metadata (`videoMedia` + `videoUrl`).
 * Supports Cloudflare Stream, Bunny Stream, Vimeo, YouTube, Custom HLS (.m3u8), and Custom HTTPS video URLs.
 */
export const validateAndNormalizeVideoMedia = ({
  videoUrl,
  videoMedia,
  existingVideoUrl = "",
  allowExistingLegacyPath = false,
} = {}) => {
  const rawUrl =
    typeof videoMedia?.playbackUrl === "string" && videoMedia.playbackUrl.trim() !== ""
      ? videoMedia.playbackUrl.trim()
      : typeof videoUrl === "string"
      ? videoUrl.trim()
      : "";

  const rawVideoId = stripHtmlText(videoMedia?.videoId || "", 200);
  const rawLibraryId = stripHtmlText(videoMedia?.libraryId || "", 100);
  const requestedProvider =
    typeof videoMedia?.provider === "string"
      ? videoMedia.provider.trim().toLowerCase()
      : "";
  const isPrivate = Boolean(videoMedia?.isPrivate);
  const playbackStrategy = ["public", "signed_url", "provider_token"].includes(
    videoMedia?.playbackStrategy
  )
    ? videoMedia.playbackStrategy
    : isPrivate
    ? "signed_url"
    : "public";

  // Allow empty video (draft/preorder before video is attached)
  if (!rawUrl && !rawVideoId) {
    return {
      valid: true,
      videoUrl: "",
      videoMedia: {
        provider: requestedProvider && VIDEO_PROVIDERS.includes(requestedProvider) ? requestedProvider : "",
        videoId: "",
        libraryId: "",
        playbackUrl: "",
        isPrivate,
        playbackStrategy,
      },
    };
  }

  // Backward compatibility for unchanged legacy `/uploads/...` videos during transition
  if (
    allowExistingLegacyPath &&
    rawUrl.startsWith("/uploads/") &&
    existingVideoUrl &&
    rawUrl === existingVideoUrl
  ) {
    return {
      valid: true,
      videoUrl: rawUrl,
      videoMedia: {
        provider: "legacy",
        videoId: "",
        libraryId: "",
        playbackUrl: rawUrl,
        isPrivate: false,
        playbackStrategy: "public",
      },
    };
  }

  if (rawUrl && rawUrl.startsWith("/uploads/")) {
    return {
      valid: false,
      errorCode: "invalidVideoUrl",
      error:
        "Direct server video uploads are deprecated. Please host the video on Cloudflare Stream, Bunny Stream, Vimeo, YouTube, or an external HTTPS video CDN.",
    };
  }

  const provider =
    requestedProvider && VIDEO_PROVIDERS.includes(requestedProvider) && requestedProvider !== "legacy"
      ? requestedProvider
      : detectVideoProviderFromUrl(rawUrl) || "custom";

  // Provider-specific validation
  if (provider === "youtube") {
    const ytCheck = validateYouTubeVideo(rawUrl);
    if (!ytCheck.valid) return ytCheck;
    return {
      valid: true,
      videoUrl: ytCheck.videoUrl,
      videoMedia: {
        provider: "youtube",
        videoId: ytCheck.youtubeId,
        libraryId: "",
        playbackUrl: ytCheck.embedUrl,
        isPrivate: false,
        playbackStrategy: "public",
      },
    };
  }

  if (provider === "cloudflare_stream") {
    let videoId = rawVideoId;
    let playbackUrl = rawUrl;

    if (playbackUrl) {
      const urlCheck = parseStrictHttpsUrl(playbackUrl, 1000);
      if (!urlCheck.valid) {
        return {
          valid: false,
          errorCode: "invalidVideoUrl",
          error: `Invalid Cloudflare Stream URL: ${urlCheck.error}`,
        };
      }
      playbackUrl = urlCheck.url;
      if (!videoId) {
        const uidMatch = urlCheck.parsed.pathname.match(/\/([a-fA-F0-9]{32})(?:\/|$)/);
        if (uidMatch?.[1]) videoId = uidMatch[1];
      }
    }

    if (videoId && !/^[a-zA-Z0-9_-]{8,128}$/.test(videoId)) {
      return {
        valid: false,
        errorCode: "invalidVideoId",
        error: "Invalid Cloudflare Stream Video ID format.",
      };
    }

    if (!playbackUrl && videoId) {
      playbackUrl = `https://iframe.videodelivery.net/${videoId}`;
    }

    if (!playbackUrl) {
      return {
        valid: false,
        errorCode: "invalidVideoUrl",
        error: "Cloudflare Stream requires a valid Video ID or HTTPS Playback URL.",
      };
    }

    return {
      valid: true,
      videoUrl: playbackUrl,
      videoMedia: {
        provider: "cloudflare_stream",
        videoId,
        libraryId: "",
        playbackUrl,
        isPrivate,
        playbackStrategy,
      },
    };
  }

  if (provider === "bunny_stream") {
    let videoId = rawVideoId;
    let libraryId = rawLibraryId;
    let playbackUrl = rawUrl;

    if (playbackUrl) {
      const urlCheck = parseStrictHttpsUrl(playbackUrl, 1000);
      if (!urlCheck.valid) {
        return {
          valid: false,
          errorCode: "invalidVideoUrl",
          error: `Invalid Bunny Stream URL: ${urlCheck.error}`,
        };
      }
      playbackUrl = urlCheck.url;
      // Extract libraryId & videoId from https://iframe.mediadelivery.net/embed/{libraryId}/{videoId}
      const bunnyMatch = urlCheck.parsed.pathname.match(
        /\/(?:embed|play)\/(\d+)\/([a-zA-Z0-9-]{8,128})/
      );
      if (bunnyMatch) {
        if (!libraryId) libraryId = bunnyMatch[1];
        if (!videoId) videoId = bunnyMatch[2];
      }
    }

    if (libraryId && !/^\d{1,20}$/.test(libraryId)) {
      return {
        valid: false,
        errorCode: "invalidVideoId",
        error: "Bunny Stream Library ID must be numeric.",
      };
    }
    if (videoId && !/^[a-zA-Z0-9-]{8,128}$/.test(videoId)) {
      return {
        valid: false,
        errorCode: "invalidVideoId",
        error: "Invalid Bunny Stream Video ID format.",
      };
    }

    if (!playbackUrl && libraryId && videoId) {
      playbackUrl = `https://iframe.mediadelivery.net/embed/${libraryId}/${videoId}`;
    }

    if (!playbackUrl) {
      return {
        valid: false,
        errorCode: "invalidVideoUrl",
        error:
          "Bunny Stream requires either an HTTPS Playback/Embed URL or both Library ID and Video ID.",
      };
    }

    return {
      valid: true,
      videoUrl: playbackUrl,
      videoMedia: {
        provider: "bunny_stream",
        videoId,
        libraryId,
        playbackUrl,
        isPrivate,
        playbackStrategy,
      },
    };
  }

  if (provider === "vimeo") {
    const urlCheck = parseStrictHttpsUrl(rawUrl, 500);
    if (!urlCheck.valid) {
      return {
        valid: false,
        errorCode: "invalidVideoUrl",
        error: `Invalid Vimeo URL: ${urlCheck.error}`,
      };
    }
    const vimeoMatch = urlCheck.url.match(/vimeo\.com\/(?:video\/)?(\d+)/);
    const vimeoId = rawVideoId || vimeoMatch?.[1] || "";
    if (!/^\d{4,20}$/.test(vimeoId)) {
      return {
        valid: false,
        errorCode: "invalidVideoId",
        error: "Invalid Vimeo video URL or numeric Video ID.",
      };
    }
    const embedUrl = `https://player.vimeo.com/video/${vimeoId}`;
    return {
      valid: true,
      videoUrl: embedUrl,
      videoMedia: {
        provider: "vimeo",
        videoId: vimeoId,
        libraryId: "",
        playbackUrl: embedUrl,
        isPrivate,
        playbackStrategy,
      },
    };
  }

  // custom_hls / custom
  const urlCheck = parseStrictHttpsUrl(rawUrl, 1000);
  if (!urlCheck.valid) {
    return {
      valid: false,
      errorCode: "invalidVideoUrl",
      error: `Invalid video playback URL: ${urlCheck.error}`,
    };
  }

  const finalProvider =
    provider === "custom_hls" || urlCheck.parsed.pathname.toLowerCase().endsWith(".m3u8")
      ? "custom_hls"
      : "custom";

  return {
    valid: true,
    videoUrl: urlCheck.url,
    videoMedia: {
      provider: finalProvider,
      videoId: rawVideoId,
      libraryId: "",
      playbackUrl: urlCheck.url,
      isPrivate,
      playbackStrategy,
    },
  };
};

/**
 * Extensible hook for private video playback (signed URLs / provider tokens).
 * Keeps provider signing secrets strictly on the backend.
 * When `isPrivate` is false (default), returns the validated public playback metadata.
 * To enable signed playback in the future, plug Cloudflare Stream JWT or Bunny Stream
 * SHA-256 token signing here using environment secrets without changing routes or React UI.
 */
export const resolveVideoPlaybackForUser = (item) => {
  const vm = item?.videoMedia || {};
  const playbackUrl = vm.playbackUrl || item?.videoUrl || "";
  const provider = vm.provider || detectVideoProviderFromUrl(playbackUrl);
  return {
    provider,
    videoId: vm.videoId || "",
    libraryId: vm.libraryId || "",
    playbackUrl,
    isPrivate: Boolean(vm.isPrivate),
    playbackStrategy: vm.playbackStrategy || "public",
  };
};
