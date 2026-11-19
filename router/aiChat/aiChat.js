import express from "express";
import axios from "axios";
import https from "https";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AiChatConversation } from "../../schema/aiChatMessage.js";
import { BlockedIps } from "../../schema/blockedIps.js";
import { checkIsBanned } from "../../middleware/spamProtection.js";
import { getMsg, getLang } from "../../utils/messages.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// Persistent HTTPS Keep-Alive Agent with IPv4 forced (family: 4) to prevent IPv6 DNS/connection stalls
const geminiHttpsAgent = new https.Agent({
  keepAlive: true,
  family: 4,
  maxSockets: 25,
  keepAliveMsecs: 30000,
});

// Load CV Knowledge Base JSON once at startup
const knowledgeFilePath = path.join(__dirname, "../../data/azizCvKnowledge.json");
let cvKnowledgeData = {};
try {
  const rawJson = fs.readFileSync(knowledgeFilePath, "utf-8");
  cvKnowledgeData = JSON.parse(rawJson);
} catch (err) {
  console.error("Failed to load azizCvKnowledge.json:", err.message);
}

// Pre-stringify compact founder profile once at startup for faster prompt processing
const COMPACT_FOUNDER_JSON = JSON.stringify(
  cvKnowledgeData.founder_profile || cvKnowledgeData
);

/**
 * Build the strict system prompt grounded exclusively in azizCvKnowledge.json
 */
const buildSystemInstructionText = (uiLang = "ar") => {
  return `أنت المساعد الشخصي للمؤسس في موقع الأكاديمية. أجب عن أسئلة الزوار بناءً على المعلومات المزودة لك فقط وبأسلوب احترافي وودود ومختصر جداً على قدر السؤال تماماً. إذا سُئلت عن معلومة غير موجودة في النص، اعتذر بلطف ووجه الزائر للتواصل عبر البريد الإلكتروني الرسمي a.nefzi@almostaqelaqademy.com

You are the personal AI assistant to the founder (Eng. Aziz Nefzi) on the Almostaqel Academy website. Answer visitors' questions strictly based ONLY on the provided JSON knowledge base in a concise, direct, professional, and friendly tone tailored precisely to what was asked. If asked about any information not present in the text or outside the scope of Aziz Nefzi and Almostaqel Academy, politely apologize and direct the visitor to contact via the official email: a.nefzi@almostaqelaqademy.com

STRICT RULES:
1. CONCISE & DIRECT (CRITICAL): Give brief, sharp, professional answers directly addressing ONLY the visitor's specific question (typically 2 to 4 crisp sentences or a few short bullet points). Do NOT dump the entire biography or unnecessary extra details unless the visitor explicitly asks for the full story or detailed breakdown.
2. GENERAL INTRO IDENTITY & C/C++ PLACEMENT RULE (CRITICAL): When the visitor asks general questions about Aziz (such as "من هو عزيز؟", "ماذا تعرف عن عزيز؟", "Who is Aziz?", "Tell me about Aziz", etc.), NEVER label him simply as a "web developer" ("مطور ويب"). Describe him strictly as a Software Engineer or Systems Engineer ("مهندس برمجيات" أو "مهندس أنظمة") and Founder of Almostaqel Academy without over-elaborating — and NEVER mention his technical foundation in C and C++ except at the VERY END of your answer.
3. WHAT AZIZ CAN BUILD RULE: Only when asked specifically about what Aziz can build, develop, or do, accurately mention his full scope: Desktop Applications, Mobile Applications, Web Applications, Scripts, and even Small Games (تطبيقات سطح المكتب، تطبيقات الموبايل، تطبيقات الويب، السكريبتات، وحتى الألعاب الصغيرة).
4. LOW-LEVEL PROGRAMMING GATING RULE (CRITICAL): Do NOT mention Aziz's preference for low-level programming (البرمجة منخفضة المستوى) at all UNLESS the visitor explicitly asks about his programming philosophy (فلسفته البرمجية) or his programming background (خلفيته البرمجية).
5. ADDITIONAL LIBRARIES & LANGUAGES GATING RULE (CRITICAL): Do NOT mention that Aziz knows many other libraries/technologies or has basic knowledge of other programming languages UNLESS the visitor explicitly asks deeper/exploratory questions such as "ماذا تعرف أكثر عن عزيز؟", "هل يعرف عزيز تقنيات أكثر؟", "ما هي اللغات البرمجية الأخرى التي يعرفها/يتقنها عزيز؟", "What else do you know about Aziz?", "Does Aziz know more technologies/languages?", or similar questions.
6. GROUNDING: ONLY use facts explicitly present in the JSON below. NEVER invent or guess external facts.
7. SCOPE: NEVER answer topics outside Eng. Aziz Nefzi and Almostaqel Academy. If out-of-scope, politely apologize in 1-2 sentences and direct them to a.nefzi@almostaqelaqademy.com.
8. LANGUAGE RULE: Detect the language of the visitor's latest message and ALWAYS reply in THAT exact language (even if the site UI language is ${uiLang} or previous messages were in another language).
9. LINKS FORMATTING RULE: Whenever you share any social media links or website links from the JSON, output each link strictly as a clean Markdown link using the exact URL from the JSON, like: [Facebook](URL) [Instagram](URL) [LinkedIn](URL) [GitHub](URL) [TikTok](URL) [YouTube](URL) — do NOT repeat the platform name before the Markdown link, because the UI automatically renders each link as a clickable badge with its icon and platform name.

FOUNDER DATA (JSON):
${COMPACT_FOUNDER_JSON}`;
};

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * 🛡️ SMART MULTI-TIER ANTI-SPAM & RATE LIMITING (Protects UX & Avoids False Bans)
 * ─────────────────────────────────────────────────────────────────────────────
 * - Tier 1 (Soft Cooldown): 2 seconds minimum between completed messages -> 429 warning (NO BAN).
 * - Tier 2 (Soft Conversational Limit): Max 12 completed messages per 1 minute -> 429 warning (NO BAN).
 *   * Network failures or retried messages with the same clientMessageId are NEVER counted!
 * - Tier 3 (Malicious Bot Flood Ban): Only if an automated attacker sends >= 45 raw requests
 *   within 60 seconds (impossible for a normal human typing/retrying) -> Device Ban in BlockedIps.
 */
const SOFT_WINDOW_MS = 60 * 1000; // 1 minute window for normal conversation pacing
const SOFT_MAX_MESSAGES_PER_MIN = 12; // 12 successful messages per minute before soft pause
const MIN_COOLDOWN_MS = 2000; // 2 seconds between consecutive messages

const FLOOD_WINDOW_MS = 60 * 1000; // 1 minute window for bot flood detection
const FLOOD_BAN_THRESHOLD = 45; // 45+ raw requests in 60s = automated bot attack

// deviceId -> Array of successful message timestamps
const successfulChatTracker = new Map();
// deviceId -> Array of raw request timestamps (excluding identical clientMessageId network retries)
const rawFloodTracker = new Map();
// deviceId -> Set of recent clientMessageIds (to avoid penalizing bad-internet retries)
const recentRetryIds = new Map();
// deviceId -> { isBanned: boolean, matchedOn?: string, errorCode?: string, checkedAt: number }
// Ensures MongoDB ban check happens ONLY ONCE on the first interaction per device session
const verifiedDeviceBans = new Map();
// `${deviceId}:${clientMessageId}` -> { reply: string, messageId: string, ts: number }
// In-memory idempotency cache so we don't block on MongoDB before calling Gemini
const completedRepliesCache = new Map();

// Normalized question cache -> { reply: string, modelUsed: string, ts: number }
// Pre-seeded with the 4 suggested questions (AR & EN) and common greetings for instant (<10ms) responses
const normalizeQuestionKey = (text) =>
  String(text || "")
    .toLowerCase()
    .replace(/[؟?!.,،؛"']/g, "")
    .replace(/\s+/g, " ")
    .trim();

const instantAnswerCache = new Map([
  [
    normalizeQuestionKey("ما هي مهارات عزيز التقنية الأساسية؟"),
    {
      reply:
        "يمتلك المهندس عزيز نفزي ترسانة تقنية قوية تجمع بين البرمجة منخفضة المستوى وتطوير التطبيقات المتكاملة:\n\n• **لغات البرمجة:** C, C++, JavaScript, Python\n• **تطوير الواجهات الأمامية (Frontend):** React.js, Next.js, Tailwind CSS\n• **تطوير الخلفية (Backend):** Node.js, Express.js, NestJS, Django, FastAPI\n• **تطوير تطبيقات الموبايل:** React Native\n• **قواعد البيانات:** MongoDB, PostgreSQL\n• **الأدوات والأمن السيبراني:** Git, GitHub, Burp Suite, Nmap\n• **المفاهيم الهندسية:** البرمجة منخفضة المستوى وأنظمة الحاسوب، إدارة الذاكرة وتحسين الأداء، معمارية البرمجيات، وتصميم واجهات RESTful APIs.",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("حدثني عن خلفية عزيز في البرمجة"),
    {
      reply:
        "بدأت رحلة المهندس عزيز نفزي في البرمجة من الصفر بتعلم أساسيات لغة **C** على هاتفه المحمول، وبعد البكالوريا عمل في مصنع لشراء أول حاسوب شخصي والانطلاق بعمق في علوم الحاسوب.\n\nبنى تأسيساً قوياً في **C و C++** وفهم أنظمة الحاسوب على المستوى المنخفض (**Low-Level**) متأثراً بـ **Casey Muratori** وفلسفة البرمجة الواعية بالأداء (إدارة الذاكرة، المؤشرات، العتاد، وتجنب التعقيد غير الضروري)، ثم توسع استراتيجياً إلى **JavaScript و Python** بخبرة تمتد لحوالي **4 سنوات** في تطوير تطبيقات الويب والموبايل وسطح المكتب والسكريبتات.",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("ما هي المشاريع والخدمات التي يقدمها؟"),
    {
      reply:
        "يطور المهندس عزيز نفزي حلولاً برمجية متنوعة تشمل:\n\n• **أكاديمية المستقل (Almostaqel Academy):** المنصة التعليمية المتكاملة التي أسسها وطوّرها (دورات، مشاريع عملية، تحديات برمجية، ومقالات تقنية).\n• **تطوير البرمجيات:** تطبيقات الويب (Web)، تطبيقات الموبايل (Mobile)، تطبيقات سطح المكتب (Desktop)، السكريبتات (Scripts)، وحتى الألعاب الصغيرة.\n• **الاستشارات التقنية:** مراجعة معمارية الكود وتحسين الأداء.\n\nيمكنك استعراض أعماله عبر:\n[GitHub](https://github.com/aziznefzi) [YouTube](https://youtube.com/@almostaqel_aqademy?si=hpxDFtJz-hYwcmiV) [Almostaqel Academy](https://www.almostaqelaqademy.com)\n\nللتواصل وطلب الخدمات: a.nefzi@almostaqelaqademy.com",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("كيف يمكنني التواصل مع عزيز؟"),
    {
      reply:
        "يسعد المهندس عزيز نفزي بتواصلك معه عبر القنوات والحسابات الرسمية التالية:\n\n• **البريد الإلكتروني الرسمي:** a.nefzi@almostaqelaqademy.com\n• **الهاتف:** +21694093873\n• **الموقع الجغرافي:** تونس، بن عروس\n\n**الروابط والمنصات الرسمية:**\n[Facebook](https://www.facebook.com/profile.php?id=61596644246184) [Instagram](https://www.instagram.com/almostaqelacademy?dmpr=MTgyazF6Z2JndmwwcQ==) [LinkedIn](https://www.linkedin.com/in/nefzi-aziz-3b223537a?utm_source=share_via&utm_content=profile&utm_medium=member_android) [GitHub](https://github.com/aziznefzi) [TikTok](https://www.tiktok.com/@almostaqel.academ?_r=1&_t=ZS-9BXSZ4INTvh) [YouTube](https://youtube.com/@almostaqel_aqademy?si=hpxDFtJz-hYwcmiV)",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("What are Aziz's core technical skills?"),
    {
      reply:
        "Eng. Aziz Nefzi has a strong technical skillset bridging low-level systems and modern full-stack engineering:\n\n• **Programming Languages:** C, C++, JavaScript, Python\n• **Frontend Development:** React.js, Next.js, Tailwind CSS\n• **Backend Development:** Node.js, Express.js, NestJS, Django, FastAPI\n• **Mobile Development:** React Native\n• **Databases:** MongoDB, PostgreSQL\n• **Tools & Security:** Git, GitHub, Burp Suite, Nmap\n• **Core Engineering Concepts:** Low-Level Programming & Computer Systems, Memory Management & Performance Optimization, OOP, RESTful API Design, and Software Architecture.",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("Tell me about Aziz's programming background"),
    {
      reply:
        "Eng. Aziz Nefzi started from scratch by learning **C** fundamentals on his mobile phone, and after his Baccalaureate worked in a factory to buy his first PC and dive deeply into computer science.\n\nHe built a strong low-level foundation in **C and C++** inspired by **Casey Muratori** and Performance-Aware Programming (memory management, CPU/cache awareness, and avoiding unnecessary complexity), then strategically expanded into **JavaScript and Python**—bringing ~4 years of experience building web, mobile, desktop applications, and scripts.",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("What projects and services does he offer?"),
    {
      reply:
        "Eng. Aziz Nefzi builds diverse software solutions and services:\n\n• **Almostaqel Academy:** The comprehensive educational platform he founded and built (courses, practical projects, coding challenges, and technical articles).\n• **Software Development:** Desktop applications, mobile applications, web applications, scripts, and small games.\n• **Technical Consultation:** Software architecture review and performance optimization.\n\nExplore his work here:\n[GitHub](https://github.com/aziznefzi) [YouTube](https://youtube.com/@almostaqel_aqademy?si=hpxDFtJz-hYwcmiV) [Almostaqel Academy](https://www.almostaqelaqademy.com)\n\nContact directly via: a.nefzi@almostaqelaqademy.com",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("How can I contact or hire Aziz?"),
    {
      reply:
        "You can contact or hire Eng. Aziz Nefzi through his official channels:\n\n• **Official Email:** a.nefzi@almostaqelaqademy.com\n• **Phone:** +21694093873\n• **Location:** Tunisia, Ben Arous\n\n**Official Links & Platforms:**\n[Facebook](https://www.facebook.com/profile.php?id=61596644246184) [Instagram](https://www.instagram.com/almostaqelacademy?dmpr=MTgyazF6Z2JndmwwcQ==) [LinkedIn](https://www.linkedin.com/in/nefzi-aziz-3b223537a?utm_source=share_via&utm_content=profile&utm_medium=member_android) [GitHub](https://github.com/aziznefzi) [TikTok](https://www.tiktok.com/@almostaqel.academ?_r=1&_t=ZS-9BXSZ4INTvh) [YouTube](https://youtube.com/@almostaqel_aqademy?si=hpxDFtJz-hYwcmiV)",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("hi"),
    {
      reply:
        "Hello! 👋 I'm Eng. Aziz Nefzi's personal AI assistant at Almostaqel Academy. How can I help you learn more about Aziz, his projects, Almostaqel Academy, or how to contact him?",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("hello"),
    {
      reply:
        "Hello! 👋 I'm Eng. Aziz Nefzi's personal AI assistant at Almostaqel Academy. Feel free to ask me anything about Aziz, Almostaqel Academy, his projects, or how to contact him!",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("مرحبا"),
    {
      reply:
        "أهلاً ومرحباً بك! 👋 أنا المساعد الشخصي للمهندس عزيز نفزي في أكاديمية المستقل. تفضل بسؤالي عن عزيز، أكاديمية المستقل، مشاريعه وخبراته، أو طرق التواصل معه!",
      modelUsed: "instant-cv-cache",
    },
  ],
  [
    normalizeQuestionKey("السلام عليكم"),
    {
      reply:
        "وعليكم السلام ورحمة الله وبركاته! 👋 أهلاً بك، أنا المساعد الشخصي للمهندس عزيز نفزي في أكاديمية المستقل. كيف يمكنني مساعدتك اليوم في التعرف على عزيز أو الأكاديمية أو طرق التواصل معه؟",
      modelUsed: "instant-cv-cache",
    },
  ],
]);

// Periodic memory cleanup every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamps] of successfulChatTracker.entries()) {
    const valid = timestamps.filter((t) => now - t < SOFT_WINDOW_MS * 2);
    if (valid.length === 0) successfulChatTracker.delete(key);
    else successfulChatTracker.set(key, valid);
  }
  for (const [key, timestamps] of rawFloodTracker.entries()) {
    const valid = timestamps.filter((t) => now - t < FLOOD_WINDOW_MS * 2);
    if (valid.length === 0) rawFloodTracker.delete(key);
    else rawFloodTracker.set(key, valid);
  }
  for (const [key, idMap] of recentRetryIds.entries()) {
    for (const [msgId, ts] of idMap.entries()) {
      if (now - ts > 5 * 60 * 1000) idMap.delete(msgId);
    }
    if (idMap.size === 0) recentRetryIds.delete(key);
  }
  for (const [cacheKey, val] of completedRepliesCache.entries()) {
    if (now - val.ts > 5 * 60 * 1000) completedRepliesCache.delete(cacheKey);
  }
}, 5 * 60 * 1000);

/**
 * Evaluate flood & soft rate limits for a deviceId.
 * Network retries with an already-seen clientMessageId are exempt from flood increments.
 */
const evaluateChatRateAndSpam = async ({ deviceId, email, ipAddress, clientMessageId }) => {
  const now = Date.now();

  // Check if this request is a network retry of an existing clientMessageId
  let isKnownRetry = false;
  if (clientMessageId) {
    let deviceRetryMap = recentRetryIds.get(deviceId);
    if (!deviceRetryMap) {
      deviceRetryMap = new Map();
      recentRetryIds.set(deviceId, deviceRetryMap);
    }
    if (deviceRetryMap.has(clientMessageId)) {
      isKnownRetry = true;
    } else {
      deviceRetryMap.set(clientMessageId, now);
    }
  }

  // 1. Bot Flood Protection (only counts non-retry raw requests)
  if (!isKnownRetry) {
    const floodTimestamps = (rawFloodTracker.get(deviceId) || []).filter(
      (t) => now - t < FLOOD_WINDOW_MS
    );
    floodTimestamps.push(now);
    rawFloodTracker.set(deviceId, floodTimestamps);

    if (floodTimestamps.length >= FLOOD_BAN_THRESHOLD) {
      const reasonText = `AI Chat Automated Spam Flood: ${floodTimestamps.length} requests within 60 seconds`;
      await BlockedIps.findOneAndUpdate(
        { deviceId },
        {
          $set: {
            deviceId,
            email: email || null,
            ipAddress: ipAddress || null,
            resson: reasonText,
            banneDate: new Date(),
            StateBan: "baned",
            banType: "device",
          },
          $inc: { BannedCount: 1 },
        },
        { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
      );
      verifiedDeviceBans.set(deviceId, {
        isBanned: true,
        matchedOn: "device",
        errorCode: "spamAttackBan",
        checkedAt: now,
      });
      return { status: "banned_flood" };
    }
  }

  // 2. Soft Pacing Check (based ONLY on completed/successful messages so bad internet never hurts the user)
  const completedTimestamps = (successfulChatTracker.get(deviceId) || []).filter(
    (t) => now - t < SOFT_WINDOW_MS
  );

  if (completedTimestamps.length > 0) {
    const lastMessageTime = completedTimestamps[completedTimestamps.length - 1];
    if (now - lastMessageTime < MIN_COOLDOWN_MS && !isKnownRetry) {
      return {
        status: "soft_cooldown",
        retryAfterSeconds: Math.ceil((MIN_COOLDOWN_MS - (now - lastMessageTime)) / 1000) || 2,
      };
    }
  }

  if (completedTimestamps.length >= SOFT_MAX_MESSAGES_PER_MIN) {
    const oldestInWindow = completedTimestamps[0];
    const retryAfterSeconds = Math.max(
      5,
      Math.ceil((SOFT_WINDOW_MS - (now - oldestInWindow)) / 1000)
    );
    return {
      status: "soft_rate_limit",
      retryAfterSeconds,
    };
  }

  return { status: "allowed" };
};

/**
 * Record a successful chat completion for soft rate pacing
 */
const recordSuccessfulChatMessage = (deviceId) => {
  const now = Date.now();
  const completedTimestamps = (successfulChatTracker.get(deviceId) || []).filter(
    (t) => now - t < SOFT_WINDOW_MS
  );
  completedTimestamps.push(now);
  successfulChatTracker.set(deviceId, completedTimestamps);
};

/**
 * Normalize conversation history so it strictly alternates user -> model -> user
 * (Prevents Gemini 400 Bad Request errors when previous messages failed or were retried)
 */
const buildNormalizedContents = (history, userMessage) => {
  const normalized = [];

  if (Array.isArray(history)) {
    const recentHistory = history.slice(-6);
    for (const turn of recentHistory) {
      if (!turn || typeof turn.text !== "string" || !turn.text.trim()) continue;
      const role = turn.sender === "user" ? "user" : "model";
      const text = turn.text.trim().slice(0, 800);

      // Gemini requires the first turn in contents to be "user"
      if (normalized.length === 0 && role !== "user") {
        continue;
      }

      // If consecutive turns have the same role, keep the most recent one
      if (normalized.length > 0 && normalized[normalized.length - 1].role === role) {
        normalized[normalized.length - 1].parts = [{ text }];
      } else {
        normalized.push({
          role,
          parts: [{ text }],
        });
      }
    }
  }

  // Ensure the turn before our new userMessage is "model" (if history ended with "user", drop that dangling user turn)
  if (normalized.length > 0 && normalized[normalized.length - 1].role === "user") {
    normalized.pop();
  }

  normalized.push({
    role: "user",
    parts: [{ text: userMessage }],
  });

  return normalized;
};

/**
 * Call Google Gemini API on Generative Language v1beta with low-latency configuration
 */
const generateGeminiReply = async ({ userMessage, history = [], lang = "ar" }) => {
  // 1. Check Instant Answer Cache first (< 5ms response for suggested questions, greetings & previously asked standalone questions)
  const normKey = normalizeQuestionKey(userMessage);
  if (normKey && instantAnswerCache.has(normKey)) {
    const cachedAns = instantAnswerCache.get(normKey);
    return {
      reply: cachedAns.reply,
      modelUsed: cachedAns.modelUsed || "instant-cv-cache",
    };
  }

  const apiKey = (
    process.env.GIMINI_API_KEN ||
    process.env.GEMINI_API_KEY ||
    process.env.GIMINI_API_KEY ||
    process.env.GOOGLE_GEMINI_API_KEY ||
    ""
  ).trim();

  if (!apiKey) {
    throw new Error("MISSING_GEMINI_API_KEY");
  }

  const systemText = buildSystemInstructionText(lang);
  const contents = buildNormalizedContents(history, userMessage);

  // Model configurations ordered by speed & availability
  const modelConfigs = [
    {
      model: "gemini-3.5-flash-lite",
      thinkingConfig: { thinkingLevel: "MINIMAL" },
      timeout: 9000,
    },
    {
      model: "gemini-3.1-flash-lite",
      thinkingConfig: null,
      timeout: 9000,
    },
    {
      model: "gemini-3.8-flash",
      thinkingConfig: null,
      timeout: 10000,
    },
  ];

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const MAX_SERVER_RETRIES = 3; // 1 initial attempt + 3 automatic retries from server to Google Gemini
  let lastError = null;

  for (let retryIndex = 0; retryIndex <= MAX_SERVER_RETRIES; retryIndex++) {
    if (retryIndex > 0) {
      // Short progressive backoff before each retry (500ms, 1000ms, 1500ms)
      await sleep(retryIndex * 500);
    }

    // Pick primary fast model first; on later retries also rotate through fallback models
    const modelsThisPass =
      retryIndex === 0
        ? [modelConfigs[0]]
        : modelConfigs;

    for (const cfg of modelsThisPass) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${cfg.model}:generateContent?key=${encodeURIComponent(apiKey)}`;
      const payload = {
        systemInstruction: {
          parts: [{ text: systemText }],
        },
        contents,
        generationConfig: {
          temperature: 0.2,
          topP: 0.85,
          maxOutputTokens: 500,
          ...(cfg.thinkingConfig ? { thinkingConfig: cfg.thinkingConfig } : {}),
        },
      };

      try {
        const response = await axios.post(url, payload, {
          headers: { "Content-Type": "application/json" },
          httpsAgent: geminiHttpsAgent,
          timeout: cfg.timeout,
        });

        const parts = response.data?.candidates?.[0]?.content?.parts || [];
        const candidateText =
          parts
            .filter((p) => !p.thought)
            .map((p) => p.text || "")
            .join("")
            .trim() ||
          parts
            .map((p) => p.text || "")
            .join("")
            .trim();

        if (candidateText) {
          // Cache standalone answers in memory so future visitors asking the same question get a <5ms response
          if (normKey && normKey.length >= 4 && (!Array.isArray(history) || history.length <= 2)) {
            if (instantAnswerCache.size < 300) {
              instantAnswerCache.set(normKey, {
                reply: candidateText,
                modelUsed: cfg.model,
              });
            }
          }
          return {
            reply: candidateText,
            modelUsed: cfg.model,
          };
        }
      } catch (err) {
        lastError = err;
        const status = err.response?.status;

        // If the API key itself is invalid (401/403), don't waste retries
        if (status === 401 || status === 403) {
          throw err;
        }

        // If local DNS/connection is completely offline, let the outer retry loop wait briefly before retrying
        if (err.code === "ENOTFOUND" || err.code === "ECONNREFUSED") {
          break;
        }
      }
    }
  }

  throw lastError || new Error("GEMINI_API_FAILED");
};

/**
 * GET /api/ai-chat/init (and legacy alias /api/ai-chat/check-ban)
 * Called ONCE when the user enters the chatbot for the first time:
 * 1) Checks if the deviceId is banned in BlockedIps.
 * 2) If banned -> returns 403 { banned: true, errorCode, message }.
 * 3) If NOT banned -> fetches the device's saved conversation (if any) by deviceId (without userId) and returns it so the frontend caches it in sessionStorage.
 */
const handleInitOrCheckBan = async (req, res) => {
  try {
    const deviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.query?.deviceId ||
      req.body?.deviceId;
    const clientIp =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      req.ip;

    if (!deviceId || !String(deviceId).trim()) {
      return res.status(400).json({
        banned: false,
        messages: [],
        message: getMsg("deviceIdRequired", req),
      });
    }

    const cleanDeviceId = String(deviceId).trim();

    // Check ban status in DB (and refresh cache on initial entry so fresh bans take effect)
    const banCheck = await checkIsBanned({
      deviceId: cleanDeviceId,
      ipAddress: clientIp,
    });

    const errKey = "devicePermanentBan";
    const banStatus = {
      isBanned: Boolean(banCheck.isBanned),
      matchedOn: banCheck.matchedOn || "device",
      errorCode: errKey,
      checkedAt: Date.now(),
    };
    verifiedDeviceBans.set(cleanDeviceId, banStatus);

    if (banStatus.isBanned) {
      return res.status(403).json({
        banned: true,
        matchedOn: banStatus.matchedOn,
        errorCode: errKey,
        message: getMsg(errKey, req),
        messages: [],
      });
    }

    // Device is NOT banned -> Fetch this device's saved conversation (if it exists)
    const conversation = await AiChatConversation.findOne({
      deviceId: cleanDeviceId,
    }).lean();

    const formattedMessages = Array.isArray(conversation?.messages)
      ? conversation.messages.map((m) => ({
          id: m._id ? String(m._id) : m.clientMessageId || `${m.sender}-${Date.now()}`,
          clientMessageId: m.clientMessageId || null,
          sender: m.sender,
          text: m.text,
          createdAt: m.createdAt || new Date().toISOString(),
        }))
      : [];

    return res.status(200).json({
      banned: false,
      messages: formattedMessages,
    });
  } catch (err) {
    console.error("Error in /api/ai-chat/init:", err.message);
    return res.status(500).json({
      banned: false,
      messages: [],
      message: getMsg("serverError", req),
    });
  }
};

router.all("/ai-chat/init", handleInitOrCheckBan);
router.all("/ai-chat/check-ban", handleInitOrCheckBan);

/**
 * DELETE /api/ai-chat/history
 * Permanently deletes the conversation document stored for this deviceId (without userId) from MongoDB
 */
router.delete("/ai-chat/history", async (req, res) => {
  try {
    const deviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.query?.deviceId ||
      req.body?.deviceId;

    if (!deviceId || !String(deviceId).trim()) {
      return res.status(400).json({ message: getMsg("deviceIdRequired", req) });
    }

    const cleanDeviceId = String(deviceId).trim();
    const cachedBan = verifiedDeviceBans.get(cleanDeviceId);
    if (cachedBan?.isBanned) {
      return res.status(403).json({
        banned: true,
        errorCode: cachedBan.errorCode || "devicePermanentBan",
        message: getMsg(cachedBan.errorCode || "devicePermanentBan", req),
      });
    }

    await AiChatConversation.deleteOne({ deviceId: cleanDeviceId });

    // Also remove any in-memory deduplicated replies belonging to this deviceId
    const prefix = `${cleanDeviceId}:`;
    for (const key of completedRepliesCache.keys()) {
      if (key.startsWith(prefix)) {
        completedRepliesCache.delete(key);
      }
    }

    return res.status(200).json({
      success: true,
      message: getMsg("aiChatClearedSuccess", req),
    });
  } catch (err) {
    console.error("Error in DELETE /api/ai-chat/history:", err.message);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
});

/**
 * POST /api/ai-chat
 * Main endpoint: uses cached device ban status (checked on first entry), applies anti-spam,
 * queries Google Gemini, and appends the exchange to this deviceId's dedicated conversation in MongoDB (no userId).
 */
router.post("/ai-chat", async (req, res) => {
  try {
    const {
      message,
      history,
      clientMessageId,
    } = req.body || {};

    const incomingDeviceId =
      req.headers["x-device-id"] ||
      req.headers["device-id"] ||
      req.body?.deviceId;

    const clientIp =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      req.ip;

    // 1. Enforce Device ID requirement (Rule 1)
    if (!incomingDeviceId || !String(incomingDeviceId).trim()) {
      return res.status(400).json({
        message: getMsg("deviceIdRequired", req),
      });
    }

    const cleanDeviceId = String(incomingDeviceId).trim();
    const resolvedLang = getLang(req);

    // 2. First-Time-Only Device Ban Check (Cached in memory after /init or first check so subsequent messages don't hit DB)
    let banStatus = verifiedDeviceBans.get(cleanDeviceId);
    if (!banStatus) {
      const banCheck = await checkIsBanned({
        deviceId: cleanDeviceId,
        ipAddress: clientIp,
      });

      const errKey = "devicePermanentBan";

      banStatus = {
        isBanned: Boolean(banCheck.isBanned),
        matchedOn: banCheck.matchedOn || "device",
        errorCode: errKey,
        checkedAt: Date.now(),
      };
      verifiedDeviceBans.set(cleanDeviceId, banStatus);
    }

    if (banStatus.isBanned) {
      const errKey = banStatus.errorCode || "devicePermanentBan";
      return res.status(403).json({
        banned: true,
        matchedOn: banStatus.matchedOn,
        errorCode: errKey,
        message: getMsg(errKey, req),
      });
    }

    // 3. Validate Message Content
    if (!message || typeof message !== "string" || !message.trim()) {
      return res.status(400).json({
        errorCode: "aiChatEmptyMessage",
        message: getMsg("aiChatEmptyMessage", req),
      });
    }

    const cleanMessage = message.trim();
    if (cleanMessage.length > 1000) {
      return res.status(400).json({
        errorCode: "aiChatMessageTooLong",
        message: getMsg("aiChatMessageTooLong", req),
      });
    }

    const cleanClientMsgId = clientMessageId
      ? String(clientMessageId).trim().slice(0, 80)
      : null;

    // 4. Fast In-Memory Bad-Internet Idempotency Check (0ms, no DB round-trip blocking):
    const dedupKey = cleanClientMsgId ? `${cleanDeviceId}:${cleanClientMsgId}` : null;
    if (dedupKey && completedRepliesCache.has(dedupKey)) {
      const cached = completedRepliesCache.get(dedupKey);
      return res.status(200).json({
        success: true,
        reply: cached.reply,
        messageId: cached.messageId,
        clientMessageId: cleanClientMsgId,
        deduplicated: true,
      });
    }

    // 5. Evaluate Smart Multi-Tier Anti-Spam & Soft Rate Pacing (strictly by deviceId)
    const rateEval = await evaluateChatRateAndSpam({
      deviceId: cleanDeviceId,
      email: null,
      ipAddress: clientIp,
      clientMessageId: cleanClientMsgId,
    });

    if (rateEval.status === "banned_flood") {
      return res.status(403).json({
        banned: true,
        matchedOn: "device",
        errorCode: "spamAttackBan",
        message: getMsg("spamAttackBan", req),
      });
    }

    if (rateEval.status === "soft_cooldown") {
      return res.status(429).json({
        cooldown: true,
        errorCode: "aiChatCooldown",
        retryAfterSeconds: rateEval.retryAfterSeconds,
        message: getMsg("aiChatCooldown", req),
      });
    }

    if (rateEval.status === "soft_rate_limit") {
      return res.status(429).json({
        rateLimited: true,
        errorCode: "aiChatRateLimitSoft",
        retryAfterSeconds: rateEval.retryAfterSeconds,
        message: getMsg("aiChatRateLimitSoft", req),
      });
    }

    // 6. Query Google Gemini Immediately (Zero blocking MongoDB queries before calling Gemini!)
    try {
      const geminiResult = await generateGeminiReply({
        userMessage: cleanMessage,
        history,
        lang: resolvedLang,
      });

      // Record against the user's conversational rate limit after a successful reply
      recordSuccessfulChatMessage(cleanDeviceId);

      const nowDate = new Date();
      const generatedMsgId = `ai-${nowDate.getTime()}`;
      if (dedupKey) {
        completedRepliesCache.set(dedupKey, {
          reply: geminiResult.reply,
          messageId: generatedMsgId,
          ts: nowDate.getTime(),
        });
      }

      // 7. Append User Message & AI Reply to this Device's dedicated conversation in MongoDB (strictly by deviceId, NO userId)
      const userEntry = {
        clientMessageId: cleanClientMsgId,
        sender: "user",
        text: cleanMessage,
        lang: resolvedLang,
        createdAt: nowDate,
      };
      const aiEntry = {
        clientMessageId: cleanClientMsgId,
        sender: "ai",
        text: geminiResult.reply,
        lang: resolvedLang,
        modelUsed: geminiResult.modelUsed,
        createdAt: new Date(nowDate.getTime() + 1),
      };

      AiChatConversation.findOneAndUpdate(
        { deviceId: cleanDeviceId },
        {
          $set: { ipAddress: clientIp || null },
          $push: {
            messages: {
              $each: [userEntry, aiEntry],
              $slice: -200,
            },
          },
        },
        { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
      ).catch((dbSaveErr) => {
        console.error("Background AiChatConversation save error:", dbSaveErr.message);
      });

      return res.status(200).json({
        success: true,
        reply: geminiResult.reply,
        messageId: generatedMsgId,
        clientMessageId: cleanClientMsgId,
        createdAt: aiEntry.createdAt.toISOString(),
      });
    } catch (geminiErr) {
      console.error(
        "Gemini API error in /api/ai-chat:",
        geminiErr?.response?.data || geminiErr?.message
      );

      const isUpstreamNetworkErr =
        geminiErr?.code === "ENOTFOUND" ||
        geminiErr?.code === "ECONNREFUSED" ||
        geminiErr?.code === "ETIMEDOUT" ||
        geminiErr?.code === "ECONNABORTED" ||
        geminiErr?.message?.toLowerCase().includes("timeout") ||
        geminiErr?.message?.toLowerCase().includes("network");

      const errKey = isUpstreamNetworkErr
        ? "networkConnectionError"
        : "aiChatServiceUnavailable";

      return res.status(503).json({
        isNetworkError: true,
        canRetry: true,
        errorCode: errKey,
        message: getMsg(errKey, req),
      });
    }
  } catch (err) {
    console.error("Unexpected error in POST /api/ai-chat:", err);
    return res.status(500).json({
      message: getMsg("serverError", req),
    });
  }
});

export default router;
