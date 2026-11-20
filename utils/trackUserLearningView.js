import mongoose from "mongoose";
import { Users } from "../schema/users.js";

const MAX_RECENT_HISTORY = 500;

export const classifyLearningCategory = (rawType) => {
  const lower = String(rawType || "").toLowerCase().trim();
  if (lower.includes("article")) return "article";
  if (lower.includes("video") || lower.includes("vidio") || lower.includes("project")) {
    return "video";
  }
  return "course";
};

/**
 * Safely record a unique learning item view for an authenticated user.
 * - Deduplicates itemId per category in `learningActivity.viewedArticles|viewedVideos|viewedCourses`
 * - Maintains a capped `recentHistory` list (latest 12 items) with `lastViewedAt` and `viewsCount`
 * - Never throws into the caller so content viewing is never disrupted
 */
export const recordUserLearningView = async (userId, itemId, rawType) => {
  try {
    if (!userId || !itemId) return;
    if (!mongoose.isValidObjectId(userId) || !mongoose.isValidObjectId(itemId)) return;

    const category = classifyLearningCategory(rawType);
    const fieldMap = {
      article: "learningActivity.viewedArticles",
      video: "learningActivity.viewedVideos",
      course: "learningActivity.viewedCourses",
    };
    const targetArrayField = fieldMap[category];
    const objItemId = new mongoose.Types.ObjectId(itemId);
    const now = new Date();

    // 1. Add unique itemId to category set
    await Users.updateOne(
      { _id: userId },
      { $addToSet: { [targetArrayField]: objItemId } }
    );

    // 2. Try incrementing existing entry in recentHistory
    const incRes = await Users.updateOne(
      { _id: userId, "learningActivity.recentHistory.itemId": objItemId },
      {
        $set: {
          "learningActivity.recentHistory.$.lastViewedAt": now,
          "learningActivity.recentHistory.$.category": category,
        },
        $inc: { "learningActivity.recentHistory.$.viewsCount": 1 },
      }
    );

    // 3. If not yet in recentHistory, push and sort/slice to keep latest 12
    if (!incRes.matchedCount) {
      await Users.updateOne(
        { _id: userId },
        {
          $push: {
            "learningActivity.recentHistory": {
              $each: [
                {
                  itemId: objItemId,
                  category,
                  lastViewedAt: now,
                  viewsCount: 1,
                },
              ],
              $sort: { lastViewedAt: -1 },
              $slice: MAX_RECENT_HISTORY,
            },
          },
        }
      );
    }
  } catch (err) {
    console.warn("recordUserLearningView warning:", err.message);
  }
};
