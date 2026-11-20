/**
 * Legacy Media Migration Audit & Cleanup Utility
 *
 * Usage (from backend/Client/):
 *   node scripts/auditLegacyMedia.js                -> Read-only audit report (safe, no writes)
 *   node scripts/auditLegacyMedia.js --strip-migrated -> Clears legacy `imageDataUrl` ONLY on docs
 *                                                        that ALREADY have a valid external HTTPS URL!
 *
 * Never deletes legacy imageDataUrl from items that have not yet been migrated to an external host.
 */
import "dotenv/config";
import dns from "dns";
dns.setDefaultResultOrder("ipv4first");
import mongoose from "mongoose";
import { Learning } from "../schema/learning.js";
import { detectImageProvider, extractCloudinaryPublicId } from "../utils/mediaValidation.js";

const stripMigrated = process.argv.includes("--strip-migrated");

async function main() {
  if (!process.env.MONGODB_URL) {
    console.error("MONGODB_URL is not configured in .env");
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGODB_URL, { family: 4 });
  const docs = await Learning.find({})
    .select("_id type title image thumbnail imageDataUrl videoUrl videoMedia courseVideos")
    .lean();

  const summary = {
    total: docs.length,
    externalImages: 0,
    legacyImagesNeedingMigration: [],
    migratedStillHoldingBase64: [],
    legacyLocalVideos: [],
    nonYoutubeCourseLessons: [],
  };

  for (const doc of docs) {
    const imgUrl = String(doc.thumbnail?.url || doc.image || "").trim();
    const hasBase64 = typeof doc.imageDataUrl === "string" && doc.imageDataUrl.startsWith("data:");
    const isExternalHttps = imgUrl.startsWith("https://");

    if (isExternalHttps) {
      summary.externalImages += 1;
      if (hasBase64) {
        summary.migratedStillHoldingBase64.push({
          id: String(doc._id),
          type: doc.type,
          title: doc.title,
          image: imgUrl,
          base64KB: Math.round(doc.imageDataUrl.length / 1024),
        });
      }
    } else if (hasBase64 || imgUrl.startsWith("/uploads/")) {
      summary.legacyImagesNeedingMigration.push({
        id: String(doc._id),
        type: doc.type,
        title: doc.title,
        image: imgUrl || "(base64 only)",
        hasBase64,
        base64KB: hasBase64 ? Math.round(doc.imageDataUrl.length / 1024) : 0,
      });
    }

    const vidUrl = String(doc.videoMedia?.playbackUrl || doc.videoUrl || "").trim();
    if (vidUrl.startsWith("/uploads/")) {
      summary.legacyLocalVideos.push({
        id: String(doc._id),
        type: doc.type,
        title: doc.title,
        videoUrl: vidUrl,
      });
    }

    if (Array.isArray(doc.courseVideos)) {
      for (const lesson of doc.courseVideos) {
        const lUrl = String(lesson.videoUrl || "");
        if (lUrl && !/(youtube\.com|youtu\.be|youtube-nocookie\.com)/i.test(lUrl)) {
          summary.nonYoutubeCourseLessons.push({
            courseId: String(doc._id),
            courseTitle: doc.title,
            lessonTitle: lesson.title,
            videoUrl: lUrl,
          });
        }
      }
    }
  }

  console.log("\n=== ALMOSTAQEL ACADEMY MEDIA MIGRATION AUDIT ===");
  console.log(`Total Learning documents: ${summary.total}`);
  console.log(`Already using external HTTPS images: ${summary.externalImages}`);
  console.log(`Legacy images needing external URL migration: ${summary.legacyImagesNeedingMigration.length}`);
  console.log(`Migrated items still holding redundant Base64: ${summary.migratedStillHoldingBase64.length}`);
  console.log(`Legacy local /uploads/ videos needing migration: ${summary.legacyLocalVideos.length}`);
  console.log(`Non-YouTube course lessons: ${summary.nonYoutubeCourseLessons.length}\n`);

  if (summary.legacyImagesNeedingMigration.length > 0) {
    console.log("Items to migrate (upload cover to Cloudinary / R2 and paste URL in Admin Dashboard):");
    console.table(summary.legacyImagesNeedingMigration);
  }

  if (stripMigrated && summary.migratedStillHoldingBase64.length > 0) {
    for (const item of summary.migratedStillHoldingBase64) {
      await Learning.updateOne(
        { _id: item.id },
        {
          $set: {
            imageDataUrl: "",
            thumbnail: {
              url: item.image,
              provider: detectImageProvider(item.image),
              publicId: extractCloudinaryPublicId(item.image),
              alt: item.title || "",
            },
          },
        }
      );
    }
    console.log(
      `Cleaned redundant Base64 imageDataUrl from ${summary.migratedStillHoldingBase64.length} already-migrated document(s).`
    );
  }

  await mongoose.disconnect();
}

main().catch((err) => {
  console.error("Audit script failed:", err);
  process.exit(1);
});
