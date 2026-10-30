import express from "express";
import { Learning } from "../../../schema/learning.js";
import { AdminAuth } from "../../Auth/Madlware.js";

const router = express.Router();

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "title", "price", "enrollments", "rating"];
const ALLOWED_STATUS_FILTERS = ["all", "published", "draft", "archived"];

const formatCourseDoc = (doc) => {
  const obj = typeof doc.toObject === "function" ? doc.toObject() : doc;
  const videos = Array.isArray(obj.courseVideos)
    ? obj.courseVideos.map((v) => ({ ...v, id: v._id }))
    : [];
  return {
    ...obj,
    id: obj._id,
    courseVideos: videos,
    lessons: videos.length > 0 ? videos.length : obj.lessons || 0,
  };
};

// ============================================================================
// 1. GET & POST /admin/learning/courses - Fetch Paginated Courses
// ============================================================================
const handleGetCourses = async (req, res) => {
  try {
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawSearch = req.query.search ?? req.body?.search;
    const rawStatus = req.query.status ?? req.body?.status ?? req.query.filter ?? req.body?.filter;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1 ? Math.min(parsedLimit, 100) : 50;
    const skip = (page - 1) * limit;

    const query = { type: { $in: ["course", "Courses"] } };

    if (rawStatus && ALLOWED_STATUS_FILTERS.includes(rawStatus) && rawStatus !== "all") {
      query.status = rawStatus;
    }

    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        query.$or = [
          { title: regex },
          { titleAr: regex },
          { description: regex },
          { descriptionAr: regex },
          { instructor: regex },
          { category: regex },
          { tag: regex },
        ];
      }
    }

    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;

    const [total, items] = await Promise.all([
      Learning.countDocuments(query),
      Learning.find(query)
        .sort({ [sortField]: sortOrder })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const totalPages = Math.max(1, Math.ceil(total / limit));

    res.status(200).json({
      items: items.map(formatCourseDoc),
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
    console.error("Error in handleGetCourses:", err);
    res.status(500).json({ message: "Failed to fetch courses" });
  }
};

router.get("/learning/courses", AdminAuth, handleGetCourses);
router.post("/learning/courses/list", AdminAuth, handleGetCourses);

// ============================================================================
// 2. GET /admin/learning/courses/:id - Get Single Course Details & Videos
// ============================================================================
router.get("/learning/courses/:id", AdminAuth, async (req, res) => {
  try {
    const course = await Learning.findById(req.params.id).lean();
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
    res.status(200).json({ item: formatCourseDoc(course) });
  } catch (err) {
    console.error("Error in GET /learning/courses/:id:", err);
    res.status(500).json({ message: "Failed to fetch course details" });
  }
});

// ============================================================================
// 3. POST /admin/learning/courses - Create Course
// ============================================================================
router.post("/learning/courses", AdminAuth, async (req, res) => {
  try {
    const {
      title,
      titleAr,
      description,
      descriptionAr,
      category,
      tag,
      level,
      levelAr,
      instructor,
      instructorAr,
      duration,
      hours,
      lessons,
      price,
      priceAfter,
      status,
      image,
      imageDataUrl,
      stack,
      rating,
      courseVideos,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "Course title is required" });
    }

    const validVideos = Array.isArray(courseVideos)
      ? courseVideos
          .filter((v) => v && v.title && v.videoUrl)
          .map((v, idx) => ({
            title: String(v.title).trim(),
            titleAr: String(v.titleAr || "").trim(),
            description: String(v.description || "").trim(),
            videoUrl: String(v.videoUrl).trim(),
            duration: String(v.duration || "0:00").trim(),
            order: idx + 1,
          }))
      : [];

    const newCourse = await Learning.create({
      type: "course",
      title: title.trim(),
      titleAr: titleAr?.trim() || "",
      description: description?.trim() || "",
      descriptionAr: descriptionAr?.trim() || "",
      category: category?.trim() || "Web Development",
      tag: tag?.trim() || category?.trim() || "General",
      level: ["Beginner", "Intermediate", "Advanced"].includes(level) ? level : "Beginner",
      levelAr:
        levelAr?.trim() ||
        (level === "Advanced" ? "متقدم" : level === "Intermediate" ? "متوسط" : "مبتدئ"),
      instructor: instructor?.trim() || "",
      instructorAr: instructorAr?.trim() || "",
      duration: duration?.trim() || (hours ? `${hours}h` : "0h"),
      hours: Number(hours) || 0,
      lessons: validVideos.length || Number(lessons) || 0,
      price: Number(price) || 0,
      priceAfter: priceAfter !== undefined ? Number(priceAfter) : Number(price) || 0,
      status: ["published", "draft", "archived"].includes(status) ? status : "published",
      rating: Number(rating) || 5.0,
      image: image?.trim() || "",
      imageDataUrl: imageDataUrl || "",
      courseVideos: validVideos,
      stack: Array.isArray(stack) ? stack : [],
    });

    res.status(201).json({
      message: "Course created successfully",
      item: formatCourseDoc(newCourse),
    });
  } catch (err) {
    console.error("Error in POST /learning/courses:", err);
    res.status(500).json({ message: "Failed to create course" });
  }
});

// ============================================================================
// 4. PUT /admin/learning/courses/:id - Update Course
// ============================================================================
router.put("/learning/courses/:id", AdminAuth, async (req, res) => {
  try {
    const course = await Learning.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    const updatable = [
      "title",
      "titleAr",
      "description",
      "descriptionAr",
      "category",
      "tag",
      "level",
      "levelAr",
      "instructor",
      "instructorAr",
      "duration",
      "hours",
      "lessons",
      "price",
      "priceAfter",
      "status",
      "image",
      "imageDataUrl",
      "stack",
      "rating",
    ];

    for (const key of updatable) {
      if (req.body[key] !== undefined) {
        course[key] = req.body[key];
      }
    }

    await course.save();

    res.status(200).json({
      message: "Course updated successfully",
      item: formatCourseDoc(course),
    });
  } catch (err) {
    console.error("Error in PUT /learning/courses/:id:", err);
    res.status(500).json({ message: "Failed to update course" });
  }
});

// ============================================================================
// 5. PATCH /admin/learning/courses/:id/status - Archive / Hide / Publish Course
// ============================================================================
router.patch("/learning/courses/:id/status", AdminAuth, async (req, res) => {
  try {
    const course = await Learning.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    if (req.body.status && ["published", "draft", "archived"].includes(req.body.status)) {
      course.status = req.body.status;
    } else {
      course.status = course.status === "published" ? "archived" : "published";
    }

    await course.save();

    res.status(200).json({
      message: "Course status updated successfully",
      status: course.status,
      item: formatCourseDoc(course),
    });
  } catch (err) {
    console.error("Error in PATCH /learning/courses/:id/status:", err);
    res.status(500).json({ message: "Failed to update course status" });
  }
});

// ============================================================================
// 6. POST /admin/learning/courses/:id/videos - Add Video to Course
// ============================================================================
router.post("/learning/courses/:id/videos", AdminAuth, async (req, res) => {
  try {
    const course = await Learning.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    const { title, titleAr, description, videoUrl, duration } = req.body;
    if (!title || !String(title).trim()) {
      return res.status(400).json({ message: "Video title is required" });
    }
    if (!videoUrl || !String(videoUrl).trim()) {
      return res.status(400).json({ message: "Video URL or file is required" });
    }

    course.courseVideos.push({
      title: String(title).trim(),
      titleAr: String(titleAr || "").trim(),
      description: String(description || "").trim(),
      videoUrl: String(videoUrl).trim(),
      duration: String(duration || "0:00").trim(),
      order: course.courseVideos.length + 1,
    });
    course.lessons = course.courseVideos.length;

    await course.save();

    res.status(201).json({
      message: "Video added to course successfully",
      item: formatCourseDoc(course),
    });
  } catch (err) {
    console.error("Error in POST /learning/courses/:id/videos:", err);
    res.status(500).json({ message: "Failed to add video to course" });
  }
});

// ============================================================================
// 7. PUT /admin/learning/courses/:id/videos/:videoId - Update Video in Course
// ============================================================================
router.put("/learning/courses/:id/videos/:videoId", AdminAuth, async (req, res) => {
  try {
    const { id, videoId } = req.params;
    const course = await Learning.findById(id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    const video = course.courseVideos.find(
      (v) => String(v._id) === String(videoId)
    );
    if (!video) {
      return res.status(404).json({ message: "Video not found in this course" });
    }

    const { title, titleAr, description, videoUrl, duration } = req.body;
    if (title !== undefined) {
      if (!String(title).trim()) {
        return res.status(400).json({ message: "Video title cannot be empty" });
      }
      video.title = String(title).trim();
    }
    if (titleAr !== undefined) video.titleAr = String(titleAr).trim();
    if (description !== undefined) video.description = String(description).trim();
    if (videoUrl !== undefined) {
      if (!String(videoUrl).trim()) {
        return res.status(400).json({ message: "Video URL or file cannot be empty" });
      }
      video.videoUrl = String(videoUrl).trim();
    }
    if (duration !== undefined) video.duration = String(duration || "0:00").trim();

    await course.save();

    res.status(200).json({
      message: "Course video updated successfully",
      item: formatCourseDoc(course),
    });
  } catch (err) {
    console.error("Error in PUT /learning/courses/:id/videos/:videoId:", err);
    res.status(500).json({ message: "Failed to update course video" });
  }
});

// ============================================================================
// 8. DELETE /admin/learning/courses/:id/videos/:videoId - Remove Video from Course
// ============================================================================
router.delete("/learning/courses/:id/videos/:videoId", AdminAuth, async (req, res) => {
  try {
    const { id, videoId } = req.params;
    const course = await Learning.findById(id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    const beforeCount = course.courseVideos.length;
    course.courseVideos = course.courseVideos.filter(
      (v) => String(v._id) !== String(videoId)
    );

    if (course.courseVideos.length === beforeCount) {
      return res.status(404).json({ message: "Video not found in this course" });
    }

    course.lessons = course.courseVideos.length;
    await course.save();

    res.status(200).json({
      message: "Video removed from course successfully",
      item: formatCourseDoc(course),
    });
  } catch (err) {
    console.error("Error in DELETE /learning/courses/:id/videos/:videoId:", err);
    res.status(500).json({ message: "Failed to delete video from course" });
  }
});

// ============================================================================
// 8. DELETE /admin/learning/courses/:id - Delete Course
// ============================================================================
router.delete("/learning/courses/:id", AdminAuth, async (req, res) => {
  try {
    const deleted = await Learning.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ message: "Course not found" });
    }
    res.status(200).json({ message: "Course deleted successfully" });
  } catch (err) {
    console.error("Error in DELETE /learning/courses/:id:", err);
    res.status(500).json({ message: "Failed to delete course" });
  }
});

export default router;

