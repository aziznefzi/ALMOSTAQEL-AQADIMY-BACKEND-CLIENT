import express from "express";
import mongoose from "mongoose";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Services } from "../../../schema/servicesSchema.js";

const router = express.Router();

const ALLOWED_STATUSES = ["pending", "contacted", "in-progress", "completed", "cancelled"];
const ALLOWED_SORT_FIELDS = ["createdAt", "updatedAt", "name", "status", "serviceType"];
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

// Never expose deviceId / ipAddress to the admin UI
const SAFE_FIELDS =
  "_id name email phone serviceType subject details budget status adminNotes createdAt updatedAt";

// Escape user-supplied regex string to prevent ReDoS / NoSQL Injection
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const formatRequest = (doc) => ({ ...doc, id: doc._id });

// ============================================================================
// GET & POST /admin/service-requests - Paginated list of real service requests
// ============================================================================
const handleListServiceRequests = async (req, res) => {
  try {
    const rawPage = req.query.page ?? req.body?.page;
    const rawLimit = req.query.limit ?? req.body?.limit;
    const rawSearch = req.query.search ?? req.body?.search;
    const rawStatus = req.query.status ?? req.body?.status;
    const rawSort = req.query.sort ?? req.body?.sort;
    const rawOrder = req.query.order ?? req.body?.order;

    const parsedPage = parseInt(rawPage, 10);
    const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

    const parsedLimit = parseInt(rawLimit, 10);
    const limit =
      Number.isInteger(parsedLimit) && parsedLimit >= 1
        ? Math.min(parsedLimit, MAX_LIMIT)
        : DEFAULT_LIMIT;

    const skip = (page - 1) * limit;
    const query = {};

    if (typeof rawSearch === "string") {
      const cleanSearch = rawSearch.trim().slice(0, 100);
      if (cleanSearch.length > 0) {
        const regex = new RegExp(escapeRegex(cleanSearch), "i");
        query.$or = [
          { name: regex },
          { email: regex },
          { phone: regex },
          { subject: regex },
          { serviceType: regex },
        ];
      }
    }

    if (typeof rawStatus === "string" && ALLOWED_STATUSES.includes(rawStatus)) {
      query.status = rawStatus;
    }

    const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
    const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;

    const [total, items, statusCounts] = await Promise.all([
      Services.countDocuments(query),
      Services.find(query)
        .sort({ [sortField]: sortOrder })
        .skip(skip)
        .limit(limit)
        .select(SAFE_FIELDS)
        .lean(),
      Services.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]),
    ]);

    const counts = { all: 0 };
    for (const s of ALLOWED_STATUSES) counts[s] = 0;
    for (const row of statusCounts) {
      if (row._id && counts[row._id] !== undefined) counts[row._id] = row.count;
      counts.all += row.count;
    }

    const totalPages = Math.max(1, Math.ceil(total / limit));

    return res.status(200).json({
      requests: items.map(formatRequest),
      counts,
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
    console.error("Error in /admin/service-requests:", err);
    return res.status(500).json({ message: "Failed to fetch service requests" });
  }
};

router.get("/service-requests", AdminAuth, handleListServiceRequests);
router.post("/service-requests/list", AdminAuth, handleListServiceRequests);

// ============================================================================
// PATCH & POST /admin/service-requests/:id/status - Update request status
// ============================================================================
const handleUpdateStatus = async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid request ID" });
    }

    const status = String(req.body?.status || "").trim();
    if (!ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({ message: "Invalid service request status" });
    }

    const updated = await Services.findByIdAndUpdate(
      id,
      { $set: { status } },
      { new: true }
    )
      .select(SAFE_FIELDS)
      .lean();

    if (!updated) {
      return res.status(404).json({ message: "Service request not found" });
    }

    return res.status(200).json({
      message: "Status updated successfully",
      request: formatRequest(updated),
    });
  } catch (err) {
    console.error("Error updating service request status:", err);
    return res.status(500).json({ message: "Failed to update status" });
  }
};

router.patch("/service-requests/:id/status", AdminAuth, handleUpdateStatus);
router.post("/service-requests/:id/status", AdminAuth, handleUpdateStatus);

// ============================================================================
// POST /admin/service-requests/:id/notes - Add internal admin note
// ============================================================================
router.post("/service-requests/:id/notes", AdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid request ID" });
    }

    const text = typeof req.body?.text === "string" ? req.body.text.trim().slice(0, 2000) : "";
    if (!text) {
      return res.status(400).json({ message: "Note text is required" });
    }

    const updated = await Services.findByIdAndUpdate(
      id,
      { $push: { adminNotes: { text, createdAt: new Date() } } },
      { new: true }
    )
      .select(SAFE_FIELDS)
      .lean();

    if (!updated) {
      return res.status(404).json({ message: "Service request not found" });
    }

    return res.status(200).json({
      message: "Note added successfully",
      request: formatRequest(updated),
    });
  } catch (err) {
    console.error("Error adding service request note:", err);
    return res.status(500).json({ message: "Failed to add note" });
  }
});

export default router;

