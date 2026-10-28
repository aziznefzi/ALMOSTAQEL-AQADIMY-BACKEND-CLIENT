import express from "express";
import { Users } from "../../../schema/users.js";
import { BlockedIps } from "../../../schema/blockedIps.js";
import { AdminAuth } from "../../Auth/Madlware.js";

const router = express.Router();

const ALLOWED_SORT_FIELDS = ["createdAt", "ferstname", "username", "email", "updatedAt"];
const ALLOWED_STATUS_FILTERS = ["all", "verified", "check", "notVerify", "banned"];
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

// Escape user-supplied regex string to prevent ReDoS / NoSQL Injection
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const handleGetUsers = async (req, res) => {
    try {
        // Source parameters from query (for GET) or body (for POST)
        const rawPage = req.query.page ?? req.body?.page;
        const rawLimit = req.query.limit ?? req.body?.limit;
        const rawSearch = req.query.search ?? req.body?.search ?? req.query.q ?? req.body?.q;
        const rawFilter = req.query.filter ?? req.body?.filter ?? req.query.status ?? req.body?.status;
        const rawSort = req.query.sort ?? req.body?.sort;
        const rawOrder = req.query.order ?? req.body?.order;

        // 1. Validate & sanitize pagination bounds
        const parsedPage = parseInt(rawPage, 10);
        const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;

        const parsedLimit = parseInt(rawLimit, 10);
        const limit = Number.isInteger(parsedLimit) && parsedLimit >= 1
            ? Math.min(parsedLimit, MAX_LIMIT)
            : DEFAULT_LIMIT;

        const skip = (page - 1) * limit;

        // 2. Base Query: Only standard users (role: 'user')
        const query = { role: "user" };

        // 3. Search Sanitization (Safe regex preventing ReDoS and NoSQL injection)
        if (typeof rawSearch === "string") {
            const cleanSearch = rawSearch.trim().slice(0, 100);
            if (cleanSearch.length > 0) {
                const escaped = escapeRegex(cleanSearch);
                const searchRegex = new RegExp(escaped, "i");
                query.$or = [
                    { ferstname: searchRegex },
                    { lastname: searchRegex },
                    { username: searchRegex },
                    { email: searchRegex },
                ];
            }
        }

        // 4. Status Filtering
        const filter = typeof rawFilter === "string" ? rawFilter.trim() : "all";
        if (ALLOWED_STATUS_FILTERS.includes(filter)) {
            if (filter === "banned") {
                // Find all user IDs associated with active bans
                const bannedRecords = await BlockedIps.find({
                    StateBan: { $in: ["baned", "permanent-baned"] },
                    userID: { $ne: null },
                })
                .select("userID")
                .lean();

                const bannedUserIds = bannedRecords.map((b) => b.userID);
                query._id = { $in: bannedUserIds };
            } else if (["verified", "check", "notVerify"].includes(filter)) {
                query.VerificaionStatus = filter;
            }
        }

        // 5. Sort Field & Order Whitelisting
        const sortField = ALLOWED_SORT_FIELDS.includes(rawSort) ? rawSort : "createdAt";
        const sortOrder = String(rawOrder).toLowerCase() === "asc" ? 1 : -1;
        const sortObj = { [sortField]: sortOrder };

        // 6. Execute count and find queries concurrently for maximum throughput
        const [totalUsers, users] = await Promise.all([
            Users.countDocuments(query),
            Users.find(query)
                .sort(sortObj)
                .skip(skip)
                .limit(limit)
                .select(
                    "_id ferstname lastname username email PhoneNumber VerificaionStatus isVerify role authProvider avatar createdAt updatedAt"
                )
                .lean(),
        ]);

        // 7. Enrich users with ban metadata
        const userIds = users.map((u) => u._id);
        const bans = await BlockedIps.find({
            userID: { $in: userIds },
            StateBan: { $in: ["baned", "permanent-baned"] },
        }).lean();

        const banMap = new Map(bans.map((b) => [String(b.userID), b]));

        const enrichedUsers = users.map((u) => {
            const ban = banMap.get(String(u._id));
            const stateBan = ban ? ban.StateBan : "not-baned";
            return {
                ...u,
                id: u._id,
                StateBan: stateBan,
                banReason: ban?.resson || "",
                banDate: ban?.banneDate || null,
            };
        });

        const totalPages = Math.max(1, Math.ceil(totalUsers / limit));

        // 8. Return paginated payload with comprehensive metadata
        res.status(200).json({
            users: enrichedUsers,
            pagination: {
                total: totalUsers,
                page,
                limit,
                totalPages,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1,
            },
        });
    } catch (err) {
        console.error("Error in getUsers handler:", err);
        res.status(500).json({ message: "Failed to fetch users" });
    }
};

// Support both GET (REST standard) and POST (backward compatibility)
router.get("/get-users", AdminAuth, handleGetUsers);
router.post("/get-users", AdminAuth, handleGetUsers);

export default router;