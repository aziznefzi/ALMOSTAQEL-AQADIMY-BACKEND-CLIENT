import cron from "node-cron";
import { Users } from "../schema/users.js";
import { BlockedIps } from "../schema/blockedIps.js";

cron.schedule("*/30 * * * *", async () => {
    try {
        const bannedRecords = await BlockedIps.find({ StateBan: { $in: ['baned', 'permanent-baned'] } }).select('userID');
        const bannedUserIds = bannedRecords.map(record => record.userID);

        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const result = await Users.deleteMany({
            isVerify: false,
            VerificaionStatus: "notVerify",
            createdAt: { $lte: thirtyMinutesAgo },
            _id: { $nin: bannedUserIds }
        });

        console.log(`Deleted ${result.deletedCount} unverified accounts (Kept banned accounts safe)`);
        
    } catch(err) {
        console.error("Error deleting unverified accounts.", err);
    }
});