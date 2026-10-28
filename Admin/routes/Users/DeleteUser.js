import express from "express";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Users } from "../../../schema/users.js";
const router = express.Router();

router.delete("/delete-user/:id", AdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await Users.findById(id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.role === "admin") {
            return res.status(403).json({ message: "Cannot delete an admin account" });
        }
        await Users.findByIdAndDelete(id);
        res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: err.message || "Failed to delete user" });
    }
});


export default router;  