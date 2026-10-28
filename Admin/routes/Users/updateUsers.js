import express from "express";
import bcrypt from "bcrypt";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Users } from "../../../schema/users.js";

const router = express.Router();

// Update user details
router.put("/update-user/:id", AdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            ferstname,
            lastname,
            username,
            email,
            PhoneNumber,
            phoneNumber,
            VerificaionStatus,
            role,
            password,
        } = req.body;

        const user = await Users.findById(id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (user.role === "admin" && role && role !== "admin") {
            return res.status(403).json({ message: "Cannot downgrade an admin account" });
        }

        // Check email uniqueness if changed
        const newEmail = email?.trim().toLowerCase();
        if (newEmail && newEmail !== user.email.toLowerCase()) {
            const existingEmail = await Users.findOne({
                email: newEmail,
                _id: { $ne: id },
            });
            if (existingEmail) {
                return res.status(400).json({ message: "Email is already taken by another account" });
            }
            user.email = newEmail;
        }

        // Check username uniqueness if changed
        const newUsername = username?.trim();
        if (newUsername && newUsername !== user.username) {
            const existingUsername = await Users.findOne({
                username: newUsername,
                _id: { $ne: id },
            });
            if (existingUsername) {
                return res.status(400).json({ message: "Username is already taken" });
            }
            user.username = newUsername;
        }

        if (ferstname !== undefined && ferstname.trim().length > 0) {
            user.ferstname = ferstname.trim();
        }

        if (lastname !== undefined) {
            user.lastname = lastname.trim();
        }

        const phoneVal = PhoneNumber !== undefined ? PhoneNumber : phoneNumber;
        if (phoneVal !== undefined) {
            user.PhoneNumber = phoneVal.trim();
        }

        if (VerificaionStatus !== undefined && ["verified", "check", "notVerify"].includes(VerificaionStatus)) {
            user.VerificaionStatus = VerificaionStatus;
            user.isVerify = VerificaionStatus === "verified";
        }

        if (role !== undefined && ["user", "admin"].includes(role)) {
            user.role = role;
        }

        // Optional password update
        if (password && typeof password === "string" && password.trim().length > 0) {
            if (password.trim().length < 8) {
                return res.status(400).json({ message: "Password must be at least 8 characters long" });
            }
            user.password = await bcrypt.hash(password.trim(), 12);
        }

        await user.save();

        const updatedData = user.toObject();
        delete updatedData.password;
        delete updatedData.AuthCode;
        delete updatedData.deviceId;
        delete updatedData.googleId;
        delete updatedData.ipAddress;
        delete updatedData.forgotPasswordRequests;

        res.status(200).json({
            message: "User updated successfully",
            user: {
                ...updatedData,
                id: updatedData._id,
            },
        });
    } catch (err) {
        console.error("Error updating user:", err);
        res.status(500).json({ message: err.message || "Failed to update user" });
    }
});

export default router;
