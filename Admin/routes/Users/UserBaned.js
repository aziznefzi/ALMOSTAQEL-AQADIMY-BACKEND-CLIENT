import express from "express";
import { AdminAuth } from "../../Auth/Madlware.js";
import { Users } from "../../../schema/users.js";
import { BlockedIps } from "../../../schema/blockedIps.js";
import { Resend } from "resend";
import nodemailer from "nodemailer";

const router = express.Router();

/**
 * Generate Ban Notification Email Content (English only, matching signup.js template)
 */
export const getUserBanEmailContent = ({
    ferstname,
    lastname,
    username,
    email,
    phoneNumber,
    isPermanent = true,
    duration = 24,
    reason = "",
    blockedUntil = null,
}) => {
    const fullName = `${ferstname || ""} ${lastname || ""}`.trim();
    const formattedDate = new Date().toLocaleString("en-US", {
        dateStyle: "medium",
        timeStyle: "short",
    });
    const formattedEndDate = blockedUntil
        ? new Date(blockedUntil).toLocaleString("en-US", {
              dateStyle: "medium",
              timeStyle: "short",
          })
        : "Unspecified";

    const subject = isPermanent
        ? "Account Ban Notification — ALMOSTAQEL AQADEMY"
        : `Account Suspension Notification (${duration}h) — ALMOSTAQEL AQADEMY`;

    const greeting = `Hello ${fullName || username},`;
    const message = isPermanent
        ? "We are writing to notify you that your account on ALMOSTAQEL AQADEMY has been permanently banned due to violations of our platform terms of service and community policies."
        : `We are writing to notify you that your account on ALMOSTAQEL AQADEMY has been temporarily suspended for ${duration} hours. You will not be able to access your account during this period.`;

    const statusTitle = "Account Status";
    const statusText = isPermanent
        ? "PERMANENTLY BANNED"
        : `TEMPORARILY SUSPENDED (${duration} HOURS)`;
    const statusColor = isPermanent ? "#f43f5e" : "#fbbf24";
    const detailsTitle = "Account & Ban Details:";
    const footerText = `&copy; ${new Date().getFullYear()} ALMOSTAQEL AQADEMY. All rights reserved.<br>This is an automated notification from ALMOSTAQEL AQADEMY administration.`;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #07070f;
      color: #f0efff;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #13111c;
      border: 1px solid #1f1b2e;
      border-radius: 16px;
      overflow: hidden;
    }
    .header {
      background: linear-gradient(to right, #9333ea, #ec4899);
      padding: 30px 20px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 24px;
      letter-spacing: 1px;
    }
    .content {
      padding: 40px 30px;
    }
    .greeting {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 20px;
    }
    .message {
      color: #cbd5e1;
      line-height: 1.6;
      margin-bottom: 30px;
    }
    .code-box {
      background-color: #07070f;
      border: 1px solid #1f1b2e;
      border-radius: 12px;
      padding: 24px 20px;
      text-align: center;
      margin-bottom: 30px;
    }
    .code-title {
      margin-top: 0;
      color: #64748b;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .code {
      font-size: 22px;
      font-weight: 700;
      color: ${statusColor};
      letter-spacing: 1px;
      margin: 10px 0 0 0;
      display: inline-block;
    }
    .reason-box {
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid #1f1b2e;
      color: #cbd5e1;
      font-size: 14px;
      line-height: 1.6;
      text-align: left;
    }
    .reason-box strong {
      color: #f0efff;
    }
    .details {
      background-color: rgba(139, 92, 246, 0.05);
      border-left: 4px solid #8b5cf6;
      padding: 15px 20px;
      border-radius: 4px;
    }
    .details p {
      margin: 6px 0;
      color: #cbd5e1;
      font-size: 14px;
    }
    .details strong {
      color: #f0efff;
      margin-right: 6px;
    }
    .appeal-note {
      margin-top: 25px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px dashed #2a253a;
      border-radius: 8px;
      padding: 14px 18px;
      font-size: 13px;
      color: #94a3b8;
      line-height: 1.6;
    }
    .appeal-note a {
      color: #c084fc;
      text-decoration: underline;
      font-weight: 600;
    }
    .footer {
      text-align: center;
      padding: 20px;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid #1f1b2e;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>ALMOSTAQEL AQADEMY</h1>
    </div>
    <div class="content">
      <div class="greeting">${greeting}</div>
      <div class="message">${message}</div>
      <div class="code-box">
        <p class="code-title">${statusTitle}</p>
        <p class="code">${statusText}</p>
        <div class="reason-box">
          <strong>Reason:</strong> ${reason}
        </div>
      </div>
      <div class="details">
        <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">${detailsTitle}</p>
        <p><strong>Username:</strong> ${username}</p>
        ${email ? `<p><strong>Email:</strong> ${email}</p>` : ""}
        ${phoneNumber ? `<p><strong>Phone:</strong> ${phoneNumber}</p>` : ""}
        <p><strong>Action Type:</strong> ${isPermanent ? "Permanent Ban" : `Temporary Suspension (${duration} hours)`}</p>
        <p><strong>Effective Date:</strong> ${formattedDate}</p>
        ${!isPermanent && blockedUntil ? `<p><strong>Suspension Lift Date:</strong> ${formattedEndDate}</p>` : ""}
      </div>
      <div class="appeal-note">
        If you believe this action was taken in error or wish to appeal this decision, please reach out to our administrative team at: 
        <a href="mailto:contact@almostaqelaqademy.com">contact@almostaqelaqademy.com</a>
      </div>
    </div>
    <div class="footer">
      ${footerText}
    </div>
  </div>
</body>
</html>
    `;

    return { subject, html };
};

/**
 * Generate Unban Notification Email Content (English only)
 */
export const getUserUnbanEmailContent = ({
    ferstname,
    lastname,
    username,
    email,
    phoneNumber,
}) => {
    const fullName = `${ferstname || ""} ${lastname || ""}`.trim();
    const formattedDate = new Date().toLocaleString("en-US", {
        dateStyle: "medium",
        timeStyle: "short",
    });

    const subject = "Account Ban Lifted — ALMOSTAQEL AQADEMY";
    const greeting = `Hello ${fullName || username},`;
    const message = "We are pleased to inform you that the suspension on your account has been lifted. You can now log in and continue using all services on ALMOSTAQEL AQADEMY.";
    const statusTitle = "Account Status";
    const statusText = "ACCOUNT RE-ACTIVATED";
    const detailsTitle = "Account Details:";
    const footerText = `&copy; ${new Date().getFullYear()} ALMOSTAQEL AQADEMY. All rights reserved.<br>This is an automated notification from ALMOSTAQEL AQADEMY administration.`;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #07070f;
      color: #f0efff;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #13111c;
      border: 1px solid #1f1b2e;
      border-radius: 16px;
      overflow: hidden;
    }
    .header {
      background: linear-gradient(to right, #9333ea, #ec4899);
      padding: 30px 20px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 24px;
      letter-spacing: 1px;
    }
    .content {
      padding: 40px 30px;
    }
    .greeting {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 20px;
    }
    .message {
      color: #cbd5e1;
      line-height: 1.6;
      margin-bottom: 30px;
    }
    .code-box {
      background-color: #07070f;
      border: 1px solid #1f1b2e;
      border-radius: 12px;
      padding: 24px 20px;
      text-align: center;
      margin-bottom: 30px;
    }
    .code-title {
      margin-top: 0;
      color: #64748b;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .code {
      font-size: 22px;
      font-weight: 700;
      color: #10b981;
      letter-spacing: 1px;
      margin: 10px 0 0 0;
      display: inline-block;
    }
    .details {
      background-color: rgba(16, 185, 129, 0.05);
      border-left: 4px solid #10b981;
      padding: 15px 20px;
      border-radius: 4px;
    }
    .details p {
      margin: 6px 0;
      color: #cbd5e1;
      font-size: 14px;
    }
    .details strong {
      color: #f0efff;
      margin-right: 6px;
    }
    .footer {
      text-align: center;
      padding: 20px;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid #1f1b2e;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>ALMOSTAQEL AQADEMY</h1>
    </div>
    <div class="content">
      <div class="greeting">${greeting}</div>
      <div class="message">${message}</div>
      <div class="code-box">
        <p class="code-title">${statusTitle}</p>
        <p class="code">${statusText}</p>
      </div>
      <div class="details">
        <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">${detailsTitle}</p>
        <p><strong>Username:</strong> ${username}</p>
        ${email ? `<p><strong>Email:</strong> ${email}</p>` : ""}
        ${phoneNumber ? `<p><strong>Phone:</strong> ${phoneNumber}</p>` : ""}
        <p><strong>Current Status:</strong> Active & Unrestricted</p>
        <p><strong>Restoration Date:</strong> ${formattedDate}</p>
      </div>
    </div>
    <div class="footer">
      ${footerText}
    </div>
  </div>
</body>
</html>
    `;

    return { subject, html };
};

/**
 * Dispatch Email using Resend with Nodemailer Gmail fallback
 * Uses sender: contact@almostaqelaqademy.com
 */
const sendNotificationEmail = async ({ to, subject, html }) => {
    // 1. Try Resend first
    if (process.env.RESEND_API_KEY) {
        try {
            const resend = new Resend(process.env.RESEND_API_KEY);
            const { data, error } = await resend.emails.send({
                from: "almostaqel aQademy <contact@almostaqelaqademy.com>",
                to,
                subject,
                html,
            });

            if (!error && data) {
                console.log("Email sent successfully via Resend to:", to);
                return { sent: true, provider: "resend", id: data.id };
            }
            console.warn("Resend email failed, attempting Nodemailer Gmail fallback:", error?.message);
        } catch (resendErr) {
            console.warn("Resend email exception, falling back to Nodemailer:", resendErr?.message);
        }
    }

    // 2. Nodemailer fallback with Gmail
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        try {
            const transporter = nodemailer.createTransport({
                service: "gmail",
                port: 587,
                secure: false,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
                tls: {
                    rejectUnauthorized: false,
                },
            });

            await transporter.sendMail({
                from: `"ALMOSTAQEL AQADEMY" <contact@almostaqelaqademy.com>`,
                to,
                subject,
                html,
                replyTo: "contact@almostaqelaqademy.com",
            });
            console.log("Email sent successfully via Nodemailer fallback to:", to);
            return { sent: true, provider: "nodemailer" };
        } catch (nodemailerErr) {
            console.error("Nodemailer email fallback failed:", nodemailerErr?.message);
        }
    }

    return { sent: false, error: "No email dispatch service succeeded" };
};

// Ban or suspend a user
router.post("/ban-user/:id", AdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { banType = "permanent", duration = 24, reason = "" } = req.body;

        const user = await Users.findById(id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.role === "admin") {
            return res.status(403).json({ message: "Cannot ban an admin account" });
        }

        const isPermanent = banType === "permanent" || banType === "permanent-baned";
        const stateBan = isPermanent ? "permanent-baned" : "baned";

        let blockedUntil = null;
        let banReasonText = reason.trim();

        if (isPermanent) {
            banReasonText = banReasonText || "Permanently banned by administrator";
            // Far future date for user blockedUntil
            blockedUntil = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000);
        } else {
            const hours = Number(duration) || 24;
            banReasonText = banReasonText || `Temporarily suspended for ${hours} hours by administrator`;
            blockedUntil = new Date(Date.now() + hours * 60 * 60 * 1000);
        }

        // Upsert the ban record in BlockedIps
        const banRecord = await BlockedIps.findOneAndUpdate(
            { userID: user._id },
            {
                $set: {
                    userID: user._id,
                    email: user.email,
                    deviceId: user.deviceId || null,
                    ipAddress: user.ipAddress || null,
                    resson: banReasonText,
                    banneDate: new Date(),
                    StateBan: stateBan,
                    banType: "all",
                },
                $inc: { BannedCount: 1 },
            },
            { upsert: true, new: true }
        );

        // Update user schema blockedUntil
        user.blockedUntil = blockedUntil;
        await user.save();

        // Send Ban Notification Email to the user in English from contact@almostaqelaqademy.com
        let emailNotification = { sent: false };
        try {
            const emailContent = getUserBanEmailContent({
                ferstname: user.ferstname,
                lastname: user.lastname,
                username: user.username,
                email: user.email,
                phoneNumber: user.PhoneNumber || user.phoneNumber || "",
                isPermanent,
                duration: Number(duration) || 24,
                reason: banReasonText,
                blockedUntil,
            });

            emailNotification = await sendNotificationEmail({
                to: user.email,
                subject: emailContent.subject,
                html: emailContent.html,
            });
        } catch (emailErr) {
            console.error("Error sending user ban notification email:", emailErr?.message || emailErr);
        }

        res.status(200).json({
            message: isPermanent ? "User permanently banned" : "User temporarily suspended",
            ban: banRecord,
            stateBan,
            blockedUntil,
            emailSent: emailNotification.sent,
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: err.message || "Failed to update ban status" });
    }
});

// Unban user
router.post("/unban-user/:id", AdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await Users.findById(id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        await BlockedIps.findOneAndUpdate(
            { userID: user._id },
            {
                $set: {
                    StateBan: "not-baned",
                    resson: "Unbanned by administrator",
                },
            }
        );

        user.blockedUntil = null;
        user.AttemptsCount = 0;
        await user.save();

        // Send Unban Notification Email in English from contact@almostaqelaqademy.com
        let emailNotification = { sent: false };
        try {
            const emailContent = getUserUnbanEmailContent({
                ferstname: user.ferstname,
                lastname: user.lastname,
                username: user.username,
                email: user.email,
                phoneNumber: user.PhoneNumber || user.phoneNumber || "",
            });

            emailNotification = await sendNotificationEmail({
                to: user.email,
                subject: emailContent.subject,
                html: emailContent.html,
            });
        } catch (emailErr) {
            console.error("Error sending user unban notification email:", emailErr?.message || emailErr);
        }

        res.status(200).json({ 
            message: "User unbanned successfully",
            emailSent: emailNotification.sent,
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: err.message || "Failed to unban user" });
    }
});

export default router;
