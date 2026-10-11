import express from "express";
import { Services } from "../schema/svrisesSheme.js";
import { BlockedIps } from "../schema/blockedIps.js";
import { verifyCaptchaToken } from "../jobs/verifyCapchaToken.js";
import { Resend } from "resend";

const router = express.Router();

// Helper to escape HTML and prevent injection in email templates
const escapeHtml = (str) => {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// Generate an elegant, branded confirmation email for the user in either Arabic or English
const generateServiceEmailHtml = ({ name, serviceType, subject, details, budget, phone, lang = "ar" }) => {
  const isEn = lang === "en";
  const safeName = escapeHtml(name);
  const safeType = escapeHtml(serviceType);
  const safeSubject = escapeHtml(subject);
  const safeDetails = escapeHtml(details);
  const safeBudget = escapeHtml(budget || (isEn ? "Flexible" : "مرن"));
  const safePhone = escapeHtml(phone);

  const submissionDate = isEn
    ? new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })
    : new Date().toLocaleDateString("ar-EG", { year: "numeric", month: "long", day: "numeric" });

  if (isEn) {
    return `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Service Request Received - almostaqel aQademy</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #07070f;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #e2e8f0;
      -webkit-font-smoothing: antialiased;
    }
    .wrapper {
      width: 100%;
      background-color: #07070f;
      padding: 40px 15px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #121024;
      border: 1px solid #272147;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
    }
    .header {
      background: linear-gradient(135deg, #7c3aed 0%, #a855f7 50%, #ec4899 100%);
      padding: 36px 24px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.5px;
    }
    .header p {
      margin: 8px 0 0 0;
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
    }
    .content {
      padding: 32px 28px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 12px;
    }
    .intro-text {
      font-size: 14px;
      line-height: 1.8;
      color: #cbd5e1;
      margin-bottom: 24px;
    }
    .summary-card {
      background-color: #1a1733;
      border: 1px solid #2e2652;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .summary-card h3 {
      margin: 0 0 16px 0;
      font-size: 15px;
      color: #c084fc;
      border-bottom: 1px solid #2e2652;
      padding-bottom: 10px;
    }
    .details-box {
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px dashed #2e2652;
      font-size: 13px;
      line-height: 1.6;
      color: #cbd5e1;
      white-space: pre-line;
    }
    .next-steps {
      background: linear-gradient(135deg, rgba(124, 58, 237, 0.12) 0%, rgba(236, 72, 153, 0.12) 100%);
      border: 1px solid rgba(168, 85, 247, 0.3);
      border-radius: 12px;
      padding: 16px 18px;
      margin-bottom: 28px;
      font-size: 13px;
      line-height: 1.7;
      color: #e2e8f0;
    }
    .footer {
      background-color: #0d0b1a;
      border-top: 1px solid #272147;
      padding: 24px;
      text-align: center;
      font-size: 12px;
      color: #64748b;
    }
    .footer a {
      color: #a855f7;
      text-decoration: none;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 999px;
      background-color: rgba(168, 85, 247, 0.2);
      color: #d8b4fe;
      font-size: 12px;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <h1>almostaqel aQademy</h1>
        <p>Software Engineering & Digital Solutions</p>
      </div>

      <div class="content">
        <div class="greeting">Hello, ${safeName} 👋</div>
        <p class="intro-text">
          Thank you for reaching out to <strong>almostaqel aQademy</strong>. We have successfully received your service request, and our engineering team led by <strong>Aziz Nefzi</strong> is currently reviewing your project requirements.
        </p>

        <div class="summary-card">
          <h3>Service Request Summary</h3>
          <table width="100%" cellpadding="6" cellspacing="0" style="border-collapse: collapse; font-size: 13px;">
            <tr>
              <td style="color: #94a3b8; font-weight: 600; width: 35%;">Service Type:</td>
              <td style="color: #f1f5f9; text-align: right;"><span class="badge">${safeType}</span></td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">Project Subject:</td>
              <td style="color: #f1f5f9; text-align: right;">${safeSubject}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">Phone / WhatsApp:</td>
              <td style="color: #f1f5f9; text-align: right;">${safePhone}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">Estimated Budget:</td>
              <td style="color: #f1f5f9; text-align: right;">${safeBudget}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">Submission Date:</td>
              <td style="color: #f1f5f9; text-align: right;">${submissionDate}</td>
            </tr>
          </table>

          <div class="details-box">
            <strong style="color: #c084fc;">Project Details:</strong><br>
            ${safeDetails}
          </div>
        </div>

        <div class="next-steps">
          💡 <strong>What's Next:</strong> We will contact you via email or phone within 24 hours to discuss the roadmap, timeline, and proposal tailored to your needs.
        </div>

        <p style="font-size: 13px; color: #94a3b8; margin: 0; line-height: 1.6;">
          If you have any urgent updates or questions, feel free to reply directly to this email.<br>
          Best regards,<br>
          <strong style="color: #ffffff;">Aziz Nefzi</strong> — Founder & Lead Engineer<br>
          <a href="mailto:a.nefzi@almostaqelaqademy.com" style="color: #a855f7;">a.nefzi@almostaqelaqademy.com</a>
        </p>
      </div>

      <div class="footer">
        <p style="margin: 0 0 6px 0;">© ${new Date().getFullYear()} almostaqel aQademy. All rights reserved.</p>
        <p style="margin: 0;"><a href="https://almostaqelaqademy.com">almostaqelaqademy.com</a></p>
      </div>
    </div>
  </div>
</body>
</html>`;
  }

  // Arabic Email Template (Default)
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>تأكيد استلام طلب الخدمة - almostaqel aQademy</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #07070f;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #e2e8f0;
      -webkit-font-smoothing: antialiased;
    }
    .wrapper {
      width: 100%;
      background-color: #07070f;
      padding: 40px 15px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #121024;
      border: 1px solid #272147;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
    }
    .header {
      background: linear-gradient(135deg, #7c3aed 0%, #a855f7 50%, #ec4899 100%);
      padding: 36px 24px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      color: #ffffff;
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.5px;
    }
    .header p {
      margin: 8px 0 0 0;
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
    }
    .content {
      padding: 32px 28px;
    }
    .greeting {
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 12px;
    }
    .intro-text {
      font-size: 14px;
      line-height: 1.8;
      color: #cbd5e1;
      margin-bottom: 24px;
    }
    .summary-card {
      background-color: #1a1733;
      border: 1px solid #2e2652;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .summary-card h3 {
      margin: 0 0 16px 0;
      font-size: 15px;
      color: #c084fc;
      border-bottom: 1px solid #2e2652;
      padding-bottom: 10px;
    }
    .details-box {
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px dashed #2e2652;
      font-size: 13px;
      line-height: 1.6;
      color: #cbd5e1;
      white-space: pre-line;
    }
    .next-steps {
      background: linear-gradient(135deg, rgba(124, 58, 237, 0.12) 0%, rgba(236, 72, 153, 0.12) 100%);
      border: 1px solid rgba(168, 85, 247, 0.3);
      border-radius: 12px;
      padding: 16px 18px;
      margin-bottom: 28px;
      font-size: 13px;
      line-height: 1.7;
      color: #e2e8f0;
    }
    .footer {
      background-color: #0d0b1a;
      border-top: 1px solid #272147;
      padding: 24px;
      text-align: center;
      font-size: 12px;
      color: #64748b;
    }
    .footer a {
      color: #a855f7;
      text-decoration: none;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 999px;
      background-color: rgba(168, 85, 247, 0.2);
      color: #d8b4fe;
      font-size: 12px;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <h1>almostaqel aQademy</h1>
        <p>أكاديمية المستقبل | هندسة وتطوير الحلول البرمجية</p>
      </div>

      <div class="content">
        <div class="greeting">أهلاً بك، ${safeName} 👋</div>
        <p class="intro-text">
          نشكرك على تواصلك وثقتك في <strong>almostaqel aQademy</strong>. نود إعلامك بأنه قد تم استلام طلبك للخدمة بنجاح، ويقوم فريقنا الهندسي بقيادة <strong>عزيز النفزي</strong> بدراسة تفاصيل ومتطلبات مشروعك حالياً.
        </p>

        <div class="summary-card">
          <h3>ملخص طلب الخدمة</h3>
          <table width="100%" cellpadding="6" cellspacing="0" style="border-collapse: collapse; font-size: 13px;">
            <tr>
              <td style="color: #94a3b8; font-weight: 600; width: 35%;">نوع الخدمة:</td>
              <td style="color: #f1f5f9; text-align: left;"><span class="badge">${safeType}</span></td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">موضوع المشروع:</td>
              <td style="color: #f1f5f9; text-align: left;">${safeSubject}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">رقم الهاتف:</td>
              <td style="color: #f1f5f9; text-align: left; direction: ltr;">${safePhone}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">الميزانية التقديرية:</td>
              <td style="color: #f1f5f9; text-align: left;">${safeBudget}</td>
            </tr>
            <tr>
              <td style="color: #94a3b8; font-weight: 600;">تاريخ التقديم:</td>
              <td style="color: #f1f5f9; text-align: left;">${submissionDate}</td>
            </tr>
          </table>

          <div class="details-box">
            <strong style="color: #c084fc;">تفاصيل المتطلبات:</strong><br>
            ${safeDetails}
          </div>
        </div>

        <div class="next-steps">
          💡 <strong>الخطوة التالية:</strong> سنتواصل معك عبر البريد الإلكتروني أو الهاتف خلال أقل من 24 ساعة لمناقشة خارطة الطريق، الجدول الزمني، وعرض العمل المناسب لاحتياجاتك.
        </div>

        <p style="font-size: 13px; color: #94a3b8; margin: 0; line-height: 1.6;">
          إذا كان لديك أي تعديل أو استفسار عاجل، يمكنك الرد مباشرة على هذا البريد الإلكتروني.<br>
          مع أطيب التحيات،<br>
          <strong style="color: #ffffff;">Aziz Nefzi</strong> — Founder & Lead Engineer<br>
          <a href="mailto:a.nefzi@almostaqelaqademy.com" style="color: #a855f7;">a.nefzi@almostaqelaqademy.com</a>
        </p>
      </div>

      <div class="footer">
        <p style="margin: 0 0 6px 0;">© ${new Date().getFullYear()} almostaqel aQademy. جميع الحقوق محفوظة.</p>
        <p style="margin: 0;"><a href="https://almostaqelaqademy.com">almostaqelaqademy.com</a></p>
      </div>
    </div>
  </div>
</body>
</html>`;
};

// Route: POST /services (or /api/services when mounted under /api)
router.post("/services", async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      serviceType,
      subject,
      details,
      budget,
      deviceId,
      captchaToken,
      lang,
    } = req.body;

    // 1. Validate required fields & CAPTCHA token
    if (
      !name ||
      !email ||
      !phone ||
      !serviceType ||
      !subject ||
      !details ||
      !captchaToken
    ) {
      return res.status(400).json({
        message: "Verify the entered information (form and captcha are required)",
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanDeviceId = deviceId ? String(deviceId).trim() : null;
    const clientIp =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress;

    // 2. Pre-check ban list:
    // Check 1: Device ban (bans this device from performing any activity)
    if (cleanDeviceId) {
      const isDeviceBanned = await BlockedIps.findOne({
        deviceId: cleanDeviceId,
        StateBan: "permanent-baned",
      });
      if (isDeviceBanned) {
        return res.status(403).json({
          message:
            "Your device is permanently banned from performing any activity on this platform.",
        });
      }
    }

    // Check 2: Email ban (bans this email from being used on any device across the platform)
    if (cleanEmail) {
      const isEmailBanned = await BlockedIps.findOne({
        email: cleanEmail,
        StateBan: "permanent-baned",
      });
      if (isEmailBanned) {
        return res.status(403).json({
          message:
            "This email is permanently banned from being used on this platform on any device.",
        });
      }
    }

    // 3. Verify Google reCAPTCHA Token
    const isHuman = await verifyCaptchaToken(captchaToken);
    if (!isHuman) {
      // Security measure: Permanently ban both deviceId (Device ban) and email (Email ban across platform)
      const banOps = [];

      // 1. Device ban record: prevents any request from this device
      if (cleanDeviceId) {
        banOps.push(
          BlockedIps.findOneAndUpdate(
            { deviceId: cleanDeviceId, banType: "device" },
            {
              $set: {
                deviceId: cleanDeviceId,
                email: cleanEmail,
                ipAddress: clientIp,
                banType: "device",
                resson: "Forged Captcha Token during Service Request - Device permanent ban",
                banneDate: new Date(),
                StateBan: "permanent-baned",
              },
            },
            { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
          )
        );
      }

      // 2. Email ban record: prevents this email from being used on any device
      if (cleanEmail) {
        banOps.push(
          BlockedIps.findOneAndUpdate(
            { email: cleanEmail, banType: "email" },
            {
              $set: {
                email: cleanEmail,
                deviceId: cleanDeviceId,
                ipAddress: clientIp,
                banType: "email",
                resson: "Forged Captcha Token during Service Request - Email permanent ban across platform",
                banneDate: new Date(),
                StateBan: "permanent-baned",
              },
            },
            { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
          )
        );
      }

      await Promise.all(banOps);

      return res.status(403).json({
        message:
          "Your device and email have been permanently blocked due to suspicious activity.",
      });
    }

    // 4. Save service request to Database
    const serviceRecord = await Services.create({
      name: String(name).trim(),
      email: cleanEmail,
      phone: String(phone).trim(),
      serviceType: String(serviceType).trim(),
      subject: String(subject).trim(),
      details: String(details).trim(),
      budget: budget ? String(budget).trim() : "",
      deviceId: cleanDeviceId,
      ipAddress: clientIp,
      status: "pending",
    });

    // 5. Send Confirmation Email to the user from a.nefzi@almostaqelaqademy.com
    try {
      if (process.env.RESEND_API_KEY) {
        const resend = new Resend(process.env.RESEND_API_KEY);
        const isEn = lang === "en";
        const emailSubject = isEn
          ? `Service Request Received - ${String(subject).trim()} | almostaqel aQademy`
          : `تم استلام طلب الخدمة بنجاح | almostaqel aQademy - ${String(subject).trim()}`;

        const { error: emailError } = await resend.emails.send({
          from: "Almostaqel Academy <a.nefzi@almostaqelaqademy.com>",
          to: cleanEmail,
          subject: emailSubject,
          html: generateServiceEmailHtml({
            name: String(name).trim(),
            serviceType: String(serviceType).trim(),
            subject: String(subject).trim(),
            details: String(details).trim(),
            budget: budget ? String(budget).trim() : "",
            phone: String(phone).trim(),
            lang: lang || "ar",
          }),
        });

        if (emailError) {
          console.error("Resend service email error:", emailError.message || emailError);
        }
      } else {
        console.warn("RESEND_API_KEY is not defined in environment variables.");
      }
    } catch (emailErr) {
      console.error("Error sending confirmation email via Resend:", emailErr?.message || emailErr);
    }

    // 6. Respond with Success
    return res.status(201).json({
      success: true,
      message: "Your service request has been submitted successfully.",
      data: {
        id: serviceRecord._id,
        createdAt: serviceRecord.createdAt,
      },
    });
  } catch (error) {
    console.error("Error in /services endpoint:", error);
    return res.status(500).json({
      message: "Internal server error. Please try again later.",
    });
  }
});

export default router;