import express from "express"
import bcrypt from "bcrypt"
import crypto from "crypto"
import nodemailer from "nodemailer"
import jwt from "jsonwebtoken"
import { Users } from "../../schema/users.js";
import { type } from "os"
import filedAuth from "../../middleware/filedAuth.js"
import { BlockedIps } from "../../schema/blockedIps.js"
import { verifyCaptchaToken } from "../../jobs/verifyCapchaToken.js"
import { Resend } from "resend";
import Sessions from "../../schema/sessions.js"
import { getMsg, getResendLockMsg, getEmailSendErrorMsg, getLang } from "../../utils/messages.js"
const router = express.Router()

export const getVerificationEmailContent = ({ type = "welcome", lang = "en", ferstname, lastname, username, email, phoneNumber, code }) => {
  const isAr = String(lang).toLowerCase().includes("ar");
  const fullName = `${ferstname || ""} ${lastname || ""}`.trim();

  if (isAr) {
    const subject = type === "resend" 
      ? "رمز التحقق الجديد - أكاديمية المستقبل" 
      : "مرحباً بك في أكاديمية المستقبل - رمز التحقق";

    const greeting = `مرحباً ${fullName || username}،`;
    const message = type === "resend"
      ? "لقد طلبت إعادة إرسال رمز التحقق. يرجى استخدام رمز التحقق الجديد أدناه لإتمام تسجيل حسابك."
      : "أهلاً بك في أكاديمية المستقبل! يسعدنا انضمامك إلينا. يرجى استخدام رمز التحقق أدناه لإتمام عملية التسجيل وتفعيل حسابك.";

    const codeTitle = type === "resend" ? "رمز التحقق الجديد" : "رمز التحقق";
    const detailsTitle = "تفاصيل الحساب:";
    const usernameLabel = "اسم المستخدم:";
    const phoneLabel = "رقم الهاتف:";
    const emailLabel = "البريد الإلكتروني:";
    const footerText = `&copy; ${new Date().getFullYear()} أكاديمية المستقبل (ALMOSTAEL AQADIMY). جميع الحقوق محفوظة.<br>هذا الرمز صالح لمدة 15 دقيقة. إذا لم تكن قد طلبت هذا البريد الإلكتروني، يمكنك تجاهله بأمان.`;

    const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #07070f;
      color: #f0efff;
      margin: 0;
      padding: 40px 20px;
      direction: rtl;
      text-align: right;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #13111c;
      border: 1px solid #1f1b2e;
      border-radius: 16px;
      overflow: hidden;
      direction: rtl;
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
      text-align: right;
    }
    .greeting {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 20px;
      color: #f0efff;
    }
    .message {
      color: #cbd5e1;
      line-height: 1.8;
      margin-bottom: 30px;
      font-size: 15px;
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
      color: #94a3b8;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .code {
      font-size: 36px;
      font-weight: 700;
      color: #c084fc;
      letter-spacing: 8px;
      margin: 10px 0 0 0;
      font-family: monospace, sans-serif;
      direction: ltr;
      display: inline-block;
    }
    .details {
      background-color: rgba(139, 92, 246, 0.05);
      border-right: 4px solid #8b5cf6;
      padding: 15px 20px;
      border-radius: 4px;
      text-align: right;
    }
    .details p {
      margin: 6px 0;
      color: #cbd5e1;
      font-size: 14px;
    }
    .details strong {
      color: #f0efff;
      margin-left: 6px;
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
      <h1>أكاديمية المستقبل</h1>
    </div>
    <div class="content">
      <div class="greeting">${greeting}</div>
      <div class="message">${message}</div>
      <div class="code-box">
        <p class="code-title">${codeTitle}</p>
        <p class="code">${code}</p>
      </div>
      <div class="details">
        <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">${detailsTitle}</p>
        <p><strong>${usernameLabel}</strong> ${username}</p>
        ${phoneNumber ? `<p><strong>${phoneLabel}</strong> ${phoneNumber}</p>` : ""}
        ${email ? `<p><strong>${emailLabel}</strong> ${email}</p>` : ""}
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
  } else {
    // English version
    const subject = type === "resend"
      ? "New Verification Code - ALMOSTAEL AQADIMY"
      : "Welcome to ALMOSTAEL AQADIMY - Verification Code";

    const greeting = `Hello ${fullName || username},`;
    const message = type === "resend"
      ? "You requested to resend your verification code. Please use the new verification code below to complete your registration."
      : "Welcome to ALMOSTAEL AQADIMY! We are thrilled to have you on board. Please use the verification code below to complete your registration.";

    const codeTitle = type === "resend" ? "New Verification Code" : "Verification Code";
    const detailsTitle = "Account Details:";
    const usernameLabel = "Username:";
    const phoneLabel = "Phone:";
    const emailLabel = "Email:";
    const footerText = `&copy; ${new Date().getFullYear()} ALMOSTAEL AQADIMY. All rights reserved.<br>This code is valid for 15 minutes. If you didn't request this email, please ignore it.`;

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
      padding: 20px;
      text-align: center;
      margin-bottom: 30px;
    }
    .code-title {
      margin-top: 0;
      color: #64748b;
      font-size: 14px;
      text-transform: uppercase;
    }
    .code {
      font-size: 32px;
      font-weight: 700;
      color: #a855f7;
      letter-spacing: 8px;
      margin: 0;
    }
    .details {
      background-color: rgba(139, 92, 246, 0.05);
      border-left: 4px solid #8b5cf6;
      padding: 15px 20px;
      border-radius: 4px;
    }
    .details p {
      margin: 5px 0;
      color: #cbd5e1;
    }
    .details strong {
      color: #f0efff;
    }
    .footer {
      text-align: center;
      padding: 20px;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid #1f1b2e;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>ALMOSTAEL AQADIMY</h1>
    </div>
    <div class="content">
      <div class="greeting">${greeting}</div>
      <div class="message">${message}</div>
      <div class="code-box">
        <p class="code-title">${codeTitle}</p>
        <p class="code">${code}</p>
      </div>
      <div class="details">
        <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">${detailsTitle}</p>
        <p><strong>${usernameLabel}</strong> ${username}</p>
        ${phoneNumber ? `<p><strong>${phoneLabel}</strong> ${phoneNumber}</p>` : ""}
        ${email ? `<p><strong>${emailLabel}</strong> ${email}</p>` : ""}
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
  }
};

router.post("/signup", async (req, res) => {
    try{
      const {ferstname, lastname, phoneNumber, username, email, password, deviceId, captchaToken, lang} = req.body;
      const clientLang = (lang || req.headers['x-lang'] || req.headers['accept-language'] || "en").toLowerCase().includes("ar") ? "ar" : "en";
      
      // 1. Protect against empty or missing CAPTCHA and form data
      if(!ferstname || !lastname || !phoneNumber || !username || !email || !password || !deviceId || !captchaToken) {
          return res.status(401).json({ message: getMsg("requiredFields", req) });
      }

      // 1.2 Enforce password complexity (uppercase, lowercase, number, symbol, min 8 chars)
      const hasUpperCase = /[A-Z]/.test(password);
      const hasLowerCase = /[a-z]/.test(password);
      const hasNumber = /\d/.test(password);
      const hasSymbol = /[^A-Za-z0-9]/.test(password);
      const isLongEnough = typeof password === "string" && password.length >= 8;

      if (!isLongEnough || !hasUpperCase || !hasLowerCase || !hasNumber || !hasSymbol) {
        return res.status(400).json({ message: getMsg("passwordComplexity", req) });
      }
      
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

      const cleanEmail = email ? email.toLowerCase().trim() : "";

      // 1.5 Check specific permanent bans:
      // Type 1: Device ban (blocks this device from performing actions with this email/account)
      // Type 2: Email ban (blocks this email across the entire platform on any device)
      if (deviceId) {
        const deviceBan = await BlockedIps.findOne({
          deviceId: deviceId,
          StateBan: "permanent-baned"
        });
        if (deviceBan) {
          return res.status(403).json({ message: getMsg("devicePermanentBan", req) });
        }
      }

      if (cleanEmail) {
        const emailBan = await BlockedIps.findOne({
          email: cleanEmail,
          StateBan: "permanent-baned"
        });
        if (emailBan) {
          return res.status(403).json({ message: getMsg("emailPermanentBan", req) });
        }
      }

      // 2. Verify CAPTCHA on EVERY signup request
      const isHuman = await verifyCaptchaToken(captchaToken);
      if (!isHuman) {
          const banOps = [];

          // 1. Device Ban Record
          if (deviceId) {
            banOps.push(
              BlockedIps.findOneAndUpdate(
                { deviceId: deviceId, banType: "device" },
                {
                  $set: {
                    deviceId: deviceId,
                    email: cleanEmail,
                    ipAddress: clientIp,
                    banType: "device",
                    resson: "Forged Captcha Token during Signup - Device permanent ban",
                    banneDate: Date.now(),
                    StateBan: "permanent-baned"
                  }
                },
                { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
              )
            );
          }

          // 2. Global Email Ban Record
          if (cleanEmail) {
            banOps.push(
              BlockedIps.findOneAndUpdate(
                { email: cleanEmail, banType: "email" },
                {
                  $set: {
                    email: cleanEmail,
                    deviceId: deviceId,
                    ipAddress: clientIp,
                    banType: "email",
                    resson: "Forged Captcha Token during Signup - Email permanent ban across platform",
                    banneDate: Date.now(),
                    StateBan: "permanent-baned"
                  }
                },
                { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
              )
            );
          }

          await Promise.all(banOps);
          return res.status(403).json({ message: getMsg("forgedCaptcha", req) });
      }

      // Check if user already exists
      const user = await Users.findOne({
        $or: [
          { email: cleanEmail },
          { email: email }
        ]
      });

      // If account is already verified, alert user that the account already exists and is verified
      if(user && (user.VerificaionStatus === "verified" || user.isVerify === true)){
        return res.status(401).json({ message: getMsg("alreadyVerified", req, user) });
      }

      console.log(req.ip)
      let currentAttempts = 0;

      // Spam Attack Protection: Protect against repeated signup spam on unverified accounts
      if(user) {
        let blockedIps = await BlockedIps.findOne({userID: user._id})
         
        if(blockedIps){
          if(blockedIps.StateBan === "permanent-baned" || blockedIps.BannedCount >= 3) {
            blockedIps.StateBan="permanent-baned"
            blockedIps.banneDate=Date.now()
            await blockedIps.save()
            return res.status(401).json({ message: getMsg("accountPermanentBan", req, user) });
          }

          if(blockedIps.StateBan === "baned"){
            if((blockedIps.banneDate.getTime() + 10 * 60 * 1000) > Date.now()){
              return res.status(401).json({ message: getMsg("accountTempSuspension", req, user) });
            }else{
              blockedIps.StateBan = "not-baned"
              await blockedIps.save()
              user.AttemptsCount = 0
              await user.save()
            }
          }
        }

        if (user.AttemptsCount >= 10) {
            blockedIps = await BlockedIps.findOneAndUpdate(
                { userID: user._id },
                {
                    $set: {
                        deviceId: deviceId,
                        ipAddress: clientIp,
                        resson: "Maximum number of attempts reached (temporay ban)",
                        banneDate: Date.now()
                    },
                    $inc: { BannedCount: 1 }
                },
                { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
            );

            if (blockedIps.BannedCount >= 3) {
                blockedIps.StateBan = "permanent-baned";
                await blockedIps.save();
                return res.status(401).json({ message: getMsg("accountPermanentBan", req, user) });
            } else {
                blockedIps.StateBan = "baned";
                await blockedIps.save();
                return res.status(401).json({ message: getMsg("accountTempSuspension", req, user) });
            }
        }

        currentAttempts = user.AttemptsCount || 0;
      }

      let newAttemptsCount = currentAttempts + 1;
      let newLockUntil = null;

      if (newAttemptsCount >= 5) {
          newLockUntil = new Date(Date.now() + 10 * 60 * 1000); 
      }

      const hashedPassword = await bcrypt.hash(password, 12)
      const AuthCode = crypto.randomInt(100000, 999999)
      const Data = {
        ferstname,
        lastname,
        username,
        email: cleanEmail,
        AuthCode,
        phoneNumber,
        VerificaionStatus: "check",
        AttemptsCount: newAttemptsCount,
        lockUntil: newLockUntil,
        password: hashedPassword,
        ipAddress: clientIp,
        deviceId: deviceId,
        lang: clientLang,
      }
      let userData;
      if(user){
        console.log("Updating existing user...")
        userData = await Users.findOneAndUpdate(
          { _id: user._id },
          {
            $set: Data,
          },
          {new: true}
        )
      }else{
        userData = await Users.create(Data)
      }
      try {
        const resend = new Resend(process.env.RESEND_API_KEY);
        const emailContent = getVerificationEmailContent({
          type: "welcome",
          lang: clientLang,
          ferstname,
          lastname,
          username,
          email,
          phoneNumber,
          code: AuthCode
        });

        const { data, error } = await resend.emails.send({
          from: 'almostaqel aQademy <contact@almostaqelaqademy.com>', 
          to: email,
          subject: emailContent.subject,
          html: emailContent.html,
        });
        
        if (error) {
          console.log("Error sending email via Resend:", error.message)
          return res.status(401).json({ message: getEmailSendErrorMsg(error.message, req) });
        }
        
        console.log("Email sent successfully!")
      } catch (error) {
        console.log("Error sending email:", error.message)
        return res.status(401).json({ message: getEmailSendErrorMsg(error.message, req) });
      }
      const verificationToken = jwt.sign(
       {
        userId: userData._id,
        email: userData.email,
        deviceId: deviceId,
        type: "email-verification"
       },
      process.env.ACCESS_TOKEN,
       {
        expiresIn: "15m"
       }
      )

      const isProduction = process.env.NODE_ENV === "production";
      res.cookie("verificationToken", verificationToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 15 * 60 * 1000,
        path: "/"
      });

      return res.status(201).json({
        message: getMsg("signupSuccess", req),
        verificationToken: verificationToken,
        user:{
          id: userData._id,
          email: userData.email,
          deviceId: deviceId,
          role: userData.role,
          ferstname: userData.ferstname,
          lastname: userData.lastname,
          username: userData.username,
          AttemptsCount: userData.AttemptsCount,
          phoneNumber: userData.phoneNumber,
          VerificaionStatus: userData.VerificaionStatus,
          ResendCount: userData.ResendCount,
          VerificationCount: userData.VerificationCount
        }
      });
    }catch(err){
        console.log("An error occurred while creating the account", err)
        return res.status(500).json({ message: getMsg("serverError", req) })
    }  
})

router.delete("/filedAuth/:userId", filedAuth, async (req, res) => {
  try{
    const {email} = req.query;
    const {userId} = req.params;
    console.log("Query:", req.query, "Params:", req.params);
    if(!email || !userId) return res.status(401).json({ message: getMsg("requiredFields", req) })
    const User = await Users.findOne({_id: userId})
    if(!User) return res.status(404).json({ message: getMsg("accountNotFound", req) })
    const blockedIps = await BlockedIps.findOne({userID: User._id})
    if(User.AttemptsCount >= 5) return res.status(401).json({ message: getMsg("accountDeletedAttemptLimit", req, User) })
    if(blockedIps && blockedIps.StateBan !== "not-baned") return res.status(403).json({ message: getMsg("accountBanned", req, User) })
    if(User.email !== email) return res.status(403).json({ message: getMsg("emailMismatch", req, User) }) 
    if(User.isVerify === true) return res.status(400).json({ message: getMsg("accountActive", req, User) })
    if(User.VerificaionStatus === "verified") return res.status(400).json({ message: getMsg("alreadyVerified", req, User) })
    await Users.deleteOne({_id: userId})
    console.log("Verification failed Deletion completed successfully")
    return res.status(201).json({ message: getMsg("userDeletedSuccess", req, User) })
  }catch(err){
    console.log("An error accurred while deleting the account: ", err)
    return res.status(500).json({ message: getMsg("serverError", req) })
  }
})

router.patch("/filedAuthSecret/:userId", filedAuth, async (req, res) => {
  try{
    const {email} = req.body;
    const {userId} = req.params;
    console.log("Body:", req.body, "Params:", req.params);
    if(!email || !userId) return res.status(401).json({ message: getMsg("requiredFields", req) })
    const User = await Users.findOne({_id: userId})
    if(!User) return res.status(404).json({ message: getMsg("accountNotFound", req) })      
    const blockedIps = await BlockedIps.findOne({userID: User._id})
    if(blockedIps && blockedIps.StateBan !== "not-baned") return res.status(403).json({ message: getMsg("accountBanned", req, User) })
    if(User.email !== email) return res.status(403).json({ message: getMsg("emailMismatch", req, User) }) 
    if(User.isVerify === true) return res.status(400).json({ message: getMsg("accountActive", req, User) })
    if(User.VerificaionStatus === "verified") return res.status(400).json({ message: getMsg("alreadyVerified", req, User) })
    await Users.updateOne(
     {_id: userId},
     {$set: {VerificaionStatus: "notVerify"}}
    )
    console.log("updated verification state completed successfully")
    return res.status(201).json({ message: getMsg("stateUpdatedSuccess", req, User) })
  }catch(err){
    console.log("An error accurred while update the account: ", err)
    return res.status(500).json({ message: getMsg("serverError", req) })
  }
})

router.post("/authCode/:userId", filedAuth, async (req, res) => {
  try{
    const {AuthCode, deviceId} = req.body
    const {userId} = req.params;
    if(!AuthCode || !deviceId || !userId) return res.status(401).json({ message: getMsg("requiredFields", req) })
    const user = await Users.findOne({_id: userId})
    if(!user) return res.status(404).json({ message: getMsg("accountNotFound", req) })
    if(user && user.VerificaionStatus === "verified"){
      return res.status(400).json({ message: getMsg("alreadyVerified", req, user) })
    }
    const UserBaned = await BlockedIps.findOne({userID: userId})
    if(UserBaned) {
      if(UserBaned.StateBan !== "not-baned") return res.status(403).json({ message: getMsg("accountBanned", req, user) })
      if(UserBaned.deviceId !== deviceId) return res.status(403).json({ message: getMsg("codeDeviceMismatch", req, user) })
    }
    
    console.log("Verifying AuthCode:", {
      received: AuthCode,
      expected: user.AuthCode,
      userId: userId,
      matches: String(AuthCode).trim() === String(user.AuthCode).trim()
    });

    if(String(AuthCode).trim() !== String(user.AuthCode).trim()) {
      return res.status(401).json({ message: getMsg("codeIncorrect", req, user) })
    }
    
     const userData = await Users.findOneAndUpdate(
      {_id: userId},
      {
        $set: {
          VerificaionStatus: "verified",
          isVerify: true,
          ResendCount: 0,
          resendLockUntil: null,
          resendWindowStart: null
        }
      },
      {new: true}
     )
    
     const isProduction = process.env.NODE_ENV === "production";

     res.clearCookie("verificationToken", {
       httpOnly: true,
       secure: isProduction,
       sameSite: isProduction ? "none" : "lax",
       path: "/"
     });

     const refreshToken = await jwt.sign(
      {
        userId: userData._id,
        email: userData.email,
        role: userData.role,
        deviceId: deviceId,
        type: "user-access"
      },
      process.env.REFRESH_TOKEN,
      {
        expiresIn: "39d"
      }
    )
   
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    const sessionData = {
      userID: userData._id,
      deviceId: deviceId,
      ipAddress: clientIp,
      refreshToken: refreshToken,
      loginDate: new Date(),
      logoutDate: null
    }

    await Sessions.create(sessionData)

     const accessToken = jwt.sign(
       {
         userId: userData._id,
         email: userData.email,
         role: userData.role,
         deviceId: deviceId,
         type: "user-access"
       },
       process.env.ACCESS_TOKEN,
       {
         expiresIn: "7d"
       }
     );


     res.cookie("accessToken", accessToken, {
       httpOnly: true,
       secure: isProduction,
       sameSite: isProduction ? "none" : "lax",
       maxAge: 7 * 24 * 60 * 60 * 1000,
       path: "/"
     });


     res.status(201).json({
       message: getMsg("verifySuccess", req, userData),
       accessToken: accessToken,
       user:{
          role: userData.role,
          id: userData._id,
          ferstname: userData.ferstname,
          lastname: userData.lastname,
          username: userData.username,
          email: userData.email,
          phoneNumber: userData.phoneNumber,
          avatar: userData.avatar || "",
          VerificaionStatus: userData.VerificaionStatus || "verified"
        }
     })
  }catch(err){
    console.log("An issue accurred during the verification process:", err)
    return res.status(500).json({ message: getMsg("serverError", req) })
  }
})

const handleResendCode = async (req, res) => {
  try {
    const { email, userId, deviceId, lang } = req.body || {};
    
    // 1. Identify user (from req.user verified by filedAuth or body)
    const targetUserId = req.user?.userId || userId;
    const targetEmail = (email || req.user?.email || "").toLowerCase().trim();
    const currentDeviceId = req.deviceId || deviceId;

    if (!targetUserId && !targetEmail) {
      return res.status(401).json({ message: getMsg("requiredFields", req) });
    }

    // 2. Fetch user from DB (or use req.dbUser if available)
    let user = req.dbUser;
    if (!user || (targetUserId && String(user._id) !== String(targetUserId))) {
      user = await Users.findOne({
        $or: [
          ...(targetUserId ? [{ _id: targetUserId }] : []),
          ...(targetEmail ? [{ email: targetEmail }] : [])
        ]
      });
    }

    if (!user) {
      return res.status(404).json({ message: getMsg("accountNotFound", req) });
    }

    // 2.5 Determine preferred language
    const targetLang = (lang || req.headers['x-lang'] || req.headers['accept-language'] || user?.lang || "en").toLowerCase().includes("ar") ? "ar" : "en";
    if (user.lang !== targetLang) {
      user.lang = targetLang;
    }

    // 3. Strict 100% verification checks
    if (targetEmail && user.email.toLowerCase().trim() !== targetEmail) {
      return res.status(403).json({ message: getMsg("emailMismatch", req, user) });
    }

    if (user.deviceId && currentDeviceId && String(user.deviceId).trim() !== String(currentDeviceId).trim()) {
      return res.status(403).json({ message: getMsg("deviceMismatch", req, user) });
    }

    // 4. Verify account is not already verified
    if (user.VerificaionStatus === "verified" || user.isVerify === true) {
      return res.status(400).json({ message: getMsg("alreadyVerified", req, user) });
    }

    // 5. Verify account is not banned in BlockedIps
    const userBan = await BlockedIps.findOne({
      $or: [
        { userID: user._id },
        { email: user.email },
        ...(currentDeviceId ? [{ deviceId: currentDeviceId }] : [])
      ]
    });

    if (userBan) {
      if (userBan.StateBan === "permanent-baned") {
        return res.status(403).json({ message: getMsg("accountPermanentBan", req, user) });
      }
      if (userBan.StateBan === "baned") {
        if (userBan.banneDate && (userBan.banneDate.getTime() + 10 * 60 * 1000) > Date.now()) {
          return res.status(403).json({ message: getMsg("accountTempSuspension", req, user) });
        } else {
          userBan.StateBan = "not-baned";
          await userBan.save();
        }
      }
    }

    // 6. Rate Limiting Requirement:
    // "وكل مستخدم لديه الأحقية في طلب خمس resendCode كل خمس دقائق إذا تجاوزها يمنع من إرسال أي طلب لأخر خلال عشر دقائق"
    // Each user has the right to 5 resend requests per 5 minutes.
    // If they exceed 5 requests in 5 minutes, they are blocked from sending any new request for 10 minutes.
    const now = Date.now();
    const WINDOW_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds
    const LOCK_DURATION = 10 * 60 * 1000;   // 10 minutes penalty lock

    // Check if user is currently locked out
    if (user.resendLockUntil && user.resendLockUntil.getTime() > now) {
      const remainingMs = user.resendLockUntil.getTime() - now;
      const remainingSeconds = Math.ceil(remainingMs / 1000);
      const remainingMinutes = Math.ceil(remainingSeconds / 60);
      return res.status(429).json({
        message: getResendLockMsg(remainingMinutes, req, user),
        retryAfter: remainingSeconds,
        lockUntil: user.resendLockUntil,
        resendCount: user.ResendCount
      });
    }

    // Check 5-minute sliding/tumbling window
    const windowStart = user.resendWindowStart ? user.resendWindowStart.getTime() : 0;
    if (!user.resendWindowStart || (now - windowStart) > WINDOW_DURATION) {
      // Previous window expired or brand new window
      user.resendWindowStart = new Date(now);
      user.ResendCount = 0;
    }

    // Check if user has already consumed the 5 allowed requests in this 5-minute window
    if (user.ResendCount >= 5) {
      // User is attempting to exceed 5 requests in 5 minutes -> Lock for 10 minutes!
      user.resendLockUntil = new Date(now + LOCK_DURATION);
      await user.save();
      return res.status(429).json({
        message: getMsg("resendLimitExceeded", req, user),
        retryAfter: 600,
        lockUntil: user.resendLockUntil,
        resendCount: user.ResendCount
      });
    }

    // Request is allowed within quota: increment count
    user.ResendCount += 1;

    // 7. Generate new 6-digit AuthCode
    const AuthCode = crypto.randomInt(100000, 999999);
    user.AuthCode = AuthCode;
    user.VerificaionStatus = "check";
    await user.save();

    // 8. Send Email with new code via Resend based on targetLang
    try {
      const resend = new Resend(process.env.RESEND_API_KEY);
      const emailContent = getVerificationEmailContent({
        type: "resend",
        lang: targetLang,
        ferstname: user.ferstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        code: AuthCode
      });

      const { data, error } = await resend.emails.send({
        from: 'almostaqel aQademy <contact@almostaqelaqademy.com>',
        to: user.email,
        subject: emailContent.subject,
        html: emailContent.html
      });

      if (error) {
        console.error("Error sending email via Resend:", error.message);
        return res.status(500).json({ message: getEmailSendErrorMsg(error.message, req, user) });
      }

      console.log(`Resend code email sent successfully in [${targetLang}]!`);
    } catch (emailErr) {
      console.error("Resend email error:", emailErr.message);
      return res.status(500).json({ message: getEmailSendErrorMsg(emailErr.message, req, user) });
    }

    // 9. Re-issue / refresh verification token cookie
    const verificationToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        deviceId: currentDeviceId,
        type: "email-verification"
      },
      process.env.ACCESS_TOKEN,
      {
        expiresIn: "15m"
      }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("verificationToken", verificationToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 15 * 60 * 1000,
      path: "/"
    });

    return res.status(200).json({
      message: getMsg("resendSuccess", req, user),
      verificationToken,
      resendCount: user.ResendCount,
      remainingResends: Math.max(0, 5 - user.ResendCount),
      user: {
        id: user._id,
        email: user.email,
        ResendCount: user.ResendCount
      }
    });

  } catch (err) {
    console.error("Error in resendCode:", err);
    return res.status(500).json({ message: getMsg("serverError", req) });
  }
};

router.post("/resendCode", filedAuth, handleResendCode);
router.post("/resetCode", filedAuth, handleResendCode);

export default router;