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
const router = express.Router()

router.post("/signup", async (req, res) => {
    try{
      const {ferstname, lastname, phoneNumber, username, email, password, deviceId, captchaToken} = req.body;
      
      // 1. Protect against empty or missing CAPTCHA and form data
      if(!ferstname || !lastname || !phoneNumber || !username || !email || !password || !deviceId || !captchaToken) {
          return res.status(401).json({message: "Verify the entered information (form and captcha are required)"});
      }
      
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

      // 2. Verify CAPTCHA on EVERY signup request
      const isHuman = await verifyCaptchaToken(captchaToken);
      if (!isHuman) {
          await BlockedIps.findOneAndUpdate(
            { deviceId: deviceId },
            {
              $set: {
                deviceId: deviceId,
                ipAddress: clientIp,
                resson: "Forged Captcha Token during Signup (Permanent ban)",
                banneDate: Date.now(),
                StateBan: "permanent-baned"
              }
            },
            { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
          );
          return res.status(401).json({message: "Your device has been permanently blocked due to suspicious activity."});
      }

      const user = await Users.findOne({email})

      if(user && user.VerificaionStatus === "verified"){
        return res.status(401).json({message: "ensure the courag of the entered information"})
      }

      const deviceBanRecord = await BlockedIps.findOne({
        deviceId: deviceId,
        StateBan: "permanent-baned"
      });
      
      if(deviceBanRecord){
         return res.status(401).json({message: "Your device is permanently banned."})
      }

      console.log(req.ip)
      let currentAttempts = 0;

      if(user) {
        let blockedIps = await BlockedIps.findOne({userID: user._id})
         
        if(blockedIps){
          if(blockedIps.StateBan === "permanent-baned" || blockedIps.BannedCount >= 3) {
            blockedIps.StateBan="permanent-baned"
            blockedIps.banneDate=Date.now()
            await blockedIps.save()
            return res.status(401).json({message: "You are permanently banned on this device. 2"})
          }

          if(blockedIps.StateBan === "baned"){
            if((blockedIps.banneDate.getTime() + 10 * 60 * 1000) > Date.now()){
              return res.status(401).json({message: "This account is temporarily suspended; please wait until the suspension period ends."})
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
                return res.status(401).json({ message: "You are permanently banned on this device." });
            } else {
                blockedIps.StateBan = "baned";
                await blockedIps.save();
                return res.status(401).json({ message: "This account is temporarily suspended; please wait until the suspension period ends." });
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
        email,
        AuthCode,
        phoneNumber,
        VerificaionStatus: "check",
        AttemptsCount: newAttemptsCount,
        lockUntil: newLockUntil,
        password: hashedPassword,
        ipAddress: clientIp,
        deviceId: deviceId,
      }
      let userData;
      if(user){
        console.log("Updating existing user...")
        userData = await Users.findOneAndUpdate(
          {email: email},
          {
            $set: Data,
          },
          {returnDocument: "after"}
        )
      }else{
        userData = await Users.create(Data)
      }
//       try {
//         const { data, error } = await resend.emails.send({
//           from: 'ALMOSTAEL AQADIMY <onboarding@resend.dev>', 
//           to: email,
//           subject: 'Welcome to ALMOSTAEL AQADIMY!',
//           html: `
// <!DOCTYPE html>
// <html>
// <head>
//   <style>
//     body {
//       font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
//       background-color: #07070f;
//       color: #f0efff;
//       margin: 0;
//       padding: 40px 20px;
//     }
//     .container {
//       max-width: 600px;
//       margin: 0 auto;
//       background-color: #13111c;
//       border: 1px solid #1f1b2e;
//       border-radius: 16px;
//       overflow: hidden;
//     }
//     .header {
//       background: linear-gradient(to right, #9333ea, #ec4899);
//       padding: 30px 20px;
//       text-align: center;
//     }
//     .header h1 {
//       margin: 0;
//       color: #ffffff;
//       font-size: 24px;
//       letter-spacing: 1px;
//     }
//     .content {
//       padding: 40px 30px;
//     }
//     .greeting {
//       font-size: 20px;
//       font-weight: 600;
//       margin-bottom: 20px;
//     }
//     .message {
//       color: #cbd5e1;
//       line-height: 1.6;
//       margin-bottom: 30px;
//     }
//     .code-box {
//       background-color: #07070f;
//       border: 1px solid #1f1b2e;
//       border-radius: 12px;
//       padding: 20px;
//       text-align: center;
//       margin-bottom: 30px;
//     }
//     .code {
//       font-size: 32px;
//       font-weight: 700;
//       color: #a855f7;
//       letter-spacing: 8px;
//       margin: 0;
//     }
//     .details {
//       background-color: rgba(139, 92, 246, 0.05);
//       border-left: 4px solid #8b5cf6;
//       padding: 15px 20px;
//       border-radius: 4px;
//     }
//     .details p {
//       margin: 5px 0;
//       color: #cbd5e1;
//     }
//     .details strong {
//       color: #f0efff;
//     }
//     .footer {
//       text-align: center;
//       padding: 20px;
//       color: #64748b;
//       font-size: 12px;
//       border-top: 1px solid #1f1b2e;
//     }
//   </style>
// </head>
// <body>
//   <div class="container">
//     <div class="header">
//       <h1>ALMOSTAEL AQADIMY</h1>
//     </div>
//     <div class="content">
//       <div class="greeting">Hello ${ferstname} ${lastname},</div>
//       <div class="message">
//         Welcome to ALMOSTAEL AQADIMY! We are thrilled to have you on board. Please use the verification code below to complete your registration.
//       </div>
//       <div class="code-box">
//         <p style="margin-top: 0; color: #64748b; font-size: 14px; text-transform: uppercase;">Verification Code</p>
//         <p class="code">${AuthCode}</p>
//       </div>
//       <div class="details">
//         <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">Your Account Details:</p>
//         <p><strong>Username:</strong> ${username}</p>
//         <p><strong>Phone:</strong> ${phoneNumber}</p>
//       </div>
//     </div>
//     <div class="footer">
//       &copy; ${new Date().getFullYear()} ALMOSTAEL AQADIMY. All rights reserved.<br>
//       If you didn't request this email, please ignore it.
//     </div>
//   </div>
// </body>
// </html>
//           `,
//         });
        
//         if (error) {
//           console.log("Error sending email via Resend:", error.message)
//           return res.status(401).json({ message: `Error sending email: ${ error.message}` });
//         }
        
//         console.log("Email sent successfully!")
//       } catch (error) {
//         console.log("Error sending email:", error.message)
//         return res.status(401).json({ message: `Error sending email: ${ error.message}` });
//       }
      const accessToken = jwt.sign(
        {
        userId: userData._id,
        email: userData.email,
        type: "email-verification"
      },
      process.env.ACCESS_TOKEN,
      {
        expiresIn: "15m"
      }
    )
      return res.status(201).json({

        message: "user created seccessfly",
        accessToken,
        AuthCode,
        user:{
        id: userData._id,
        deviceId: deviceId,
        role: userData.role,
        ferstname: userData.ferstname,
        lastname: userData.lastname,
        username: userData.username,
        email: userData.email,
        AttemptsCount: userData.AttemptsCount,
        phoneNumber: userData.phoneNumber,
        VerificaionStatus: userData.VerificaionStatus,
        ResendCount: userData.ResendCount,
        VerificationCount: userData.VerificationCount
        }
      })
    }catch(err){
        console.log("An error occurred while creating the account", err)
        return res.status(500).json({message: `An error occurred while creating the account" ${err}`})
    }
})



router.delete("/filedAuth/:userId", filedAuth, async (req, res) => {
  try{
    const {email} = req.query;
    const {userId} = req.params;
    console.log("Query:", req.query, "Params:", req.params);
    if(!email || !userId) return res.status(401).json({message: `Verify the entered information. Email received: ${email}, UserID received: ${userId}`})
    const User = await Users.findOne({_id: userId})
    if(!User) return res.status(401).json({message: "This account does not exist"})
    const blockedIps = await BlockedIps.findOne({userID: User._id})
    if(User.AttemptsCount >= 5) return res.status(401).json({message: "This account cannot be deleted due to the exhaustion of login attempts."})
    if(blockedIps && blockedIps.StateBan !== "not-baned") return res.status(401).json({message: "This accunt is banned"})
    if(User.email !== email) return res.status(401).json({message: "Deletion process failes (Verify the entred email)"}) 
    if(User.isVerify === true) return res.status(401).json({message: "Deletion process failes (this account is currently active)"})
    if(User.VerificaionStatus === "verified") return res.status(401).json({message: "Deletion process failes (Verification has been cmpleted for this accunt)"})
    await Users.deleteOne({_id: userId})
    console.log("Verification failed Deletion completed successfully")
    return res.status(201).json({message: "user deleted seccessfuly"})
  }catch(err){
    console.log("An error accurred while deleting the account: ", err)
    return res.status(500).json({message: "An error accurred while deleting the account: ", err})
  }
})

router.patch("/filedAuthSecret/:userId", filedAuth, async (req, res) => {
  try{
    const {email} = req.body;
    const {userId} = req.params;
    console.log("Body:", req.body, "Params:", req.params);
    if(!email || !userId) return res.status(401).json({message: `Verify the entered information. Email received: ${email}, UserID received: ${userId}`})
    const User = await Users.findOne({_id: userId})
    if(!User) return res.status(401).json({message: "This account does not exist"})      
    const blockedIps = await BlockedIps.findOne({userID: User._id})
    if(blockedIps && blockedIps.StateBan !== "not-baned") return res.status(401).json({message: "This accunt is banned"})
    if(User.email !== email) return res.status(401).json({message: "Deletion process failes (Verify the entred email)"}) 
    if(User.isVerify === true) return res.status(401).json({message: "Deletion process failes (this account is currently active)"})
    if(User.VerificaionStatus === "verified") return res.status(401).json({message: "Deletion process failes (Verification has been cmpleted for this accunt)"})
    await Users.updateOne(
     {_id: userId},
     {$set: {VerificaionStatus: "notVerify"}}
    )
    console.log("updated verification state completed successfully")
    return res.status(201).json({message: "updated verification state completed successfully"})
  }catch(err){
    console.log("An error accurred while update the account: ", err)
    return res.status(500).json({message: "An error accurred while update the account: ", err})
  }
})

router.post("/authCode/:userId", filedAuth, async (req, res) => {
  try{
    const {AuthCode, deviceId} = req.body
    const {userId} = req.params;
    const accessToken = req.headers.authorization;
    if(!AuthCode || !deviceId || !userId) return res.status(401).json({message: "Make sure to enter all the required information."})
      const user = await Users.findOne({_id: userId})
      if(!user) return res.status(401).json({message: ""})
      if(user && user.VerificaionStatus === "verified"){
        return res.status(401).json({message: "ensure the courag of the entered information"})
    }
    const UserBaned = await BlockedIps.findOne({userID: userId})
    if(UserBaned) {
      if(UserBaned.StateBan !== "not-baned") return res.status(401).json({message: "This accunt is banned"})
      if(UserBaned.deviceId !== deviceId) return res.status(401).json({message: "This code is not valid for this device."})
    }
    
    if(Number(AuthCode) !== user.AuthCode) return res.status(401).json({message: "This code is incorrect. Please verify the code sent to this email."})
    
     const userData = await Users.findOneAndUpdate(
      {_id: userId},
      {$set: {VerificaionStatus: "verified"}},
      {new: true}
     )
    
     res.status(201).json({
     message: "signup seccessfuly",
     accessToken,
     user:{
        role: userData.role,
        id: userData._id,
        ferstname: userData.ferstname,
        lastname: userData.lastname,
        username: userData.username,
        email: userData.email,
        phoneNumber: userData.phoneNumber
      }
    })
  }catch(err){
    console.log("An issue accurred during the verification process:", err)
    return res.status(500).json({message: `An issue accurred during the verification process: ${err}`})
  }
})

router.post("/resendCode", filedAuth, async (req, res) => {
  const {email, userId} = req.body
  if(!email || !userId) return res.status(401).json({message: "Verify the entered information"})
  const user = await Users.findOne({_id: userId})
  if(!user) return res.status(401).json({message: "This account does not exist"})
  if(user.email !== email) return res.status(401).json({message: "Deletion process failes (Verify the entred email)"}) 
})

export default router;