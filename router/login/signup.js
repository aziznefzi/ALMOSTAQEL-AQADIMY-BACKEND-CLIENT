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
const router = express.Router()

const transporter = nodemailer.createTransport({
  host: '108.177.15.108',
  port: 587,
  secure: false,
  requireTLS: true,
  tls: {
    servername: 'smtp.gmail.com'
  },
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

router.post("/signup", async (req, res) => {
    try{
      const {ferstname, lastname, phoneNumber, username, email, password, deviceId} = req.body;
      if(!ferstname || !lastname || !phoneNumber || !username || !email || !password || !deviceId) return res.status(401).json({message: "Verify the entered information"})
      const user = await Users.findOne({email})
      const IpBanRecord = await BlockedIps.findOne({deviceId: deviceId})
      
      if(IpBanRecord){
        if(IpBanRecord.StateBan === "permanent-baned"){
          return res.status(401).json({message: "You are permanently banned on this device."})
        }
      }

      console.log(req.ip)
      let currentAttempts = 0;

      if(user) {
        const blockedIps = await BlockedIps.findOne({userID: user._id})
         if(blockedIps){
          if(blockedIps.StateBan === "permanent-baned" || blockedIps.BannedCount >= 3) {
            blockedIps.StateBan="permanent-baned"
            blockedIps.banneDate=Date.now()
            await blockedIps.save()
            return res.status(401).json({message: "You are permanently banned on this device."})
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

          if(blockedIps.StateBan === "not-baned" && user.AttemptsCount >= 10){
              blockedIps.BannedCount+=1
                if(blockedIps.BannedCount >= 3 ){
                  blockedIps.StateBan = "permanent-baned";
                  blockedIps.banneDate = Date.now()
                  await blockedIps.save()
                  return res.status(401).json({message: "You are permanently banned on this device."})
                }else{
                  blockedIps.StateBan="baned"
                  blockedIps.banneDate=Date.now()
                  await blockedIps.save()
                  return res.status(401).json({message: "This account is temporarily suspended; please wait until the suspension period ends."});
                }
            }          
         }

        if(user.VerificaionStatus === "verified"){
           return res.status(401).json({message: "ensure the courag of the entered information"})
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
          const {captchaToken} = req.body
          if(!captchaToken) {
            if(user.AttemptsCount >= 10) {
              let ipRecord = await BlockedIps.findOneAndUpdate(
                  { userID: user._id },
                  {
                      $set: {
                          deviceId: deviceId,
                          resson: "Maximum number of attempts reached (temporay ban)",
                          banneDate: Date.now()
                      },
                      $inc: { BannedCount: 1 }
                  },
                  { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
              );
              if (ipRecord.BannedCount >= 3) {
                  ipRecord.StateBan = "permanent-baned";
              } else {
                  ipRecord.StateBan = "baned";
              }
              await ipRecord.save();

              return res.status(401).json({ message: "Access was denied. Please try again later." });
            }
            user.AttemptsCount += 1
            await user.save()
            return res.status(428).json({
            code: "CAPTCHA_REQUIRED",
            message: `You have exhausted the allowed number of attempts; Please verify are human.`
            });
          }
          const isHuman = await verifyCaptchaToken(captchaToken)
          if(!isHuman) {
            await BlockedIps.findOneAndUpdate(
              { userID: user._id },
              {
                $set: {
                  deviceId: deviceId,
                  resson: "Invallid Verification Token (Permanent ban)",
                  banneDate: Date.now(),
                  StateBan: "permanent-baned"
                }
              },
              { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
            )
            return res.status(401).json({message: "Your account and device have been permanently blocked due to suspicious activity"})
          }
          currentAttempts = 0;
          user.lockUntil = undefined;
          user.AttemptsCount = 0
        }

        if (user.lockUntil && user.lockUntil <= Date.now()) {
          currentAttempts = 0;
          user.lockUntil = undefined;
          user.AttemptsCount = 0
        } else {
            currentAttempts = user.AttemptsCount || 0;
        }
      }

      let newAttemptsCount = currentAttempts + 1;
      let newLockUntil = null;

      if (newAttemptsCount >= 5) {
          newLockUntil = new Date(Date.now() + 10 * 60 * 1000); 
      }

      console.log("Start hashing password...")
      const hashedPassword = await bcrypt.hash(password, 12)
      console.log("Password hashed. Generating AuthCode...")
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
        console.log("Creating new user...")
        userData = await Users.create(Data)
      }
      console.log("User saved in DB. Attempting to send email...")
      try {
        await transporter.sendMail({
          from: '"ALMOSTAEL AQADIMY" almostaqelacademy@gmail.com', 
          to: email,
          subject: 'Welcome to ALMOSTAEL AQADIMY!',
          html: `
<!DOCTYPE html>
<html>
<head>
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
      <div class="greeting">Hello ${ferstname} ${lastname},</div>
      <div class="message">
        Welcome to ALMOSTAEL AQADIMY! We are thrilled to have you on board. Please use the verification code below to complete your registration.
      </div>
      <div class="code-box">
        <p style="margin-top: 0; color: #64748b; font-size: 14px; text-transform: uppercase;">Verification Code</p>
        <p class="code">${AuthCode}</p>
      </div>
      <div class="details">
        <p style="margin-top: 0; margin-bottom: 10px; font-weight: 600; color: #f0efff;">Your Account Details:</p>
        <p><strong>Username:</strong> ${username}</p>
        <p><strong>Phone:</strong> ${phoneNumber}</p>
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} ALMOSTAEL AQADIMY. All rights reserved.<br>
      If you didn't request this email, please ignore it.
    </div>
  </div>
</body>
</html>
          `,
        });
        console.log("Email sent successfully!")
      } catch (error) {
        console.log("Error sending email:", error.message)
        return res.status(401).json({ message: `Error sending email: ${ error.message}` });
      }
      console.log("Generating access token...")
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
      console.log("Sending successful response back to frontend...")
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
    if(!email || !userId) return res.status(401).json({message: "Verify the entered information"})
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
    console.log(email, userId)
    if(!email || !userId) return res.status(401).json({message: "Verify the entered information"})
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

router.post("/resendCode", filedAuth, async (req, res) => {
  const {email, userId} = req.body
  if(!email || !userId) return res.status(401).json({message: "Verify the entered information"})
  const user = await Users.findOne({_id: userId})
  if(!user) return res.status(401).json({message: "This account does not exist"})
  if(user.email !== email) return res.status(401).json({message: "Deletion process failes (Verify the entred email)"}) 
})

export default router;