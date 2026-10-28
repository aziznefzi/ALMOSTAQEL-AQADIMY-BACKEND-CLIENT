import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Users } from "../schema/users.js";

const router = express.Router()

router.post("/login", async (req,res)=>{
    const {email, password, deviceId} = req.body
    try{
        if(!email || !password || !deviceId) return res.status(400).json({message:"All fields are required"})    
        const user = await Users.findOne({email})
        if(!user) return res.status(404).json({message:"Account not found"})
        if(user.role !== "admin") return res.status(403).json({message:"You are not authorized to login"})
        const DeviceIdBycrept = await bcrypt.compare(deviceId, user.deviceId) 
        if(!DeviceIdBycrept) return res.status(403).json({message:"You are not authorized to login"})
        if(user.blockedUntil && user.blockedUntil > Date.now()) {
            return res.status(429).json({message:"Too many attempts, please try again later"})
        }
        if(user.blockedUntil && user.blockedUntil <= Date.now()) {
            user.AttemptsCount = 0
            user.blockedUntil = null
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch) {
            user.AttemptsCount++
            if(user.AttemptsCount >= 3) user.blockedUntil = Date.now() + 1000 * 60 * 15
            await user.save()
            return res.status(401).json({message:"Invalid credentials"})
        }
        user.AttemptsCount = 0
        user.blockedUntil = null
        await user.save()
        const token = jwt.sign({userId:user._id, email:user.email, role:user.role, type:"admin-access"},process.env.ADMIN_TOKEN_SECRET,{expiresIn:"1h"})
        res.status(200).json({message:"Login successful",token, role: user.role, email: user.email })
    }catch(err){
        console.log(err)
        res.status(500).json({message:err})
    }
})

export default router