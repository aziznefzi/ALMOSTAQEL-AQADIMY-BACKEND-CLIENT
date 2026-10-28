import bcrypt from "bcrypt"
import { Users } from "../schema/users.js"

export const CreateAdminAccunt = async () => {
  try {
    const admin = await Users.findOne({ role: "admin" })
    if (admin) {
      console.log("Admin account already exists")
      return
    }

    const hashedPassword = await bcrypt.hash(process.env.ADMIN_DASHBORD_PASS, 10)
    const ENVdeviceId = process.env.ADMIN_DEVISE_ID
    const hashedDeviceId = await bcrypt.hash(ENVdeviceId, 10)

    await Users.create({
      role: "admin",
      email: process.env.ADMIN_DASHBORD_USER,
      password: hashedPassword,
      ferstname: "Admin",
      lastname: "Admin",
      username: "Admin",
      isVerify: true,
      VerificaionStatus: "verified",
      authProvider: "local",
      deviceId: hashedDeviceId
    })
    console.log("Admin account created successfully")
  } catch (err) {
    console.log(`an issue occurred while creating the admin account => ${err.message}`)
  }
}