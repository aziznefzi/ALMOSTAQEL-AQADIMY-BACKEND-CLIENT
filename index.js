import "dotenv/config"
import dns from "dns"
dns.setDefaultResultOrder('ipv4first')
import express from "express"
import cors from "cors"
import login from "./router/login/login.js"
import signup from "./router/login/signup.js"
import googleAuth from "./router/login/googleAuth.js"
import forgotPassword from "./router/login/forgotPassword.js"
import servicesRouter from "./services/Services.js"
import supportRouter from "./router/support/support.js"
import connectDB from "./config/db.js"
import AdminLogin from "./Admin/Login.js"
import "./jobs/deleteFindUser.js"
import cookieParser from "cookie-parser"
import path from "path"
import { fileURLToPath } from "url"
import { getMsg } from "./utils/messages.js"
import getUsers from "./Admin/routes/Users/getUsers.js"
import DeleteUser from "./Admin/routes/Users/DeleteUser.js"
import UserBaned from "./Admin/routes/Users/UserBaned.js"
import updateUsers from "./Admin/routes/Users/updateUsers.js"
import mongoose from "mongoose"
import bcrypt from "bcrypt"
import { CreateAdminAccunt } from "./Admin/AminAccunt.js"
import learningAdminRouter from "./Admin/routes/Learning/learning.js"
import learningClientRouter from "./router/learning/learning.js"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(cookieParser())
app.use(express.json())
app.use("/uploads", express.static(path.join(__dirname, "uploads")))
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: getMsg("invalidJson", req) });
  }
  next();
})


const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:3000",
  "https://almostaqelaqademy.com",
  "https://www.almostaqelaqademy.com",
  "https://client.almostaqelaqademy.com",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or Postman) or local LAN development IPs
    if (
      !origin ||
      allowedOrigins.includes(origin) ||
      /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$/.test(origin)
    ) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "x-device-id", "x-lang", "Accept-Language"]
}));


// if (mongoose.connection.readyState === 1) {
//   CreateAdminAccunt();
// } else {
//   mongoose.connection.once("connected", () => {
//     CreateAdminAccunt();
//   });
// }

connectDB()

const port = process.env.PORT || 3000

//user router
app.use("/auth", login)
app.use("/auth", signup)
app.use("/auth", googleAuth)
app.use("/auth", forgotPassword)
app.use("/api", servicesRouter)
app.use("/api", supportRouter)
app.use("/api", learningClientRouter)

app.listen(port, () => {
  console.log(`server running is ${port}`)
})

// // admin router: separate app, reachable only from localhost on a different port
// const adminPort = process.env.ADMIN_PORT || 4000
// const adminApp = express()
// adminApp.use(cookieParser())
// adminApp.use(express.json())
// adminApp.use("/uploads", express.static(path.join(__dirname, "uploads")))
// adminApp.use(cors({
//   origin: ["http://localhost:5173", "http://localhost:5174"],
//   credentials: true,
//   methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
//   allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "x-device-id", "x-lang", "Accept-Language"]
// }))
// adminApp.use("/admin/auth", AdminLogin)
// adminApp.use("/admin/", getUsers)
// adminApp.use("/admin/", DeleteUser)
// adminApp.use("/admin/", UserBaned)
// adminApp.use("/admin/", updateUsers)
// adminApp.use("/admin/", learningAdminRouter)

// // Bind to loopback only so the admin API is never exposed externally
// adminApp.listen(adminPort, "127.0.0.1", () => {
//   console.log(`admin server running on http://localhost:${adminPort}`)
// })
