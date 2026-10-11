import "dotenv/config"
import dns from "dns"
dns.setDefaultResultOrder('ipv4first')
import express from "express"
import cors from "cors"
import login from "./router/login/login.js"
import signup from "./router/login/signup.js"
import servicesRouter from "./services/Services.js"
import connectDB from "./config/db.js"
import "./jobs/deleteFindUser.js"
import cookieParser from "cookie-parser"
const app = express()
app.use(cookieParser())
app.use(express.json())
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: "Data sent is not valid JSON. Please check the request body formatting." });
  }
  next();
})
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}))
connectDB()

const port = process.env.PORT || 3000
app.use("/auth", login)
app.use("/auth", signup)
app.use("/api", servicesRouter)


app.listen(port, () => {
   console.log(`server running is ${port}`)
})