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
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://almostaqelaqademy.com",
  "https://www.almostaqelaqademy.com",
  "https://client.almostaqelaqademy.com",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or Postman)
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "x-device-id"]
}));
connectDB()

const port = process.env.PORT || 3000
app.use("/auth", login)
app.use("/auth", signup)
app.use("/api", servicesRouter)


app.listen(port, () => {
   console.log(`server running is ${port}`)
})