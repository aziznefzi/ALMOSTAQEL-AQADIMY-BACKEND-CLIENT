import mongoose from "mongoose";

const usersSchema = mongoose.Schema({
  role: {
    type: String,
    required: true,
    default: "user",
    enum: ['user', 'admin']
  },
  ferstname: {
    type: String,
    required: true,
    minLength: 1,
    maxLength: 50
  },
  lastname: {
    type: String,
    required: false,
    default: "",
    maxLength: 50
  },
  username: {
    type: String,
    required: true,
    maxLength: 50
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: false
  },
  googleId: {
    type: String,
    default: null
  },
  avatar: {
    type: String,
    default: ""
  },
  authProvider: {
    type: String,
    enum: ['local', 'google'],
    default: 'local'
  },
  AuthCode: {
    type: Number,
    required: false,
    default: 0
  },
  isVerify: {
    type: Boolean,
    default: false,
    required: true,
  },
  ResendCount: {
    type: Number,
    default: 0,
    required: true,
  },
  VerificationCount: {
    type: Number,
    default: 0,
    required: true,
  },
  AttemptsCount: {
    type: Number,
    default: 0,
    required: true,
  },
  lockUntil: {
    type: Date,
    default: null
  },
  resendLockUntil: {
    type: Date,
    default: null
  },
  resendWindowStart: {
    type: Date,
    default: null
  },
  VerificaionStatus: {
    type: String,
    default: "notVerify",
    enum: ['notVerify', 'check', "verified"],
    required: true,
  },
  PhoneNumber: {
    type: String,
    required: false,
    default: ""
  },
  birthDate: {
    type: Date,
  },
  ipAddress: {
    type: String,
  },
  deviceId: {
    type: String,
  },
  lang: {
    type: String,
    default: "en",
    enum: ['en', 'ar']
  },
  forgotPasswordRequests: {
    type: [Date],
    default: []
  }
}, { timestamps: true })

export const Users = mongoose.model("User", usersSchema);
