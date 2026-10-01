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
    minLength: 3,
    maxLength: 10
  },
  lastname: {
    type: String,
    required: true,
    minLength: 3,
    maxLength: 10
  },
  username: {
    type: String,
    required: true,
    maxLength: 15
  },
  email: {
    type: String,
    required: true,
  },
  AuthCode: {
    type: Number,
    required: true,
  },
  isVerify: {
    type: Boolean,
    default: false,
    required: true,
  },
  ResendCount: {
    type: Number,
    default: 0,
    require: true,
  },
  VerificationCount: {
    type: Number,
    default: 0,
    require: true,
  },
  AttemptsCount: {
    type: Number,
    default: 0,
    require: true,
  },
  lockUntil: {
    type: Date,
    default: null
},
  VerificaionStatus: {
    type: String,
    default: "notVerify",
    enum: ['notVerify', 'check', "verified"],
    require: true,
  },
  PhoneNumber: {
    type: String,
    require: true,
  },
  birthDate: {
    type: Date,
  },
  ipAddress: {
    type: String,
  },
  deviceId: {
    type: String,
  }
}, { timestamps: true })

export const Users = mongoose.model("User", usersSchema);
