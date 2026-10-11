import mongoose from "mongoose";

const BlockedIpsSchema = mongoose.Schema({
    userID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: false,
      default: null
    },
    email: {
      type: String,
      default: null,
      lowercase: true,
      trim: true
    },
    deviceId: {
      type: String,
      default: null
    },
    ipAddress: {
      type: String,
      default: null
    },
    resson: {
      type: String,
      default: ""
    },
    banneDate: {
      type: Date,
      default: Date.now
    },
    BannedCount: {
      type: Number,
      default: 0
    },
    StateBan: {
      type: String,
      default: "not-baned",
      enum: ['not-baned', 'baned', 'permanent-baned']
    },
    banType: {
      type: String,
      default: "all",
      enum: ['device', 'email', 'all']
    }
}, { timestamps: true })

export const BlockedIps = mongoose.model("BlockedIp", BlockedIpsSchema)