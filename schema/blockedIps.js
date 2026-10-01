import mongoose from "mongoose";

const BlockedIpsSchema = mongoose.Schema({
    userID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    deviceId: {
      type: String,
      required: true,
    },
    ipAddress: {
      type: String,
    },
    resson: {
      type: String,
    },
    banneDate: {
      type: Date,
      required: true,
    },
    BannedCount: {
      type: Number,
      default: 0
    },
    StateBan: {
      type: String,
      default: "not-baned",
      enum: ['not-baned', 'baned', 'permanent-baned']
    }
})

export const BlockedIps = mongoose.model("BlockedIp", BlockedIpsSchema)