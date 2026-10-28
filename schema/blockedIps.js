import mongoose from "mongoose";

const BlockedIpsSchema = mongoose.Schema({
    userID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: false,
      default: null,
      alias: 'userId'
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
      default: "",
      alias: 'reason'
    },
    banneDate: {
      type: Date,
      default: Date.now,
      alias: 'bannedDate'
    },
    BannedCount: {
      type: Number,
      default: 0
    },
    StateBan: {
      type: String,
      default: "not-baned",
      enum: ['not-baned', 'baned', 'permanent-baned'],
      alias: 'stateBan'
    },
    banType: {
      type: String,
      default: "all",
      enum: ['device', 'email', 'all', 'ip']
    }
}, { timestamps: true })

// Indexes for fast ban lookups by userID, IP, device, and email
BlockedIpsSchema.index({ userID: 1 });
BlockedIpsSchema.index({ ipAddress: 1, banType: 1, StateBan: 1 });
BlockedIpsSchema.index({ deviceId: 1, banType: 1, StateBan: 1 });
BlockedIpsSchema.index({ email: 1, banType: 1, StateBan: 1 });

export const BlockedIps = mongoose.model("BlockedIp", BlockedIpsSchema)
export default BlockedIps;