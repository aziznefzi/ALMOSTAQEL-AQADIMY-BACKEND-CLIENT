import mongoose from "mongoose";

const DeviceIdSaved = mongoose.Schema({
    deviceId: {
      type: String,
      required: true,
      unique: true
    },
    ipAddress: {
      type: String,
      required: true,
    },
    creationTime: {
      type: Date,
      required: true,
      default: Date.now
    },
    createDeviceCount: {
      type: Number,
      required: true,
      default: 1
    }
}) 

export const DeviceId = mongoose.model("DeviceId", DeviceIdSaved)