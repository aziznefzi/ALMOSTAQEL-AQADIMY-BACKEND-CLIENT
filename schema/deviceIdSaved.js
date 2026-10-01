import mongoose from "mongoose";

const DeviceIdSaved = mongoose.Schema({
    deviceId: {
      type: String,
      required: true,
      unque: true
    },
    ipAddress: {
      type: String,
      required: true,
    },
    creationTime: {
      type: Date,
      required: true,
      unque: true
    },
    createDeviceCount: {
      type: Number,
      required: true,
      default: 1
    }
}) 

export const DeviceId = mongoose.model("DeviceId", DeviceIdSaved)