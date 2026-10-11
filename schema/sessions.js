import mongoose from "mongoose";

const SessionsSchema = mongoose.Schema({
    userID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      alias: 'userId'
    },
    deviceId: {
      type: String,
      required: true,
      alias: 'deviseID'
    },
    ipAddress: {
      type: String,
      required: true
    },
    refreshToken: {
      type: String,
      required: true
    },
    loginDate: {
      type: Date,
      default: Date.now,
      required: true
    },
    logoutDate: {
      type: Date,
      default: null,
      alias: 'logoutDade'
    }
}, { timestamps: true });

const Sessions = mongoose.model("Sessions", SessionsSchema);
export default Sessions;