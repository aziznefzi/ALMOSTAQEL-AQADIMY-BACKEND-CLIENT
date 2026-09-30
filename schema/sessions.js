import mongoose from "mongoose";

const SessionsSchema = mongoose.Schema({
    userID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Users',
      required: true
    },
    deviseID: {
      type: String,
      required: true
    },
    ipAddress: {
      type: Number,
      required: true
    },
    loginDate: {
      type: Date,
      required: true,
    },
    logoutDade: {
      type: Date,
      required: true
    }
})