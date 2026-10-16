import mongoose from "mongoose";

const connectDB = async (retryCount = 0) => {
  try {
    await mongoose.connect(process.env.MONGODB_URL, { family: 4 });
    console.log("mongoDb connected successfully");
  } catch (err) {
    console.log("Failed connect to the database (MongoDB):", err.message);
    setTimeout(() => {
      console.log("Retrying MongoDB connection...");
      connectDB(retryCount + 1);
    }, 5000);
  }
};

export default connectDB;