import mongoose from "mongoose";

const connectDB = async () => {
  try{
    await mongoose.connect(process.env.MONGODB_URL)
    console.log("mongoDb conneected seccesfuly")
  }catch(err){
    console.log("Failed connect to the database (MongoDB):", err)
    process.exit(1);
  }
}

export default connectDB;