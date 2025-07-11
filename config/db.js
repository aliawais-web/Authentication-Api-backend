import mongoose from "mongoose";

// Connect to MongoDB
 export const connectDB = async () =>{
    try {
        const connectDB = await mongoose.connect(process.env.MONGO_URI);
        console.log(`✅ > MongoDB connected: ${connectDB.connection.host}`);
    } catch (error) {
        console.error('Error connecting to MongoDB:',error);
        process.exit(1); // Exit the process with failure
    }
    
}