import mongoose from "mongoose";

const scheduleSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    lessons: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Lesson' }]
  }, { timestamps: true });

export default mongoose.model("Schedule", scheduleSchema)