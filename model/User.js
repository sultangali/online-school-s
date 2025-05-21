import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['student', 'teacher', 'admin'], default: 'student' },
  rating: { type: Number, default: 0 },
  schedule: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Schedule' }],
  // Дополнительные поля для студентов
  firstName: { type: String }, // Имя
  lastName: { type: String },  // Фамилия
  patronymic: { type: String }, // Отчество
  avatar: { type: String }
}, { timestamps: true });

export default mongoose.model("User", userSchema);
