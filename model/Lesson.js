import mongoose from "mongoose";

const lessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  videoUrl: { type: String },
  theory: { type: String, required: true },

  tasks: [ // Новое поле для массив задач
    {
      _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
      question: { type: String, required: true },
      correctAnswer: { type: String, required: true },
    }
  ],
  tests: [
    {
      question: { type: String, required: true },
      options: [{ type: String, required: true }],
      correctAnswer: { type: String, required: true },
    }
  ],
  submissions: [
    {
      student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      lessonId: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson", required: true },
      task: { type: mongoose.Schema.Types.ObjectId, required: true },
      answer: { type: String, required: true },
      score: { type: Number, default: 0 }, // Баллы за задачу
      status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
      feedback: { type: String },
      submittedAt: { type: Date, default: Date.now },
    }
  ],
  testResults: [
    {
      student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      lessonId: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson", required: true },
      answers: [
        {
          question: { type: mongoose.Schema.Types.ObjectId, required: true }, // Ссылка на вопрос теста
          selectedAnswer: { type: String, required: true },
          isCorrect: { type: Boolean, default: false },
        }
      ],
      totalScore: { type: Number, default: 0 },
      submittedAt: { type: Date, default: Date.now },
    }
  ]
}, { timestamps: true });

export default mongoose.model("Lesson", lessonSchema);
