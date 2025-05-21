import mongoose from "mongoose"

import Lesson from "../model/Lesson.js"

// Получение всех уроков
export const getLessons = async (req, res) => {
  try {
    const lessons = await Lesson.find()
      .populate('submissions.student', 'username email firstName lastName patronymic') // Указывайте необходимые поля
      .populate('testResults.student', 'username email firstName lastName patronymic');
    res.status(200).json(lessons);
  } catch (error) {
    res.status(500).json({ message: 'Сабақтар тізімін алу кезіндегі серверден келген қате' });
  }
};

// POST /api/lessons
export const addLesson = async (req, res) => {
  const { title, description, videoUrl, theory, tasks, tests } = req.body;

  try {
    const newLesson = new Lesson({
      title,
      description,
      videoUrl,
      theory,
      tasks,
      tests,
    });

    await newLesson.save();
    res.status(201).json({ message: 'Сабақ сәтті қосылды', lesson: newLesson });
  } catch (error) {
    console.error('Ошибка при добавлении урока:', error.message);
    res.status(500).json({ message: 'Сабақты қосу керзіндегі қате' });
  }
};

// PATCH /api/lessons/:lessonId
export const updateLesson = async (req, res) => {
  const { lessonId } = req.params;
  const { title, description, videoUrl, theory, tasks, tests } = req.body;

  try {
    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ message: 'Сабақ табылмады' });

    // Обновление данных урока
    lesson.title = title || lesson.title;
    lesson.description = description || lesson.description;
    lesson.videoUrl = videoUrl || lesson.videoUrl;
    lesson.theory = theory || lesson.theory;
    lesson.tasks = tasks || lesson.tasks;
    lesson.tests = tests || lesson.tests;

    await lesson.save();
    res.status(200).json({ message: 'Сабақ сәтті жаңарды', lesson });
  } catch (error) {
    console.error('Ошибка при обновлении урока:', error.message);
    res.status(500).json({ message: 'Сабақты жаңарту кезіндегі серверден келген қате' });
  }
};

// DELETE /api/lessons/:lessonId
export const deleteLesson = async (req, res) => {
  const { lessonId } = req.params;

  try {
    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ message: 'Сабақ табылмады' });

    await lesson.deleteOne();
    res.status(200).json({ message: 'Сабақ сәтті қосылды' });
  } catch (error) {
    console.error('Ошибка при удалении урока:', error.message);
    res.status(500).json({ message: 'Сабақты өшіру кезіндегі қате' });
  }
};

// POST /api/lessons/:lessonId/task/submit
export const submitTask = async (req, res) => {
  const { lessonId } = req.params;
  const { taskId, answer } = req.body;
  const studentId = req.userId;

  // Валидация ID
  if (!mongoose.Types.ObjectId.isValid(lessonId) || !mongoose.Types.ObjectId.isValid(taskId)) {
    return res.status(400).json({ message: 'Сабақ немесе тапсырма коды қате алынды.' });
  }

  if (typeof answer !== 'string' || answer.trim() === '') {
    return res.status(400).json({ message: 'Жауап бос болмауы керек.' });
  }

  try {
    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ message: 'Сабақ табылмады.' });

    const task = lesson.tasks.id(taskId);
    if (!task) {
      return res.status(404).json({ message: 'Бұл сабақта тапсырма табылмады.' });
    }

    // Проверка повторной отправки
    const existingSubmission = lesson.submissions.find(sub =>
      sub.student.equals(studentId) && sub.task.equals(taskId)
    );

    if (existingSubmission) {
      return res.status(400).json({ message: 'Бұл сабаққа тапырма жауабы бұрын жіберілді.' });
    }

    // Добавление отправки с полем 'task'
    lesson.submissions.push({
      student: new mongoose.Types.ObjectId(studentId),
      task: new mongoose.Types.ObjectId(taskId),
      lessonId: new mongoose.Types.ObjectId(lessonId), // Добавлено
      answer,
      status: 'pending',
      submittedAt: new Date(),
    });

    await lesson.save();

    res.status(200).json({ message: 'Шешім тексеруге жіберілді.' });
  } catch (error) {
    console.error('Ошибка при отправке решения задачи:', error.message);
    res.status(500).json({ message: 'Тапсырма шешімін жіберу кезіндегі серверден келген қате.' });
  }
};

// GET: Просмотреть все решения (только для учителей)
export const getSubmissions = async (req, res) => {
  const { lessonId } = req.params;

  // Валидация lessonId
  if (!mongoose.Types.ObjectId.isValid(lessonId)) {
    return res.status(400).json({ message: 'Сабақ ID қате' });
  }

  try {
    const lesson = await Lesson.findById(lessonId)
      .populate('submissions.student', 'username email firstName lastName patronymic'); // Популяция студента

    if (!lesson) {
      return res.status(404).json({ message: 'Сабақ табылмады.' });
    }

    // Добавление информации о задаче вручную
    const submissionsWithTask = lesson.submissions.map(sub => {
      const task = lesson.tasks.id(sub.task);
      return {
        _id: sub._id,
        student: sub.student,
        task: task ? { _id: task._id, question: task.question } : null,
        answer: sub.answer,
        score: sub.score,
        status: sub.status,
        feedback: sub.feedback,
        submittedAt: sub.submittedAt,
      };
    });

    res.status(200).json({ submissions: submissionsWithTask });
  } catch (error) {
    console.error('Ошибка при получении решений задач:', error.message);
    res.status(500).json({ message: 'Тапсырма шешімін алу кезіндегі қате.' });
  }
};

// PATCH: Проверить решение (только для учителей)
export const reviewSubmission = async (req, res) => {
  const { lessonId, submissionId } = req.params;
  const { score, feedback } = req.body; // Дополнительное поле feedback (опционально)

  // Валидация lessonId и submissionId
  if (!mongoose.Types.ObjectId.isValid(lessonId)) {
    return res.status(400).json({ message: 'Сабақ ID қате.' });
  }

  if (!mongoose.Types.ObjectId.isValid(submissionId)) {
    return res.status(400).json({ message: 'Шешім ID алу кезіндегі қате.' });
  }

  // Валидация score
  if (typeof score !== 'number' || score < 0) {
    return res.status(400).json({ message: 'Баға теріс сан болмауы керек.' });
  }

  try {
    // Поиск урока по ID
    const lesson = await Lesson.findById(lessonId);

    if (!lesson) {
      return res.status(404).json({ message: 'Сабақ табылмады.' });
    }

    // Поиск отправки по submissionId
    const submission = lesson.submissions.id(submissionId);

    if (!submission) {
      return res.status(404).json({ message: 'Шешім табылмады.' });
    }

    // Обновление полей score и status
    submission.score = score;
    submission.status = 'approved';

    // Если есть feedback, добавляем его
    if (feedback) {
      submission.feedback = feedback;
    }

    // Сохранение изменений
    await lesson.save();

    res.status(200).json({ message: 'Жауап сәтті тексерілді.', submission });
  } catch (error) {
    console.error('Ошибка при проверке отправки задачи:', error.message);
    res.status(500).json({ message: 'Тапсырма шешімін тексеру кезіндегі серверден келген қате.' });
  }
};


// POST /api/lessons/:lessonId/test/submit
// Отправка теста
// Отправка теста
export const submitTest = async (req, res) => {
  const { lessonId } = req.params;
  const { answers } = req.body; // Массив [{ questionId, selectedAnswer }]
  const studentId = req.userId; // Предполагается, что middleware добавляет объект пользователя в req.user

  // Валидация входных данных
  if (!mongoose.Types.ObjectId.isValid(lessonId)) {
    return res.status(400).json({ message: 'Сабақ ID қате.' });
  }

  if (!Array.isArray(answers) || answers.length === 0) {
    return res.status(400).json({ message: 'Жауаптар бос болмауы керек.' });
  }

  try {
    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ message: 'Сабақ табылмады' });

    if (!lesson.tests || lesson.tests.length === 0) {
      return res.status(400).json({ message: 'Сабақта тест сұрағы қарастырылмаған.' });
    }

    // Проверка, отправил ли студент уже тест для этого урока
    const existingTestResult = lesson.testResults.find(tr => tr.student.equals(studentId));
    if (existingTestResult) {
      return res.status(400).json({ message: 'Бұл сабаққа арналған тест тапсырылған...'})
    }
    let totalScore = 0;

    // Проверка каждого ответа
    const checkedAnswers = answers.map((answer) => {
      const { questionId, selectedAnswer } = answer;

      if (!mongoose.Types.ObjectId.isValid(questionId)) {
        throw new Error(`Сұрақ ID қате: ${questionId}`);
      }

      const question = lesson.tests.id(questionId);
      if (!question) {
        throw new Error(`Вопрос с ID ${questionId} не найден в этом уроке.`);
      }

      // Получение индекса правильного ответа на основе буквы
      const correctOptionLetter = question.correctAnswer.toUpperCase(); // Например, "B"
      const correctOptionIndex = correctOptionLetter.charCodeAt(0) - 65; // 'A' -> 0, 'B' -> 1, и т.д.

      // Проверка, что индекс находится в пределах массива options
      if (correctOptionIndex < 0 || correctOptionIndex >= question.options.length) {
        throw new Error(`Неверный индекс правильного ответа для вопроса ID ${questionId}.`);
      }

      const correctOptionText = question.options[correctOptionIndex]; // Извлечение текста правильного ответа

      const isCorrect = correctOptionText.trim() === selectedAnswer.trim();
      if (isCorrect) totalScore += 10; // 10 баллов за правильный ответ

      return {
        question: question._id,
        selectedAnswer,
        isCorrect,
      };
    });

    // Добавление отправки в массив testResults
    lesson.testResults.push({
      student: new mongoose.Types.ObjectId(studentId), // Использование 'new' для создания ObjectId
      answers: checkedAnswers,
      lessonId: new mongoose.Types.ObjectId(lessonId), // Добавлено
      totalScore,
      submittedAt: new Date(), // Добавление даты отправки
    });
    await lesson.save();

    res.status(200).json({ message: 'Тест жауабы сәтті жіберілді.', totalScore });
  } catch (error) {
    console.error('Ошибка при отправке теста:', error.message);
    res.status(500).json({ message: 'Тест жауабын жіберу кезіндегі серверден келген қате.' });
  }
};

// GET /api/lessons/:lessonId/test/results
export const getTestResults = async (req, res) => {
  const { lessonId } = req.params;
  try {
    const lesson = await Lesson.findById(lessonId).populate('testResults.student', 'username email firstName lastName patronymic');
    if (!lesson) return res.status(404).json({ message: 'Сабақ табылмады' });

    res.status(200).json(lesson.testResults);
  } catch (error) {
    console.error('Ошибка при получении результатов теста:', error.message);
    res.status(500).json({ message: 'Тест жауаптарын алу кезіндегі серверден келген қате' });
  }
}
