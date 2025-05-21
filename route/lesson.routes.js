import express from 'express'
import * as controller from '../controller/index.js'
import { school, teacher } from '../middleware/checkAuth.js'

const lessonRouter =  express.Router()

// GET: Получить все уроки (доступно для всех авторизованных пользователей)
lessonRouter.get('/', school, controller.lesson.getLessons);
// POST: Добавить урок
lessonRouter.post('/', school, controller.lesson.addLesson);
// PATCH: Изменить урок
lessonRouter.patch('/:lessonId', school,  controller.lesson.updateLesson);
// DELETE: Удалить урок
lessonRouter.delete('/:lessonId', school,  controller.lesson.deleteLesson);

// POST: Отправить решение задачи (только для студентов)
lessonRouter.post('/:lessonId/task/submit', school, controller.lesson.submitTask);
// GET: Просмотреть все решения (только для учителей)
lessonRouter.get('/:lessonId/task/submissions', school,  controller.lesson.getSubmissions);
// PATCH: Проверить решение (только для учителей)
lessonRouter.patch('/:lessonId/task/submissions/:submissionId', school,  controller.lesson.reviewSubmission);

// POST: Отправить ответы на тест
lessonRouter.post('/:lessonId/test/submit', school, controller.lesson.submitTest);

// GET: Получить результаты теста (учитель)
lessonRouter.get('/:lessonId/test/results', school,  controller.lesson.getTestResults);

export default lessonRouter