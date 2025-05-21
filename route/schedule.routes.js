import express from 'express'
import { school } from '../middleware/checkAuth.js'
import * as controller from '../controller/index.js'
const scheduleRouter = express.Router();

// GET: Получить расписание
scheduleRouter.get('/', school, controller.schedule.getSchedule);

// POST: Добавить урок в расписание
scheduleRouter.post('/add', school,  controller.schedule.addLessonToSchedule);

// DELETE: Удалить урок из расписания
scheduleRouter.delete('/:scheduleId/lesson/:lessonId', school,  controller.schedule.removeLessonFromSchedule);

export default scheduleRouter