import mongoose from "mongoose"
import Schedule from "../model/Shedule.js"

// GET /api/schedule
export const getSchedule = async (req, res) => {
    try {
      const schedule = await Schedule.find().populate('lessons');
      console.log("schedule", schedule)
      res.status(200).json(schedule);
    } catch (error) {
      console.error('Сабақ кестесін алу кезінде қате:', error.message);
      res.status(500).json({ message: 'Серверден келген қате' });
    }
  };

// POST /api/schedule/add
export const addLessonToSchedule = async (req, res) => {
    const { date, lessonId } = req.body;
  
    try {
      let schedule = await Schedule.findOne({ user: req.userId, date });
  
      if (!schedule) {
        schedule = new Schedule({ user: req.userId, date, lessons: [] });
      }
  
      schedule.lessons.push(lessonId);
      await schedule.save();
  
      res.status(200).json({ message: 'Ағымдағы сабақ кестегі сәтті қосылды' });
    } catch (error) {
      console.error('Сабақты кестеге қосу қатесі:', error.message);
      res.status(500).json({ message: 'Серверден келген қате' });
    }
  };

  // DELETE /api/schedule/:scheduleId/lesson/:lessonId
export const removeLessonFromSchedule = async (req, res) => {
    const { scheduleId, lessonId } = req.params;
  
    try {
      const schedule = await Schedule.findById(scheduleId);
  
      if (!schedule) {
        return res.status(404).json({ message: 'Расписание не найдено' });
      }
  
      schedule.lessons = schedule.lessons.filter((id) => id.toString() !== lessonId);
      await schedule.save();
  
      res.status(200).json({ message: 'Сабақ кестеден алынып тасталды.' });
    } catch (error) {
      console.error('Сабақты кестеден жою қатесі:', error.message);
      res.status(500).json({ message: 'Серверден келген қате' });
    }
  };
  