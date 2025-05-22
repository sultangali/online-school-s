import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "config";
import mongoose from "mongoose";
import { transliterate } from 'transliteration'

import User from '../model/User.js'
import Lesson from "../model/Lesson.js";

export const registration = async (req, res) => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      patronymic,
      role
    } = req.body;

    // Проверяем, существует ли email
    const isEmailExist = await User.findOne({ email });
    if (isEmailExist) {
      return res.status(400).json({
        message: "Қолданушы желіде тіркелген",
      });
    }

    // Генерация хеша пароля
    const salt = await bcrypt.genSalt(6);
    const hashedPassword = await bcrypt.hash(password, salt);


    async function generateUsername(firstname, lastname, patronymic) {
      let username = transliterate(`${lastname}${firstname}${patronymic}`).replace(/[''`]/g, '').replace(/\s+/g, '');

      // Проверяем уникальность логина
      let isUnique = false;
      let count = 1;

      while (!isUnique) {
        const user = await User.findOne({ username });
        if (!user) {
          isUnique = true;
        } else {
          username = `${username}${count}`;
          count++;
        }
      }

      return username;
    }


    const username = await generateUsername(firstName?.substring(0, 1), lastName, patronymic?.substring(0, 1));

    console.log( username)

    // Создание нового пользователя
    const newUser = new User({
      email,
      username,
      password: hashedPassword,
      role,
      // Заполнение ФИО только для студентов
      ...(role === "student" && { firstName, lastName, patronymic }),
    });

    const user = await newUser.save();

    // Убираем пароль из данных, возвращаемых клиенту
    const { password: _, ...userData } = user._doc;

    // Генерация токена
    const token = jwt.sign(
      {
        _id: user._id,
        role: user.role,
      },
      config.get("jwt_key"),
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "Қолданушы бұрын жүйеде тіркелген",
      userData,
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: "Тіркелу кезінде серверден қате келді",
      error: error.message,
    });
  }
};


export const login = async (req, res) => {
  try {
    const { login, password } = req.body;

    let user = await User.findOne({
      $or: [{ email: login }, { username: login }],
    });

    if (!user) {
      return res.status(404).json({
        message: `Қолданушы '${login}' желіде жоқ`,
      });
    }

    const isPassValid = await bcrypt.compare(password, user.password);
    if (!isPassValid) {
      return res.status(400).json({
        message: "Құпия сөз қате терілген",
      });
    }

    const token = jwt.sign(
      {
        _id: user._id,
      },
      config.get("jwt_key"),
      {
        expiresIn: "1h",
      }
    );

    const { password: _, ...userData } = user._doc;

    res.status(200).json({
      ...userData,
      token,
    });
  } catch (error) {
    res.status(500).json(error.message);
  }
};


export const me = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        message: "Қолданушы табылмады"
      });
    }

    const populatedUser = await User.findById(userId)
      .populate("schedule")
      .exec();

    const { password, ...userData } = populatedUser._doc;

    return res.status(200).json(userData);

  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

export const update = async (req, res) => {
  try {
    const { username, email, firstName, lastName, patronymic, rating } = req.body;

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "Қолданушы жүйеден табылмады" });
    }

    // Обновляем данные пользователя
    user.username = username || user.username;
    user.email = email || user.email;

    if (user.role === "student") {
      user.firstName = firstName || user.firstName;
      user.lastName = lastName || user.lastName;
      user.patronymic = patronymic || user.patronymic;
    }

    user.rating = rating || user.rating;

    await user.save();

    const { password: _, ...userData } = user._doc;

    res.status(200).json({
      message: "Профиль жаңартылды",
      user: userData,
    });
  } catch (error) {
    res.status(500).json({
      message: "Профилді жаңарту кезінде серверден қате келді",
      error: error.message,
    });
  }
};

export const rating = async (req, res) => {
  try {
    const userId = req.userId; // Предполагается, что вы используете аутентификацию и `req.user` доступен

    // Найти все уроки, где студент имеет submissions или testResults
    const lessons = await Lesson.find({
      $or: [
        { 'submissions.student': new mongoose.Types.ObjectId(userId) },
        { 'testResults.student': new mongoose.Types.ObjectId(userId) },
      ],
    });

    // Собрать submissions и testResults для студента
    const submissions = [];
    const testResults = [];

    lessons.forEach((lesson) => {
      // Сбор submissions
      lesson.submissions.forEach((sub) => {
        if (sub.student.toString() === userId.toString()) {
          submissions.push({
            lessonId: lesson._id,
            lessonTitle: lesson.title,
            score: sub.score,
          });
        }
      });

      // Сбор testResults
      lesson.testResults.forEach((test) => {
        if (test.student.toString() === userId.toString()) {
          testResults.push({
            lessonId: lesson._id,
            lessonTitle: lesson.title,
            totalScore: test.totalScore,
          });
        }
      });
    });

    res.json({ submissions, testResults });
  } catch (error) {
    res.status(500).json({ message: 'Оқушы рейтингін алу кезіндегі қате: ' +  error});
  }
}