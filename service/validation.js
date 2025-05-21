import { body } from 'express-validator'

export const registration = [
    body('email').isEmail().withMessage('Некорректный email'),
    body('password').isString().withMessage('Пароль должен быть строкой'),
    body('firstName').optional().isString().withMessage('Имя должно быть строкой'),
    body('lastName').optional().isString().withMessage('Фамилия должна быть строкой'),
    body('patronymic').optional().isString().withMessage('Отчество должно быть строкой')
  ];
  
  export const login = [
    body('login').isString().withMessage('Некорректный логин'),
    body('password').isString().withMessage('Пароль должен быть строкой')
  ];
  
  export const update = [
    body('email').optional().isString().withMessage('Некорректный email'),
    body('firstName').optional().isString().withMessage('Имя должно быть строкой'),
    body('lastName').optional().isString().withMessage('Фамилия должна быть строкой'),
    body('patronymic').optional().isString().withMessage('Отчество должно быть строкой'),
    body('rating').optional().isNumeric().withMessage('Рейтинг должен быть числом')
  ];