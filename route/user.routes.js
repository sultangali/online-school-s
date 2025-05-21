import express from 'express'
import * as controller from '../controller/index.js'
import * as validation from '../service/validation.js'
import validationHandler from '../service/validationHandler.js'
import {school} from '../middleware/checkAuth.js'

const userRouter =  express.Router()

userRouter.post('/auth/registration', validation.registration, validationHandler, controller.user.registration)
userRouter.post('/auth/login', validation.login, validationHandler, controller.user.login)
userRouter.patch('/me/update', school, validation.update, validationHandler, controller.user.update )
userRouter.get('/me', school, controller.user.me)
userRouter.get('/rating', school, controller.user.rating)

export default userRouter 