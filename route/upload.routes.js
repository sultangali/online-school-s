import express from 'express'
import multer from 'multer'

import * as controller from '../controller/upload.controller.js'
import {school} from '../middleware/checkAuth.js'
import storageService from '../service/diskStorage.js'

const uploadRouter = express.Router()

const uploadStudentAvatar = multer({
    storage: storageService('users')
})

const uploadLessonVideo = multer({
    storage: storageService('lessons')
})

uploadRouter.post('/avatar', school, uploadStudentAvatar.single('image'), controller.uploadAvatar)
uploadRouter.post('/lesson', school, uploadLessonVideo.single('video'), controller.uploadVideo)

export default uploadRouter