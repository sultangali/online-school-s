import express from 'express'
import mongoose from 'mongoose'
import config from 'config'
import cors from 'cors'

import userRouter from './route/user.routes.js'
import uploadRouter from './route/upload.routes.js'
import lessonRouter from './route/lesson.routes.js'
import scheduleRouter from './route/schedule.routes.js'

const app = express()
 
const PORT = config.get('port')

app.use(express.json())

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`📥 ${new Date().toISOString()} | ${req.method} ${req.originalUrl} | IP: ${req.ip}`);
  next();
});

app.use('/upload', express.static('upload'))
app.use('/images', express.static('images'))

app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://34.116.228.89'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept-Language']
})) 

const start = async () => {
    try {
        await mongoose.set('strictQuery', true)
        await mongoose.set('strictPopulate', false)
        await mongoose.connect(config.get('dbUrl'))
        console.log(`database OK\tname: ${mongoose.connection.name}`)
    } catch (error) {
        console.log(`database ERROR: ${error.message}`)
    }
  
    app.use('/api/upload', uploadRouter)
    app.use('/api/user', userRouter)
    app.use('/api/lessons', lessonRouter)
    app.use('/api/schedule', scheduleRouter)

    app.listen(PORT, (error) => {
        if(error) {
            console.log(`server ERROR`)
        }
        console.log(`server OK\tport: ${PORT}`)
    })
}
  
start() 