import jwt from 'jsonwebtoken'

import config from 'config'

export const school = (req, res, next) => {
    const token = (req.headers.authorization || '').replace(/Bearer\s?/, '')
    
    if (!token) {
        return res.status(403).json({
            message: 'Рұқсат жоқ! Токен жоқ.'
        })
    }
    
    try {
        const decoded = jwt.verify(token, config.get('jwt_key'))
        req.userId = decoded._id
        next()
    } catch (error) {
        console.log("Token verification error:", error.message)
        return res.status(403).json({
            message: 'Рұқсат жоқ! Токен жарамсыз.'
        })
    }
}

export const teacher = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ message: 'Access denied, only for teachers/admins' });
    }
};
