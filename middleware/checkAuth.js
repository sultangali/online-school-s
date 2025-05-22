import jwt from 'jsonwebtoken'

import config from 'config'

export const school = (req, res, next) => {
    console.log('🔒 Auth middleware called for path:', req.originalUrl)
    
    const token = (req.headers.authorization || '').replace(/Bearer\s?/, '')
    console.log('🔑 Token received:', token ? `${token.substring(0, 15)}...` : 'No token')
    
    if (!token) {
        console.log('❌ No token provided')
        return res.status(403).json({
            message: 'Рұқсат жоқ! Токен жоқ.'
        })
    }
    
    try {
        console.log('🔍 Trying to verify token with key:', config.get('jwt_key').substring(0, 3) + '...')
        const decoded = jwt.verify(token, config.get('jwt_key'))
        console.log('✅ Token verified successfully for user:', decoded._id)
        req.userId = decoded._id
        next()
    } catch (error) {
        console.log("❌ Token verification error:", error.message)
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
