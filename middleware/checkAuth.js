import jwt from 'jsonwebtoken'

import config from 'config'

export const school = (req, res, next) => {
    console.log('🔒 Auth middleware called for path:', req.originalUrl)
    
    const authHeader = req.headers.authorization || ''
    console.log('🔑 Authorization header:', authHeader.length > 15 ? 
                `${authHeader.substring(0, 15)}...` : authHeader || 'not provided')
    
    // Check for Bearer prefix and extract token
    const bearerPrefix = 'Bearer '
    if (!authHeader || !authHeader.startsWith(bearerPrefix)) {
        console.log('❌ No valid Bearer token found')
        return res.status(403).json({
            message: 'Рұқсат жоқ! Токен жоқ.'
        })
    }
    
    // Extract token without Bearer prefix
    const token = authHeader.substring(bearerPrefix.length)
    if (!token || token.length < 10) {  // Basic validation to ensure token isn't just a short string
        console.log('❌ Token too short or invalid format')
        return res.status(403).json({
            message: 'Рұқсат жоқ! Жарамсыз токен.'
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
