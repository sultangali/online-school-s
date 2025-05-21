import jwt from 'jsonwebtoken'

import config from 'config'

export const school = (req, res, next) => {
    const token = (req.headers.authorization || '').replace(/Bearer\s?/, '')
    if (token) {
        try {
            const decoded = jwt.verify(token, config.get('jwt_key'))
            req.userId = decoded._id
            next()
        } catch (error) {
            res.status(403).json({
                message: 'Рұқсат жоқ!'
            })
        }
    } else {
        res.status(403).json({
            message: 'Рұқсат жоқ!'
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
