import jwt from 'jsonwebtoken';
import logger from "#config/logger.js";

const jwtSecret = process.env.JWT_SECRET || 'your-secret-key-please-change-in-production';
const JWT_EXPIRES_IN = '1d';

export const jwt_token = {
    sign: (payload) => {
        try{
             return jwt.sign(payload, jwtSecret, { expiresIn: JWT_EXPIRES_IN });
        } catch (e) {
          logger.error('JWT sign failed', e);
          throw new Error('Failed to authenticate');
        }
    },
    verify:(token) => {
        try {
               return jwt.verify(token, jwtSecret);
        } catch (e) {
            logger.error('JWT verify failed', e);
            throw new Error('Failed to authenticate token');
        }
    }
}