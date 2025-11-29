import logger from '#config/logger.js';
import { jwt_token } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';

export const authenticate = (req, res, next) => {
  try {
    const token = cookies.get(req, 'token');

    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt_token.verify(token);
    req.user = decoded;
    next();
  } catch (e) {
    logger.error('Authentication error:', e);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

export const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: 'Insufficient permissions for this action' });
    }

    next();
  };
};
