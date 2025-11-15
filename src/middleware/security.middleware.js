import aj from '#config/arcject.js'
import {slidingWindow} from "@arcjet/node";
import logger from "#config/logger.js";

const  securityMiddleware = async (req, res, next) => {
    try {
        const role = req.user?.role || 'guest';

        let limit;
        let message;

        switch (role) {
            case 'admin':
                limit=20
                message='Your Admin Request had exceeded 20 requests per min Slow down Bro!!'
                break;
            case 'user':
                limit=10
                message='Your Admin Request had exceeded 10 requests per min Slow down Bro!!'
                break;
            case 'guest':
                limit=5
                message='Your Admin Request had exceeded 20 requests per min Slow down Bro!!'
                break;
        }
        const client = aj.withRule(slidingWindow({ mode:'LIVE', interval:'1m', max: limit, name: `${role}-rate-limit`}));

        const decision = await client.protect(req);

        if(decision.isDenied() && decision.reason.isBot()) {
           logger.warn('Bot Detected', {req: req.ip, userAgent: req.get('User-Agent'), path: req.path});

           return res.status(403).json({ error: 'Forbidden', message: 'Automated requests are not allowed' });
        }
        if(decision.isDenied() && decision.reason.isShield()) {
            logger.warn('Shield Blocked Request', {req: req.ip, userAgent: req.get('User-Agent'), path: req.path, method: req.method});

            return res.status(403).json({ error: 'Forbidden', message: 'Automated requests are not allowed' });
        }
        if(decision.isDenied() && decision.reason.isRateLimit()) {
            logger.warn('Rate limit Exceeded', {req: req.ip, userAgent: req.get('User-Agent'), path: req.path});

            return res.status(403).json({ error: 'Forbidden', message: 'Too many Requests' });
        }
        next();
    } catch (e) {
        console.error('ArcJet Middleware Error', e);
        res.status(500).json({ error: 'Internal Server Error', message: 'Something went wrong with middleware' });
    }
}
export default securityMiddleware;