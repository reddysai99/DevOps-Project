import logger from "#config/logger.js";
import {formatValidationError} from "#utils/format.js";
import {signupSchema, signInSchema} from "#validations/auth.validation.js";
import {createUser, authenticateUser} from "#services/auth.service.js";
import {jwt_token} from "#utils/jwt.js";
import {cookies} from "#utils/cookies.js";

export const signup = async (req, res, next) => {
    try {
        const validationResult = signupSchema.safeParse(req.body);
        if(!validationResult.success) {
            return res.status(400).json({
                error: 'Validation failed',
                details: formatValidationError(validationResult.error)
            });
        }
        const { name, email, password, role } = validationResult.data;

        const user = await createUser({ name, email, password, role});

        const token = jwt_token.sign({ id: user.id, email: user.email, role: user.role });

        cookies.set(res, 'token', token);

        logger.info(`User Registered Successfully: ${email}`);
        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id:user.id,
                name:user.name,
                email:user.email,
                role:user.role
            }

        });
    } catch (e) {
        logger.error('Signup Error', e);

        if(e.message === 'User Already Exists') {
            return res.status(409).json({ error: 'Email already exists' });
        }

        next(e);
    }
}

export const signin = async (req, res, next) => {
    try {
        const validationResult = signInSchema.safeParse(req.body);
        if(!validationResult.success) {
            return res.status(400).json({
                error: 'Validation failed',
                details: formatValidationError(validationResult.error)
            });
        }

        const { email, password } = validationResult.data;
        const user = await authenticateUser({ email, password });

        const token = jwt_token.sign({ id: user.id, email: user.email, role: user.role });
        cookies.set(res, 'token', token);

        logger.info(`User Signed In Successfully: ${email}`);
        return res.status(200).json({
            message: 'User signed in successfully',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (e) {
        logger.error('Signin Error', e);
        if(e.message === 'Invalid credentials') {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        next(e);
    }
}

export const signout = async (req, res, next) => {
    try {
        cookies.clear(res, 'token');
        logger.info('User Signed Out Successfully');
        return res.status(200).json({ message: 'User signed out successfully' });
    } catch (e) {
        logger.error('Signout Error', e);
        next(e);
    }
}
