import bcrypt from 'bcrypt';
import logger from "#config/logger.js";
import {users} from "#models/user.model.js";
import {eq} from "drizzle-orm";
import {db} from "#config/database.js";

export const hashPassword = async (password) => {
    try {
           return await bcrypt.hash(password, 10);
    } catch (e) {
        logger.error(`Error hashing the password: ${e}`);
        throw new Error('Error hashing the password');

    }
};

export const comparePassword = async (password, hash) => {
    try {
        return await bcrypt.compare(password, hash);
    } catch (e) {
        logger.error(`Error comparing password: ${e}`);
        throw new Error('Error comparing password');
    }
};

export const createUser = async ({ name, email, password, role = 'user' }) => {
    try {
        const rows = await db.select().from(users).where(eq(users.email, email)).limit(1);
        if (rows.length > 0) throw new Error('User Already Exists');

        const password_hash = await hashPassword(password);
        const normalizedRole = (role || 'user').toLowerCase();

        const [ newUser ] = await db
            .insert(users)
            .values({ name, email, password: password_hash, role: normalizedRole })
            .returning({ id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at });

        logger.info(`User ${newUser.email} created successfully`);
        return newUser;
    } catch (e) {
        logger.error(`Error creating user: ${e}`);
        throw e;
    }
}

export const authenticateUser = async ({ email, password }) => {
    try {
        const rows = await db.select().from(users).where(eq(users.email, email)).limit(1);
        const user = rows[0];
        if (!user) {
            throw new Error('Invalid credentials');
        }

        const valid = await comparePassword(password, user.password);
        if (!valid) {
            throw new Error('Invalid credentials');
        }

        // Remove password before returning
        const { password: _ignored, ...safeUser } = user;
        return safeUser;
    } catch (e) {
        logger.error(`Error authenticating user: ${e}`);
        throw e;
    }
};
