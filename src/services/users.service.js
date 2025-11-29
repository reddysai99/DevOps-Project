import logger from '#config/logger.js';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';
import { hashPassword } from '#services/auth.service.js';

export const getAllUsers = async () => {
  try {
    return await db
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      })
      .from(users);
  } catch (e) {
    logger.error('Error getting Users', e);
    throw e;
  }
};

export const getUserById = async id => {
  try {
    const rows = await db
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      })
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (rows.length === 0) {
      throw new Error('User not found');
    }

    return rows[0];
  } catch (e) {
    logger.error(`Error getting user by ID ${id}:`, e);
    throw e;
  }
};

export const updateUser = async (id, updates) => {
  try {
    // Check if user exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (existingUser.length === 0) {
      throw new Error('User not found');
    }

    // Check if email is being updated and if it's already taken
    if (updates.email) {
      const emailCheck = await db
        .select()
        .from(users)
        .where(eq(users.email, updates.email))
        .limit(1);

      if (emailCheck.length > 0 && emailCheck[0].id !== id) {
        throw new Error('Email already in use');
      }
    }

    // Hash password if being updated
    if (updates.password) {
      updates.password = await hashPassword(updates.password);
    }

    // Add updated_at timestamp
    const updateData = {
      ...updates,
      updated_at: new Date(),
    };

    const [updatedUser] = await db
      .update(users)
      .set(updateData)
      .where(eq(users.id, id))
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      });

    logger.info(`User ${id} updated successfully`);
    return updatedUser;
  } catch (e) {
    logger.error(`Error updating user ${id}:`, e);
    throw e;
  }
};

export const deleteUser = async id => {
  try {
    // Check if user exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (existingUser.length === 0) {
      throw new Error('User not found');
    }

    await db.delete(users).where(eq(users.id, id));

    logger.info(`User ${id} deleted successfully`);
    return { id, deleted: true };
  } catch (e) {
    logger.error(`Error deleting user ${id}:`, e);
    throw e;
  }
};
