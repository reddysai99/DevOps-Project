import logger from '#config/logger.js';
import {
  getAllUsers,
  getUserById as getUserByIdService,
  updateUser as updateUserService,
  deleteUser as deleteUserService,
} from '#services/users.service.js';
import { formatValidationError } from '#utils/format.js';
import {
  userIdSchema,
  updateUserSchema,
} from '#validations/users.validation.js';

export const fetchAllUsers = async (req, res, next) => {
  try {
    logger.info('Getting all users....');

    const allUsers = await getAllUsers();

    res.json({
      message: 'Users fetched successfully',
      users: allUsers,
      count: allUsers.length,
    });
  } catch (e) {
    logger.error(e);
    next(e);
  }
};

export const getUserById = async (req, res, next) => {
  try {
    const validationResult = userIdSchema.safeParse({ id: req.params.id });
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { id } = validationResult.data;
    logger.info(`Getting user with ID: ${id}`);

    const user = await getUserByIdService(id);

    res.json({
      message: 'User fetched successfully',
      user,
    });
  } catch (e) {
    logger.error('Get user by ID error:', e);

    if (e.message === 'User not found') {
      return res.status(404).json({ error: 'User not found' });
    }

    next(e);
  }
};

export const updateUser = async (req, res, next) => {
  try {
    // Validate user ID
    const idValidation = userIdSchema.safeParse({ id: req.params.id });
    if (!idValidation.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(idValidation.error),
      });
    }

    const { id } = idValidation.data;

    // Validate update data
    const updateValidation = updateUserSchema.safeParse(req.body);
    if (!updateValidation.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(updateValidation.error),
      });
    }

    const updates = updateValidation.data;

    // Ensure at least one field is being updated
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        error: 'No valid fields to update',
      });
    }

    // Authorization checks
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Users can only update their own information
    if (req.user.id !== id && req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'You can only update your own information',
      });
    }

    // Only admins can change roles
    if (updates.role && req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Only administrators can change user roles',
      });
    }

    // If non-admin trying to update another user, remove role from updates
    if (req.user.id === id && req.user.role !== 'admin') {
      delete updates.role;
    }

    logger.info(
      `User ${req.user.id} updating user ${id} with fields: ${Object.keys(updates).join(', ')}`
    );

    const updatedUser = await updateUserService(id, updates);

    res.json({
      message: 'User updated successfully',
      user: updatedUser,
    });
  } catch (e) {
    logger.error('Update user error:', e);

    if (e.message === 'User not found') {
      return res.status(404).json({ error: 'User not found' });
    }

    if (e.message === 'Email already in use') {
      return res.status(409).json({ error: 'Email already in use' });
    }

    next(e);
  }
};

export const deleteUser = async (req, res, next) => {
  try {
    // Validate user ID
    const validationResult = userIdSchema.safeParse({ id: req.params.id });
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { id } = validationResult.data;

    // Authorization check
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Users can only delete their own account, or admins can delete any account
    if (req.user.id !== id && req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'You can only delete your own account',
      });
    }

    logger.info(`User ${req.user.id} deleting user ${id}`);

    await deleteUserService(id);

    res.json({
      message: 'User deleted successfully',
      deleted: true,
    });
  } catch (e) {
    logger.error('Delete user error:', e);

    if (e.message === 'User not found') {
      return res.status(404).json({ error: 'User not found' });
    }

    next(e);
  }
};
