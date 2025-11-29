import express from 'express';
import {
  fetchAllUsers,
  getUserById,
  updateUser,
  deleteUser,
} from '#controllers/users.controller.js';
import { authenticate } from '#middleware/auth.middleware.js';

const router = express.Router();

// Get all users (requires authentication)
router.get('/', authenticate, fetchAllUsers);

// Get user by ID (requires authentication)
router.get('/:id', authenticate, getUserById);

// Update user (requires authentication)
router.put('/:id', authenticate, updateUser);

// Delete user (requires authentication)
router.delete('/:id', authenticate, deleteUser);

export default router;
