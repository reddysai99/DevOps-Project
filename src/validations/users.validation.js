import { z } from 'zod';

export const userIdSchema = z.object({
  id: z
    .string()
    .regex(/^\d+$/, 'ID must be a valid number')
    .transform(val => parseInt(val, 10))
    .refine(val => val > 0, 'ID must be a positive number'),
});

export const updateUserSchema = z.object({
  name: z.string().min(2).max(255).trim().optional(),
  email: z.string().email().max(255).toLowerCase().trim().optional(),
  password: z.string().min(6).max(255).optional(),
  role: z.enum(['user', 'admin']).optional(),
});
