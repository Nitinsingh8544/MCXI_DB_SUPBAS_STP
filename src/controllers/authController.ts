import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  username: z.string().min(3)
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string()
});

// SIGNUP
export const signup = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, username } = signupSchema.parse(req.body);

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      res.status(400).json({ error: 'Email already in use' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hashedPassword, username }
    });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: { id: user.id, email: user.email, username: user.username }
    });

  } catch (error) {
    res.status(400).json({ error: 'Signup failed', details: String(error) });
  }
};

// LOGIN
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, username: user.username }
    });

  } catch (error) {
    res.status(400).json({ error: 'Login failed', details: String(error) });
  }
};

// GET CURRENT USER
export const getMe = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: (req as any).userId },
      select: { id: true, email: true, username: true, avatar: true, role: true }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
};