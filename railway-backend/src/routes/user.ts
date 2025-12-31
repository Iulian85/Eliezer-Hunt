import { Router, Request, Response } from 'express';
import { prisma } from '../db';

const router = Router();

// Get user by Telegram ID
router.get('/:telegramId', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;
    
    const user = await prisma.user.findUnique({
      where: { telegramId: BigInt(telegramId) },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or update user
router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      telegramId,
      username,
      photoUrl,
      deviceFingerprint,
      balance = 0,
      tonBalance = 0,
      gameplayBalance = 0,
      rareBalance = 0,
      eventBalance = 0,
      dailySupplyBalance = 0,
      merchantBalance = 0,
      referralBalance = 0,
      collectedIds = [],
    } = req.body;

    const user = await prisma.user.upsert({
      where: { telegramId: BigInt(telegramId) },
      update: {
        username,
        photoUrl,
        deviceFingerprint,
        lastActive: new Date(),
        balance: BigInt(balance),
        tonBalance: BigInt(tonBalance),
        gameplayBalance: BigInt(gameplayBalance),
        rareBalance: BigInt(rareBalance),
        eventBalance: BigInt(eventBalance),
        dailySupplyBalance: BigInt(dailySupplyBalance),
        merchantBalance: BigInt(merchantBalance),
        referralBalance: BigInt(referralBalance),
        collectedIds,
      },
      create: {
        telegramId: BigInt(telegramId),
        username,
        photoUrl,
        deviceFingerprint,
        balance: BigInt(balance),
        tonBalance: BigInt(tonBalance),
        gameplayBalance: BigInt(gameplayBalance),
        rareBalance: BigInt(rareBalance),
        eventBalance: BigInt(eventBalance),
        dailySupplyBalance: BigInt(dailySupplyBalance),
        merchantBalance: BigInt(merchantBalance),
        referralBalance: BigInt(referralBalance),
        collectedIds,
      },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error creating/updating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user balance
router.post('/:telegramId/update-balance', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;
    const {
      balance = 0,
      tonBalance = 0,
      gameplayBalance = 0,
      rareBalance = 0,
      eventBalance = 0,
      dailySupplyBalance = 0,
      merchantBalance = 0,
      referralBalance = 0,
      collectedIds = [],
    } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        balance: { increment: BigInt(balance) },
        tonBalance: { increment: BigInt(tonBalance) },
        gameplayBalance: { increment: BigInt(gameplayBalance) },
        rareBalance: { increment: BigInt(rareBalance) },
        eventBalance: { increment: BigInt(eventBalance) },
        dailySupplyBalance: { increment: BigInt(dailySupplyBalance) },
        merchantBalance: { increment: BigInt(merchantBalance) },
        referralBalance: { increment: BigInt(referralBalance) },
        collectedIds: { push: collectedIds },
        lastActive: new Date(),
      },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error updating user balance:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset user
router.post('/:telegramId/reset', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        balance: BigInt(0),
        tonBalance: BigInt(0),
        gameplayBalance: BigInt(0),
        rareBalance: BigInt(0),
        eventBalance: BigInt(0),
        dailySupplyBalance: BigInt(0),
        merchantBalance: BigInt(0),
        referralBalance: BigInt(0),
        collectedIds: [],
      },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error resetting user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user wallet
router.put('/:telegramId/wallet', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;
    const { walletAddress } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: { walletAddress },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error updating user wallet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle user ban
router.put('/:telegramId/ban', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;
    const { isBanned } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: { isBanned },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error toggling user ban:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle user biometric setting
router.put('/:telegramId/biometric', async (req: Request, res: Response) => {
  try {
    const { telegramId } = req.params;
    const { enabled } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: { biometricEnabled: enabled },
    });

    res.json({ user });
  } catch (error) {
    console.error('Error toggling user biometric setting:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export const userRoutes = router;