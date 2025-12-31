import { Router, Request, Response } from 'express';
import { prisma } from '../db';

const router = Router();

// Daily reward endpoint
router.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId, rewardAmount } = req.body;

    if (!userId || !rewardAmount) {
      res.status(400).json({ error: 'Missing userId or rewardAmount' });
      return;
    }

    // Update the user's daily supply balance
    const updatedUser = await prisma.user.update({
      where: { id: Number(userId) },
      data: {
        dailySupplyBalance: {
          increment: BigInt(rewardAmount)
        },
        balance: {
          increment: BigInt(rewardAmount)
        },
        lastDailyClaim: Date.now(), // Update the last daily claim timestamp
      },
    });

    res.json({
      success: true,
      message: `Daily reward of ${rewardAmount} added to user ${userId}`,
      updatedBalance: updatedUser.dailySupplyBalance.toString()
    });
  } catch (error) {
    console.error('Error processing daily reward:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export const dailyRewardRoutes = router;