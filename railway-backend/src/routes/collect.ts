import { Router, Request, Response } from 'express';
import { prisma } from '../server';

const router = Router();

// Save collection to database
router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      userId,
      spawnId,
      category,
      claimedValue,
      tonReward,
      status
    } = req.body;

    const claim = await prisma.claim.create({
      data: {
        userId: parseInt(userId),
        spawnId,
        category,
        claimedValue: BigInt(claimedValue),
        tonReward: BigInt(tonReward),
        status: status || 'verified',
      },
    });

    res.json({ claim });
  } catch (error) {
    console.error('Error creating claim:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export const collectRoutes = router;