const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Create a new claim
router.post('/', async (req, res) => {
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
        claimedValue: BigInt(claimedValue || 0),
        tonReward: BigInt(tonReward || 0),
        status: status || 'completed' // default status
      }
    });

    res.json(claim);
  } catch (error) {
    console.error('Error creating claim:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};