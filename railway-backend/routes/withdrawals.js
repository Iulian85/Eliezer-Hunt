const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Get all withdrawal requests
router.get('/', async (req, res) => {
  try {
    const requests = await prisma.withdrawalRequest.findMany({
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({ requests });
  } catch (error) {
    console.error('Error fetching withdrawal requests:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new withdrawal request
router.post('/', async (req, res) => {
  try {
    const {
      userId,
      amount,
      status
    } = req.body;

    const request = await prisma.withdrawalRequest.create({
      data: {
        userId: parseInt(userId),
        amount: BigInt(amount),
        status: status || 'pending'
      }
    });

    res.json(request);
  } catch (error) {
    console.error('Error creating withdrawal request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update withdrawal status
router.put('/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const request = await prisma.withdrawalRequest.update({
      where: { id: parseInt(id) },
      data: {
        status,
        processedAt: new Date()
      }
    });

    res.json(request);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'Withdrawal request not found' });
    }
    console.error('Error updating withdrawal status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};