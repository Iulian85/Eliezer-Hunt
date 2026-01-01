const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Get admin wallet
router.get('/wallet', async (req, res) => {
  try {
    // In a real implementation, this would fetch from a secure configuration
    // For now, we'll return a placeholder
    res.json({
      adminWalletAddress: process.env.ADMIN_WALLET_ADDRESS || 'UQCpvC9nskdZ9hqMths4jifCMKganQX05CZrCXSyWuyNkOwp'
    });
  } catch (error) {
    console.error('Error fetching admin wallet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Process referral reward
router.post('/users/:id/referral-reward', async (req, res) => {
  try {
    const { id } = req.params;
    const { rewardAmount, referralName } = req.body;

    // Update referrer's balance and referral count
    const user = await prisma.user.update({
      where: { telegramId: BigInt(id) },
      data: {
        balance: { increment: BigInt(rewardAmount) },
        referralBalance: { increment: BigInt(rewardAmount) },
        referrals: { increment: 1 }
      }
    });

    res.json(user);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Error processing referral reward:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark user as having claimed referral
router.post('/users/:id/mark-referral-claimed', async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(id) },
      data: { hasClaimedReferral: true }
    });

    res.json(user);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Error marking referral as claimed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark user as airdropped
router.post('/users/:id/airdrop', async (req, res) => {
  try {
    const { id } = req.params;
    const { allocation } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(id) },
      data: {
        isAirdropped: true,
        airdropAllocation: BigInt(allocation),
        airdropTimestamp: new Date()
      }
    });

    res.json(user);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Error marking user as airdropped:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};