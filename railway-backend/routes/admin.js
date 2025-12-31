const express = require('express');
const { Client } = require('pg');
const router = express.Router();

// Database connection
const db = new Client({
  connectionString: process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Connect to database
db.connect();

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
    const query = `
      UPDATE users SET 
        balance = balance + $1,
        referral_balance = referral_balance + $1,
        referrals = referrals + 1,
        referral_names = referral_names || ARRAY[$2]::text[]
      WHERE telegram_id = $3
      RETURNING *;
    `;

    const result = await db.query(query, [rewardAmount, referralName, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error processing referral reward:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark user as having claimed referral
router.post('/users/:id/mark-referral-claimed', async (req, res) => {
  try {
    const { id } = req.params;

    const query = `
      UPDATE users SET has_claimed_referral = true
      WHERE telegram_id = $1
      RETURNING *;
    `;

    const result = await db.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error marking referral as claimed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark user as airdropped
router.post('/users/:id/airdrop', async (req, res) => {
  try {
    const { id } = req.params;
    const { allocation } = req.body;

    const query = `
      UPDATE users SET 
        is_airdropped = true,
        airdrop_allocation = $1,
        airdrop_timestamp = CURRENT_TIMESTAMP
      WHERE telegram_id = $2
      RETURNING *;
    `;

    const result = await db.query(query, [allocation, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error marking user as airdropped:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;