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

// Get all withdrawal requests
router.get('/', async (req, res) => {
  try {
    const query = 'SELECT * FROM withdrawal_requests ORDER BY created_at DESC';
    const result = await db.query(query);
    
    res.json({ requests: result.rows });
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

    const query = `
      INSERT INTO withdrawal_requests (
        user_id, amount, status
      ) VALUES ($1, $2, $3)
      RETURNING *;
    `;

    const result = await db.query(query, [
      userId, amount, status || 'pending'
    ]);

    res.json(result.rows[0]);
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

    const query = `
      UPDATE withdrawal_requests SET status = $1, processed_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *;
    `;

    const result = await db.query(query, [status, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Withdrawal request not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating withdrawal status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;