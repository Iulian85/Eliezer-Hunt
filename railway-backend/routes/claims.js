const express = require('express');
const router = express.Router();

// Accept database connection as parameter
module.exports = (db) => {

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

    const query = `
      INSERT INTO claims (
        user_id, spawn_id, category, claimed_value, ton_reward, status
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `;

    const result = await db.query(query, [
      userId, spawnId, category, claimedValue, tonReward, status
    ]);

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating claim:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};