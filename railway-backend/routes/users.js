const express = require('express');
const router = express.Router();

// Accept database connection as parameter
module.exports = (db) => {

// Get user by Telegram ID
router.get('/:telegramId', async (req, res) => {
  try {
    const { telegramId } = req.params;

    const query = 'SELECT * FROM users WHERE telegram_id = $1';
    const result = await db.query(query, [telegramId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or update user
router.post('/', async (req, res) => {
  try {
    const {
      telegram_id,
      username,
      photo_url,
      device_fingerprint,
      last_init_data
    } = req.body;

    // Check if user already exists
    const existingUserQuery = 'SELECT * FROM users WHERE telegram_id = $1';
    const existingUserResult = await db.query(existingUserQuery, [telegram_id]);

    if (existingUserResult.rows.length > 0) {
      // Update existing user
      const updateQuery = `
        UPDATE users SET
          username = COALESCE($1, username),
          photo_url = COALESCE($2, photo_url),
          device_fingerprint = COALESCE($3, device_fingerprint),
          last_active = CURRENT_TIMESTAMP,
          last_init_data = COALESCE($4, last_init_data),
          updated_at = CURRENT_TIMESTAMP
        WHERE telegram_id = $5
        RETURNING *;
      `;

      const result = await db.query(updateQuery, [
        username,
        photo_url,
        device_fingerprint,
        last_init_data,
        telegram_id
      ]);

      res.json(result.rows[0]);
    } else {
      // Create new user
      const insertQuery = `
        INSERT INTO users (
          telegram_id, username, photo_url, device_fingerprint, last_init_data
        ) VALUES ($1, $2, $3, $4, $5)
        RETURNING *;
      `;

      const result = await db.query(insertQuery, [
        telegram_id,
        username,
        photo_url,
        device_fingerprint,
        last_init_data
      ]);

      res.status(201).json(result.rows[0]);
    }
  } catch (error) {
    console.error('Error creating/updating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user balance
router.put('/:telegramId/balance', async (req, res) => {
  try {
    const { telegramId } = req.params;
    const { balance, ton_balance, gameplay_balance, rare_balance, event_balance, daily_supply_balance, merchant_balance, referral_balance } = req.body;

    const query = `
      UPDATE users SET
        balance = COALESCE($1, balance),
        ton_balance = COALESCE($2, ton_balance),
        gameplay_balance = COALESCE($3, gameplay_balance),
        rare_balance = COALESCE($4, rare_balance),
        event_balance = COALESCE($5, event_balance),
        daily_supply_balance = COALESCE($6, daily_supply_balance),
        merchant_balance = COALESCE($7, merchant_balance),
        referral_balance = COALESCE($8, referral_balance),
        updated_at = CURRENT_TIMESTAMP
      WHERE telegram_id = $9
      RETURNING *;
    `;

    const result = await db.query(query, [
      balance, ton_balance, gameplay_balance, rare_balance, 
      event_balance, daily_supply_balance, merchant_balance, referral_balance, telegramId
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user balance:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user wallet address
router.put('/:telegramId/wallet', async (req, res) => {
  try {
    const { telegramId } = req.params;
    const { wallet_address } = req.body;

    const query = `
      UPDATE users SET
        wallet_address = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE telegram_id = $2
      RETURNING *;
    `;

    const result = await db.query(query, [wallet_address, telegramId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user wallet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users (admin only)
router.get('/', async (req, res) => {
  try {
    const query = 'SELECT id, telegram_id, username, balance, joined_at, last_active FROM users ORDER BY joined_at DESC';
    const result = await db.query(query);

    res.json({ users: result.rows });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};