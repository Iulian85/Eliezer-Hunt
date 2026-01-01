const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Get user by Telegram ID
router.get('/:telegramId', async (req, res) => {
  try {
    const { telegramId } = req.params;

    const user = await prisma.user.findUnique({
      where: { telegramId: BigInt(telegramId) }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
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

    const user = await prisma.user.upsert({
      where: { telegramId: BigInt(telegram_id) },
      update: {
        username: username || undefined,
        photoUrl: photo_url || undefined,
        deviceFingerprint: device_fingerprint || undefined,
        lastInitData: last_init_data || undefined,
      },
      create: {
        telegramId: BigInt(telegram_id),
        username,
        photoUrl: photo_url,
        deviceFingerprint: device_fingerprint,
        lastInitData: last_init_data,
      }
    });

    res.status(201).json(user);
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

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        balance: balance !== undefined ? BigInt(balance) : undefined,
        tonBalance: ton_balance !== undefined ? BigInt(ton_balance) : undefined,
        gameplayBalance: gameplay_balance !== undefined ? BigInt(gameplay_balance) : undefined,
        rareBalance: rare_balance !== undefined ? BigInt(rare_balance) : undefined,
        eventBalance: event_balance !== undefined ? BigInt(event_balance) : undefined,
        dailySupplyBalance: daily_supply_balance !== undefined ? BigInt(daily_supply_balance) : undefined,
        merchantBalance: merchant_balance !== undefined ? BigInt(merchant_balance) : undefined,
        referralBalance: referral_balance !== undefined ? BigInt(referral_balance) : undefined,
      }
    });

    res.json(user);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Error updating user balance:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user wallet address
router.put('/:telegramId/wallet', async (req, res) => {
  try {
    const { telegramId } = req.params;
    const { wallet_address } = req.body;

    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        walletAddress: wallet_address
      }
    });

    res.json(user);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Error updating user wallet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users (admin only)
router.get('/', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        telegramId: true,
        username: true,
        balance: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({ users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Telegram authentication and user creation/update
router.post('/telegram-auth', async (req, res) => {
  try {
    const { telegramUser, deviceFingerprint } = req.body;

    if (!telegramUser) {
      return res.status(400).json({ error: 'Telegram user data is required' });
    }

    const {
      id: telegram_id,
      username,
      first_name,
      last_name,
      photo_url
    } = telegramUser;

    // Combine first name and last name for full name
    const fullName = last_name ? `${first_name} ${last_name}` : first_name;

    const user = await prisma.user.upsert({
      where: { telegramId: BigInt(telegram_id) },
      update: {
        username: username || fullName,
        photoUrl: photo_url || undefined,
        deviceFingerprint: deviceFingerprint || undefined,
      },
      create: {
        telegramId: BigInt(telegram_id),
        username: username || fullName,
        firstName: first_name,
        lastName: last_name,
        photoUrl: photo_url,
        deviceFingerprint: deviceFingerprint,
      }
    });

    res.status(201).json({ user, isNew: user.createdAt.getTime() === user.updatedAt.getTime() });
  } catch (error) {
    console.error('Error processing Telegram authentication:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};