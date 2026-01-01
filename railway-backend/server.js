const express = require('express');
const port = 3000
const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS simplificat
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Database connection POOL (MUȘTE mai bun!)
const pool = new Pool({
  connectionString: process.env.DATABASE_PUBLIC_URL,
  ssl: "prefer",
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test database connection
async function testDatabaseConnection() {
  console.log('🔍 Testing database connection...');
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT NOW() as time');
    console.log('✅ Database connected at:', result.rows[0].time);
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  } finally {
    client.release();
  }
}

// Telegram authentication verification
function verifyTelegramData(initData) {
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  if (!BOT_TOKEN) {
    console.error('TELEGRAM_BOT_TOKEN is not set in environment variables');
    // For development/testing, allow simplified format without verification
    if (typeof initData === 'string' && initData.startsWith('id=')) {
      const params = new URLSearchParams(initData);
      const id = params.get('id');
      if (id) {
        return { id: parseInt(id) };
      }
    }
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) {
      // For development/testing, allow simplified format without hash
      if (typeof initData === 'string' && initData.startsWith('id=')) {
        const params = new URLSearchParams(initData);
        const id = params.get('id');
        if (id) {
          return { id: parseInt(id) };
        }
      }
      console.error('No hash found in Telegram init data');
      return null;
    }

    params.delete('hash');

    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData')
      .update(BOT_TOKEN)
      .digest();

    const computedHash = crypto.createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    if (computedHash !== hash) {
      console.error('Telegram auth hash verification failed');
      return null;
    }

    const userParam = params.get('user');
    if (!userParam) {
      console.error('No user parameter found in Telegram init data');
      return null;
    }

    return JSON.parse(decodeURIComponent(userParam));
  } catch (error) {
    console.error('Telegram verification error:', error);
    // For development/testing, allow simplified format without verification
    if (typeof initData === 'string' && initData.startsWith('id=')) {
      const params = new URLSearchParams(initData);
      const id = params.get('id');
      if (id) {
        return { id: parseInt(id) };
      }
    }
    return null;
  }
}

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId, action, maxRequests = 10, windowMs = 60000) {
  const key = `${userId}:${action}`;
  const now = Date.now();
  const windowStart = now - windowMs;

  const limit = rateLimits.get(key);

  if (!limit || limit.windowStart < windowStart) {
    // Reset the rate limit
    rateLimits.set(key, { count: 1, windowStart: now });
    return true;
  }

  if (limit.count >= maxRequests) {
    return false; // Rate limit exceeded
  }

  // Increment the count
  rateLimits.set(key, { count: limit.count + 1, windowStart: now });
  return true;
}

// RUN MIGRATIONS - FUNCȚIA REVIZUITĂ
async function runMigrations() {
  console.log('🔄 Running database migrations...');
  const client = await pool.connect();
  
  try {
    // Tabela users - VERSIUNE SIMPLIFICATĂ FĂRĂ ERORI
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE NOT NULL,
        username VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        photo_url TEXT,
        device_fingerprint VARCHAR(255),
        balance BIGINT DEFAULT 0,
        ton_balance BIGINT DEFAULT 0,
        gameplay_balance BIGINT DEFAULT 0,
        rare_balance BIGINT DEFAULT 0,
        event_balance BIGINT DEFAULT 0,
        daily_supply_balance BIGINT DEFAULT 0,
        merchant_balance BIGINT DEFAULT 0,
        referral_balance BIGINT DEFAULT 0,
        biometric_enabled BOOLEAN DEFAULT true,
        is_banned BOOLEAN DEFAULT false,
        wallet_address VARCHAR(255),
        referrals INTEGER DEFAULT 0,
        has_claimed_referral BOOLEAN DEFAULT false,
        ads_watched INTEGER DEFAULT 0,
        sponsored_ads_watched INTEGER DEFAULT 0,
        rare_items_collected INTEGER DEFAULT 0,
        event_items_collected INTEGER DEFAULT 0,
        screenshot_lock BOOLEAN DEFAULT false,
        is_airdropped BOOLEAN DEFAULT false,
        airdrop_allocation BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Created users table');

    // Tabela claims - SIMPLĂ
    await client.query(`
      CREATE TABLE IF NOT EXISTS claims (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        spawn_id VARCHAR(255) NOT NULL,
        category VARCHAR(50),
        claimed_value BIGINT DEFAULT 0,
        ton_reward BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Created claims table');

    // Tabela campaigns
    await client.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id SERIAL PRIMARY KEY,
        owner_wallet VARCHAR(255) NOT NULL,
        target_lat DECIMAL(10, 8) NOT NULL,
        target_lng DECIMAL(11, 8) NOT NULL,
        count INTEGER DEFAULT 1,
        multiplier INTEGER DEFAULT 1,
        duration_days INTEGER DEFAULT 1,
        expiry_date BIGINT,
        total_price BIGINT DEFAULT 0,
        brand_name VARCHAR(255),
        logo_url TEXT,
        video_url TEXT,
        video_file_name TEXT,
        contact_street VARCHAR(255),
        contact_city VARCHAR(255),
        contact_zip VARCHAR(50),
        contact_country VARCHAR(100),
        contact_phone VARCHAR(50),
        contact_email VARCHAR(255),
        contact_website VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending_review',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Created campaigns table');

    // Tabela hotspots
    await client.query(`
      CREATE TABLE IF NOT EXISTS hotspots (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        lat DECIMAL(10, 8) NOT NULL,
        lng DECIMAL(11, 8) NOT NULL,
        radius INTEGER DEFAULT 100,
        density INTEGER DEFAULT 10,
        category VARCHAR(50),
        base_value BIGINT DEFAULT 100,
        logo_url TEXT,
        custom_text VARCHAR(100),
        prizes TEXT, -- JSON array of numbers as text
        video_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Created hotspots table');

    // Tabela withdrawal_requests
    await client.query(`
      CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        amount BIGINT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP
      );
    `);
    console.log('✅ Created withdrawal_requests table');

    // Indexuri
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_telegram ON users(telegram_id);
      CREATE INDEX IF NOT EXISTS idx_claims_user ON claims(user_id);
      CREATE INDEX IF NOT EXISTS idx_claims_spawn ON claims(spawn_id);
      CREATE INDEX IF NOT EXISTS idx_users_wallet_address ON users(wallet_address);
      CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(created_at);
      CREATE INDEX IF NOT EXISTS idx_campaigns_owner ON campaigns(owner_wallet);
      CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user ON withdrawal_requests(user_id);
    `);
    console.log('✅ Created indexes');

    console.log('🎉 All migrations completed successfully!');

  } catch (error) {
    console.error('❌ Migration error:', error.message);
    console.error('SQL State:', error.code);
    // CONTINUĂ chiar dacă migrațiile eșuează parțial
  } finally {
    client.release();
  }
}

// API Routes
const usersRouter = require('./routes/users')(pool);
const claimsRouter = require('./routes/claims')(pool);
const campaignsRouter = require('./routes/campaigns')(pool);
const hotspotsRouter = require('./routes/hotspots')(pool);
const withdrawalsRouter = require('./routes/withdrawals')(pool);
const adminRouter = require('./routes/admin')(pool);
const aiRouter = require('./routes/ai')(pool);

// API routes
app.use('/api/users', usersRouter);
app.use('/api/claims', claimsRouter);
app.use('/api/campaigns', campaignsRouter);
app.use('/api/hotspots', hotspotsRouter);
app.use('/api/withdrawals', withdrawalsRouter);
app.use('/api/admin', adminRouter);
app.use('/api/ai', aiRouter);

// NEW endpoints as required by the prompt
// /api/sync-user (POST) - Creates/updates users with Telegram auth and fingerprint
app.post('/api/sync-user', async (req, res) => {
  try {
    const { telegramInitData, fingerprint } = req.body;

    // Verify Telegram authentication
    const telegramUser = verifyTelegramData(telegramInitData);
    if (!telegramUser) {
      return res.status(401).json({ success: false, error: 'Invalid Telegram auth' });
    }

    const telegramId = telegramUser.id;

    // Check rate limit
    if (!checkRateLimit(telegramId.toString(), 'sync-user')) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    // Check if user exists
    const existingUserQuery = 'SELECT * FROM users WHERE telegram_id = $1';
    const existingUserResult = await pool.query(existingUserQuery, [telegramId]);

    if (existingUserResult.rows.length > 0) {
      // Update existing user
      const updateQuery = `
        UPDATE users SET
          username = COALESCE($2, username),
          first_name = COALESCE($3, first_name),
          last_name = COALESCE($4, last_name),
          photo_url = COALESCE($5, photo_url),
          device_fingerprint = COALESCE($6, device_fingerprint),
          updated_at = CURRENT_TIMESTAMP
        WHERE telegram_id = $1
        RETURNING *;
      `;

      const result = await pool.query(updateQuery, [
        telegramId,
        telegramUser.username,
        telegramUser.first_name,
        telegramUser.last_name,
        telegramUser.photo_url,
        fingerprint
      ]);

      return res.json({ success: true, user: result.rows[0] });
    } else {
      // Create new user
      const insertQuery = `
        INSERT INTO users (
          telegram_id, username, first_name, last_name,
          photo_url, device_fingerprint
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *;
      `;

      const result = await pool.query(insertQuery, [
        telegramId,
        telegramUser.username,
        telegramUser.first_name,
        telegramUser.last_name,
        telegramUser.photo_url,
        fingerprint
      ]);

      return res.status(201).json({ success: true, user: result.rows[0] });
    }

  } catch (error) {
    console.error('Sync user error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// /api/collect (POST) - Saves collections and updates balances
app.post('/api/collect', async (req, res) => {
  try {
    const { telegramInitData, spawnId, value, category, tonReward, location } = req.body;

    // Verify Telegram authentication
    const telegramUser = verifyTelegramData(telegramInitData);
    if (!telegramUser) {
      return res.status(401).json({ success: false, error: 'Invalid Telegram auth' });
    }

    const telegramId = telegramUser.id;

    // Check rate limit
    if (!checkRateLimit(telegramId.toString(), 'collect')) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    // Check if collection already exists (except for ads)
    if (!spawnId.startsWith("ad-")) {
      const existingCollectionQuery = 'SELECT * FROM claims WHERE user_id = (SELECT id FROM users WHERE telegram_id = $1) AND spawn_id = $2';
      const existingCollectionResult = await pool.query(existingCollectionQuery, [telegramId, spawnId]);

      if (existingCollectionResult.rows.length > 0) {
        return res.status(400).json({ success: false, error: 'Item already collected' });
      }
    }

    // Get user ID from telegram_id
    const userQuery = 'SELECT id FROM users WHERE telegram_id = $1';
    const userResult = await pool.query(userQuery, [telegramId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const userId = userResult.rows[0].id;

    // Insert collection record
    const insertClaimQuery = `
      INSERT INTO claims (
        user_id, spawn_id, category, claimed_value, ton_reward
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `;

    await pool.query(insertClaimQuery, [userId, spawnId, category, value, tonReward]);

    // Update user balance based on category
    let updateField = 'gameplay_balance';
    if (category === 'AD_REWARD') {
      updateField = 'daily_supply_balance';
    } else if (category === 'LANDMARK') {
      updateField = 'rare_balance';
    } else if (category === 'EVENT') {
      updateField = 'event_balance';
    } else if (category === 'MERCHANT') {
      updateField = 'merchant_balance';
    } else if (category === 'GIFTBOX') {
      updateField = 'gameplay_balance';
    }

    // Update user balance and collected IDs
    const updateUserQuery = `
      UPDATE users SET
        ${updateField} = ${updateField} + $1,
        balance = balance + $1,
        ton_balance = ton_balance + $2,
        updated_at = CURRENT_TIMESTAMP
      WHERE telegram_id = $3
    `;

    await pool.query(updateUserQuery, [value, tonReward, telegramId]);

    // Update counters based on category
    if (category === 'LANDMARK') {
      await pool.query(
        'UPDATE users SET rare_items_collected = rare_items_collected + 1 WHERE telegram_id = $1',
        [telegramId]
      );
    } else if (category === 'EVENT') {
      await pool.query(
        'UPDATE users SET event_items_collected = event_items_collected + 1 WHERE telegram_id = $1',
        [telegramId]
      );
    } else if (category === 'AD_REWARD') {
      await pool.query(
        'UPDATE users SET ads_watched = ads_watched + 1 WHERE telegram_id = $1',
        [telegramId]
      );
    } else if (category === 'MERCHANT') {
      await pool.query(
        'UPDATE users SET sponsored_ads_watched = sponsored_ads_watched + 1 WHERE telegram_id = $1',
        [telegramId]
      );
    }

    res.json({ success: true, message: 'Collection saved successfully' });

  } catch (error) {
    console.error('Collect error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// /api/update-wallet (POST) - Updates wallet addresses with validation
app.post('/api/update-wallet', async (req, res) => {
  try {
    const { telegramInitData, walletAddress } = req.body;

    // Verify Telegram authentication
    const telegramUser = verifyTelegramData(telegramInitData);
    if (!telegramUser) {
      return res.status(401).json({ success: false, error: 'Invalid Telegram auth' });
    }

    const telegramId = telegramUser.id;

    // Check rate limit
    if (!checkRateLimit(telegramId.toString(), 'update-wallet')) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    // Validate wallet address format (basic validation)
    if (!walletAddress || typeof walletAddress !== 'string' || walletAddress.length < 10) {
      return res.status(400).json({ success: false, error: 'Invalid wallet address format' });
    }

    // Update user wallet address
    const updateQuery = `
      UPDATE users SET
        wallet_address = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE telegram_id = $2
      RETURNING *;
    `;

    const result = await pool.query(updateQuery, [walletAddress, telegramId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, message: 'Wallet updated successfully', user: result.rows[0] });

  } catch (error) {
    console.error('Update wallet error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// /api/get-user (GET) - Returns user data by Telegram ID
app.get('/api/get-user', async (req, res) => {
  try {
    const telegramId = req.query.telegramId;

    if (!telegramId) {
      return res.status(400).json({ success: false, error: 'Telegram ID is required' });
    }

    // Check rate limit
    if (!checkRateLimit(telegramId, 'get-user')) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    const query = 'SELECT * FROM users WHERE telegram_id = $1';
    const result = await pool.query(query, [telegramId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: result.rows[0] });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// /api/get-leaderboard (GET) - Returns top 50 users by balance
app.get('/api/get-leaderboard', async (req, res) => {
  try {
    // Check rate limit
    if (!checkRateLimit('leaderboard', 'get-leaderboard')) {
      return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
    }

    const query = `
      SELECT
        telegram_id,
        username,
        first_name,
        last_name,
        photo_url,
        balance,
        ton_balance,
        gameplay_balance,
        rare_balance,
        event_balance,
        daily_supply_balance,
        merchant_balance,
        referral_balance
      FROM users
      WHERE is_banned = FALSE
      ORDER BY balance DESC
      LIMIT 50
    `;

    const result = await pool.query(query);

    res.json({ success: true, leaderboard: result.rows });

  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// BASIC ENDPOINTS CARE MERG SIGUR

// Test endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'ELZR Hunt Railway Backend API',
    status: 'running',
    timestamp: new Date().toISOString(),
    database: pool.totalCount > 0 ? 'pool-ready' : 'pool-empty'
  });
});

// Health check pentru Railway
app.get('/health', async (req, res) => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    
    res.json({ 
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy',
      database: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Test database endpoint
app.get('/test-db', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT COUNT(*) as user_count FROM users');
    client.release();
    
    res.json({
      success: true,
      database: 'working',
      userCount: result.rows[0].user_count,
      tables: ['users', 'claims', 'campaigns', 'hotspots', 'withdrawal_requests']
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Check if tables exist'
    });
  }
});

// START SERVER - PROCES IERARHIC CORECT
async function startServer() {
  console.log('🚀 Starting ELZR Hunt Backend...');
  console.log('📊 Environment:', process.env.NODE_ENV || 'development');
  console.log('🔌 Database URL:', process.env.DATABASE_PUBLIC_URL ? 'Set' : 'Not set');
  
  try {
    // 1. Testează conexiunea la DB
    const dbConnected = await testDatabaseConnection();
    if (!dbConnected) {
      console.log('⚠️  Continuing without database connection...');
    }
    
    // 2. Rulează migrațiile
    await runMigrations();
    
    // 3. Pornește serverul
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
      console.log(`📡 Local: http://localhost:${PORT}`);
      console.log(`🩺 Health check: http://localhost:${PORT}/health`);
      console.log(`🗄️  DB test: http://localhost:${PORT}/test-db`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

// PORNESTE SERVERUL
startServer();

module.exports = app;