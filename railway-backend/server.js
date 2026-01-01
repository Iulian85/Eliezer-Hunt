console.log('🚀 Starting server.js...');
console.log('📁 Current directory:', __dirname);
console.log('📦 Node version:', process.version);
console.log('🔧 NODE_ENV:', process.env.NODE_ENV);
console.log('🌐 PORT:', process.env.PORT);
console.log('🗄️ DATABASE_PUBLIC_URL:', process.env.DATABASE_PUBLIC_URL ? 'Set' : 'Not set');

const express = require('express');
const { Pool } = require('pg'); // Folosește Pool în loc de Client
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configurat pentru securitate
const cors = require('cors');
app.use(cors({
  origin: [
    'https://eliezer-hunt-production.up.railway.app',
    'https://t.me',  // Telegram Web Apps
    'https://web.telegram.org',
    'http://localhost:8080',  // Local development
    'http://localhost:3000',  // Alternative local port
    'http://localhost:5000',  // Vite default port
    'http://localhost:5173',  // Vite default port
    'https://*.railway.app'    // Orice subdomeniu Railway
  ],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Database connection POOL (mai bun pentru Railway)
const pool = new Pool({
  connectionString: process.env.DATABASE_PUBLIC_URL,
  ssl: { rejectUnauthorized: false },
});

// Test database connection
pool.on('connect', () => {
  console.log('Database connected successfully');
});

pool.on('error', (err) => {
  console.error('Unexpected database error', err);
});

// Run migrations ONCE
async function runMigrations() {
  const client = await pool.connect();
  try {
    console.log('Running database migrations...');
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE NOT NULL,
        username VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        photo_url TEXT,
        device_fingerprint VARCHAR(255),
        joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS claims (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        spawn_id VARCHAR(255) NOT NULL,
        category VARCHAR(50),
        claimed_value BIGINT DEFAULT 0,
        ton_reward BIGINT DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, spawn_id)
      );
    `);

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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount BIGINT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP WITH TIME ZONE
      );
    `);

    // Function to update updated_at timestamp
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Trigger to update updated_at for users table
    await client.query(`
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    // Trigger to update updated_at for campaigns table
    await client.query(`
      CREATE TRIGGER update_campaigns_updated_at
          BEFORE UPDATE ON campaigns
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    // Trigger to update updated_at for hotspots table
    await client.query(`
      CREATE TRIGGER update_hotspots_updated_at
          BEFORE UPDATE ON hotspots
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    // Indexes for performance
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
      CREATE INDEX IF NOT EXISTS idx_users_wallet_address ON users(wallet_address);
      CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);
      CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
      CREATE INDEX IF NOT EXISTS idx_claims_spawn_id ON claims(spawn_id);
      CREATE INDEX IF NOT EXISTS idx_claims_created_at ON claims(created_at);
      CREATE INDEX IF NOT EXISTS idx_campaigns_created_at ON campaigns(created_at);
      CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
      CREATE INDEX IF NOT EXISTS idx_campaigns_owner_wallet ON campaigns(owner_wallet);
      CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON withdrawal_requests(user_id);
      CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON withdrawal_requests(status);
    `);
    
    console.log('Migrations completed successfully');
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    client.release();
  }
}

// API Routes - folosește pool în loc de db
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

// Basic endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'ELZR Hunt Backend API',
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

// Health check pentru Railway
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: error.message
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Rulează migrațiile o singură dată
    await runMigrations();

    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Database: ${process.env.DATABASE_PUBLIC_URL ? 'Connected' : 'Not configured'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = { app, pool };