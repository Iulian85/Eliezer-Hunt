const express = require('express');
const { Client } = require('pg');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
const usersRouter = require('./routes/users');
const claimsRouter = require('./routes/claims');
const campaignsRouter = require('./routes/campaigns');
const hotspotsRouter = require('./routes/hotspots');
const withdrawalsRouter = require('./routes/withdrawals');
const adminRouter = require('./routes/admin');
const aiRouter = require('./routes/ai');

// API routes
app.use('/api/users', usersRouter);
app.use('/api/claims', claimsRouter);
app.use('/api/campaigns', campaignsRouter);
app.use('/api/hotspots', hotspotsRouter);
app.use('/api/withdrawals', withdrawalsRouter);
app.use('/api/admin', adminRouter);
app.use('/api/ai', aiRouter);

// Basic route
app.get('/', (req, res) => {
  res.json({ message: 'ELZR Hunt Railway Backend API' });
});

// Database connection
const db = new Client({
  connectionString: process.env.DATABASE_PUBLIC_URL,
  ssl: { rejectUnauthorized: false }, // SSL mode prefer - encryption is used if the server supports it
});

// Function to run migrations
async function runMigrations() {
  let client;
  try {
    console.log('Starting migration process...');
    const connectionString = process.env.DATABASE_URL || process.env.DATABASE_PUBLIC_URL;
    if (!connectionString) {
      throw new Error('No database connection string. Set DATABASE_URL or DATABASE_PUBLIC_URL');
    }

    client = new Client({
      connectionString,
      ssl: { rejectUnauthorized: false },
    });

    await client.connect();
    console.log('Connected to database');

    // Creează tabelele direct în cod (adaptează la schema ta exactă)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE NOT NULL,
        username VARCHAR(255),
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
        collected_ids TEXT[] DEFAULT '{}',
        biometric_enabled BOOLEAN DEFAULT true,
        is_banned BOOLEAN DEFAULT false,
        wallet_address VARCHAR(255),
        referrals INTEGER DEFAULT 0,
        referral_names TEXT[] DEFAULT '{}',
        has_claimed_referral BOOLEAN DEFAULT false,
        last_ad_watch BIGINT DEFAULT 0,
        last_daily_claim BIGINT DEFAULT 0,
        ads_watched INTEGER DEFAULT 0,
        sponsored_ads_watched INTEGER DEFAULT 0,
        rare_items_collected INTEGER DEFAULT 0,
        event_items_collected INTEGER DEFAULT 0,
        last_init_data TEXT,
        screenshot_lock BOOLEAN DEFAULT false,
        is_airdropped BOOLEAN DEFAULT false,
        airdrop_allocation BIGINT DEFAULT 0,
        airdrop_timestamp TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Function to update updated_at timestamp
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';

      -- Trigger to update updated_at for users table
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();

      CREATE TABLE IF NOT EXISTS claims (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        spawn_id VARCHAR(255) NOT NULL,
        category VARCHAR(50),
        claimed_value BIGINT DEFAULT 0,
        ton_reward BIGINT DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Index for claims table
      CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
      CREATE INDEX IF NOT EXISTS idx_claims_spawn_id ON claims(spawn_id);

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

      -- Trigger to update updated_at for campaigns table
      CREATE TRIGGER update_campaigns_updated_at
          BEFORE UPDATE ON campaigns
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();

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

      -- Trigger to update updated_at for hotspots table
      CREATE TRIGGER update_hotspots_updated_at
          BEFORE UPDATE ON hotspots
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();

      CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount BIGINT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP WITH TIME ZONE
      );

      -- Index for withdrawal_requests table
      CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON withdrawal_requests(user_id);
      CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON withdrawal_requests(status);

      -- Rate limits table (for API rate limiting)
      CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        action VARCHAR(100) NOT NULL,
        count INTEGER DEFAULT 1,
        window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Index for rate_limits table
      CREATE INDEX IF NOT EXISTS idx_rate_limits_user_action ON rate_limits(user_id, action);

      -- Indexes for performance
      CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
      CREATE INDEX IF NOT EXISTS idx_users_wallet_address ON users(wallet_address);
      CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);
      CREATE INDEX IF NOT EXISTS idx_claims_created_at ON claims(created_at);
      CREATE INDEX IF NOT EXISTS idx_campaigns_created_at ON campaigns(created_at);
      CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
      CREATE INDEX IF NOT EXISTS idx_campaigns_owner_wallet ON campaigns(owner_wallet);
    `);

    console.log('Tables created or already exist');
    await client.end();
  } catch (error) {
    console.error('Migration error:', error.message, error.stack);
    if (client) await client.end();
    process.exit(1);
  }
}

// Run migrations first, then start the server
async function startServer() {
  try {
    await runMigrations();

    // Error handling middleware
    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).json({ error: 'Something went wrong!' });
    });

    // Start server
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
