const express = require('express');
const { Pool } = require('pg'); // Folosește Pool în loc de Client
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS simplificat
const cors = require('cors');
app.use(cors());

// Database connection POOL (mai bun pentru Railway)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || process.env.DATABASE_PUBLIC_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
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

    // Adaugă restul tabelelor...
    
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
// ... restul routerelor

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
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    // Rulează migrațiile o singură dată
    await runMigrations();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = { app, pool };