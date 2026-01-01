import { serve } from 'bun';
import { Client } from 'pg';
import * as crypto from 'crypto';

// PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Telegram User interface
interface TelegramUser {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  language_code?: string;
}

// Verify Telegram authentication data
function verifyTelegramData(initData: string): TelegramUser | null {
  const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  if (!BOT_TOKEN) {
    console.error('TELEGRAM_BOT_TOKEN is not set in environment variables');
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) {
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
    
    return JSON.parse(decodeURIComponent(userParam)) as TelegramUser;
  } catch (error) {
    console.error('Telegram verification error:', error);
    return null;
  }
}

// Initialize database and create tables
async function initDB() {
  await client.connect();
  
  // Create tables if not exists
  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      telegram_id BIGINT UNIQUE NOT NULL,
      username VARCHAR(100),
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      photo_url TEXT,
      language_code VARCHAR(10),
      fingerprint VARCHAR(255),
      balance DECIMAL(15,2) DEFAULT 0,
      ton_balance DECIMAL(15,2) DEFAULT 0,
      gameplay_balance DECIMAL(15,2) DEFAULT 0,
      rare_balance DECIMAL(15,2) DEFAULT 0,
      event_balance DECIMAL(15,2) DEFAULT 0,
      daily_supply_balance DECIMAL(15,2) DEFAULT 0,
      merchant_balance DECIMAL(15,2) DEFAULT 0,
      referral_balance DECIMAL(15,2) DEFAULT 0,
      collected_ids TEXT[] DEFAULT '{}',
      is_banned BOOLEAN DEFAULT FALSE,
      referrals INTEGER DEFAULT 0,
      referral_names TEXT[] DEFAULT '{}',
      ads_watched INTEGER DEFAULT 0,
      sponsored_ads_watched INTEGER DEFAULT 0,
      rare_items_collected INTEGER DEFAULT 0,
      event_items_collected INTEGER DEFAULT 0,
      last_ad_watch TIMESTAMP,
      last_daily_claim TIMESTAMP,
      last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS collections (
      id SERIAL PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      spawn_id VARCHAR(100) NOT NULL,
      category VARCHAR(50),
      value DECIMAL(15,2) NOT NULL,
      ton_reward DECIMAL(15,2) DEFAULT 0,
      location JSONB,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS campaigns (
      id VARCHAR(100) PRIMARY KEY,
      owner_wallet VARCHAR(100),
      owner_telegram_id BIGINT,
      owner_username VARCHAR(100),
      target_coords JSONB,
      count INTEGER,
      multiplier DECIMAL(10,2),
      duration_days INTEGER,
      total_price DECIMAL(15,2),
      data JSONB,
      status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS hotspots (
      id VARCHAR(100) PRIMARY KEY,
      name VARCHAR(200),
      coords JSONB,
      radius INTEGER,
      density INTEGER,
      category VARCHAR(50),
      base_value DECIMAL(15,2),
      logo_url TEXT,
      custom_text VARCHAR(100),
      sponsor_data JSONB,
      created_by VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  return client;
}

// Rate limiting storage
const rateLimits = new Map<string, { count: number; windowStart: number }>();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests: number = 10, windowMs: number = 60000): boolean {
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

// Create response helper functions
function successResponse(data: any) {
  return new Response(JSON.stringify({ success: true, ...data }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

function errorResponse(message: string, statusCode: number = 400) {
  return new Response(JSON.stringify({ success: false, error: message }), {
    status: statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// Initialize database
const db = await initDB();

const server = serve({
  port: process.env.PORT || 3000,
  async fetch(req) {
    const url = new URL(req.url);
    
    // CORS headers
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json'
    };

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // API Routes
    if (url.pathname === '/api/sync-user' && req.method === 'POST') {
      try {
        const { telegramInitData, fingerprint } = await req.json();
        
        // Verify Telegram authentication
        const telegramUser = verifyTelegramData(telegramInitData);
        if (!telegramUser) {
          return errorResponse('Invalid Telegram auth', 401);
        }

        const telegramId = telegramUser.id;
        
        // Check rate limit
        if (!checkRateLimit(telegramId.toString(), 'sync-user')) {
          return errorResponse('Rate limit exceeded', 429);
        }

        // Check if user exists
        const existingUser = await db.query(
          'SELECT * FROM users WHERE telegram_id = $1',
          [telegramId]
        );
        
        if (existingUser.rows.length > 0) {
          // Update existing user
          await db.query(`
            UPDATE users SET 
              username = COALESCE($2, username),
              first_name = COALESCE($3, first_name),
              last_name = COALESCE($4, last_name),
              photo_url = COALESCE($5, photo_url),
              language_code = COALESCE($6, language_code),
              fingerprint = COALESCE($7, fingerprint),
              last_active = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
            WHERE telegram_id = $1
          `, [telegramId, telegramUser.username, telegramUser.first_name, 
              telegramUser.last_name, telegramUser.photo_url, 
              telegramUser.language_code, fingerprint]);
              
          const updatedUser = await db.query(
            'SELECT * FROM users WHERE telegram_id = $1',
            [telegramId]
          );
          
          return successResponse({ user: updatedUser.rows[0] });
        } else {
          // Create new user
          const newUser = await db.query(`
            INSERT INTO users (
              telegram_id, username, first_name, last_name, 
              photo_url, language_code, fingerprint, joined_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
            RETURNING *
          `, [telegramId, telegramUser.username, telegramUser.first_name,
              telegramUser.last_name, telegramUser.photo_url,
              telegramUser.language_code, fingerprint]);
              
          return successResponse({ user: newUser.rows[0] });
        }
        
      } catch (error) {
        console.error('Sync user error:', error);
        return errorResponse('Internal server error', 500);
      }
    }

    // API Route: /api/collect (POST)
    if (url.pathname === '/api/collect' && req.method === 'POST') {
      try {
        const { telegramInitData, spawnId, value, category, tonReward, location } = await req.json();
        
        // Verify Telegram authentication
        const telegramUser = verifyTelegramData(telegramInitData);
        if (!telegramUser) {
          return errorResponse('Invalid Telegram auth', 401);
        }

        const telegramId = telegramUser.id;
        
        // Check rate limit
        if (!checkRateLimit(telegramId.toString(), 'collect')) {
          return errorResponse('Rate limit exceeded', 429);
        }

        // Check if collection already exists (except for ads)
        if (!spawnId.startsWith("ad-")) {
          const existingCollection = await db.query(
            'SELECT * FROM collections WHERE telegram_id = $1 AND spawn_id = $2',
            [telegramId, spawnId]
          );
          
          if (existingCollection.rows.length > 0) {
            return errorResponse('Item already collected', 400);
          }
        }

        // Insert collection record
        await db.query(`
          INSERT INTO collections (
            telegram_id, spawn_id, category, value, ton_reward, location
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `, [telegramId, spawnId, category, value, tonReward, location]);

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
        await db.query(`
          UPDATE users SET 
            ${updateField} = ${updateField} + $2,
            balance = balance + $2,
            ton_balance = ton_balance + $3,
            last_active = CURRENT_TIMESTAMP,
            collected_ids = CASE 
              WHEN $4 = true THEN collected_ids
              ELSE array_append(collected_ids, $1)
            END
          WHERE telegram_id = $5
        `, [spawnId, value, tonReward, spawnId.startsWith("ad-"), telegramId]);

        // Update counters based on category
        if (category === 'LANDMARK') {
          await db.query(`
            UPDATE users SET 
              rare_items_collected = rare_items_collected + 1
            WHERE telegram_id = $1
          `, [telegramId]);
        } else if (category === 'EVENT') {
          await db.query(`
            UPDATE users SET 
              event_items_collected = event_items_collected + 1
            WHERE telegram_id = $1
          `, [telegramId]);
        } else if (category === 'AD_REWARD') {
          await db.query(`
            UPDATE users SET 
              ads_watched = ads_watched + 1,
              last_ad_watch = CURRENT_TIMESTAMP
            WHERE telegram_id = $1
          `, [telegramId]);
        } else if (category === 'MERCHANT') {
          await db.query(`
            UPDATE users SET 
              sponsored_ads_watched = sponsored_ads_watched + 1
            WHERE telegram_id = $1
          `, [telegramId]);
        }

        return successResponse({ message: 'Collection saved successfully' });
        
      } catch (error) {
        console.error('Collect error:', error);
        return errorResponse('Internal server error', 500);
      }
    }

    // API Route: /api/update-wallet (POST)
    if (url.pathname === '/api/update-wallet' && req.method === 'POST') {
      try {
        const { telegramInitData, walletAddress } = await req.json();
        
        // Verify Telegram authentication
        const telegramUser = verifyTelegramData(telegramInitData);
        if (!telegramUser) {
          return errorResponse('Invalid Telegram auth', 401);
        }

        const telegramId = telegramUser.id;
        
        // Check rate limit
        if (!checkRateLimit(telegramId.toString(), 'update-wallet')) {
          return errorResponse('Rate limit exceeded', 429);
        }

        // Validate wallet address format (basic validation)
        if (!walletAddress || typeof walletAddress !== 'string' || walletAddress.length < 10) {
          return errorResponse('Invalid wallet address format', 400);
        }

        // Update user wallet address
        await db.query(`
          UPDATE users SET 
            wallet_address = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE telegram_id = $2
        `, [walletAddress, telegramId]);

        return successResponse({ message: 'Wallet updated successfully' });
        
      } catch (error) {
        console.error('Update wallet error:', error);
        return errorResponse('Internal server error', 500);
      }
    }

    // API Route: /api/get-user (GET)
    if (url.pathname === '/api/get-user' && req.method === 'GET') {
      try {
        const telegramId = url.searchParams.get('telegramId');
        
        if (!telegramId) {
          return errorResponse('Telegram ID is required', 400);
        }

        // Check rate limit
        if (!checkRateLimit(telegramId, 'get-user')) {
          return errorResponse('Rate limit exceeded', 429);
        }

        const result = await db.query(
          'SELECT * FROM users WHERE telegram_id = $1',
          [telegramId]
        );

        if (result.rows.length === 0) {
          return errorResponse('User not found', 404);
        }

        return successResponse({ user: result.rows[0] });
        
      } catch (error) {
        console.error('Get user error:', error);
        return errorResponse('Internal server error', 500);
      }
    }

    // API Route: /api/get-leaderboard (GET)
    if (url.pathname === '/api/get-leaderboard' && req.method === 'GET') {
      try {
        // Check rate limit
        if (!checkRateLimit('leaderboard', 'get-leaderboard')) {
          return errorResponse('Rate limit exceeded', 429);
        }

        const result = await db.query(`
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
        `);

        return successResponse({ leaderboard: result.rows });
        
      } catch (error) {
        console.error('Get leaderboard error:', error);
        return errorResponse('Internal server error', 500);
      }
    }

    // Default 404
    return new Response('Not Found', { 
      status: 404,
      headers: {
        'Content-Type': 'text/plain'
      }
    });
  }
});

console.log(`Bun.js server running on port ${server.port}`);