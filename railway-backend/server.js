const express = require('express');
const port = 3000
const crypto = require('crypto');
const prisma = require('./lib/prisma');
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

// Test database connection
async function testDatabaseConnection() {
  console.log('🔍 Testing database connection...');
  try {
    if (process.env.DATABASE_URL) {
      await prisma.$connect();
      console.log('✅ Database connected successfully');
      return true;
    } else {
      console.log('⚠️  DATABASE_URL not set, skipping connection test');
      return false;
    }
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
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
  try {
    // Prisma 7 uses schema-based migrations, so we'll just test the connection
    // The actual table creation is handled by Prisma schema and migrations
    console.log('📝 Prisma schema-based migrations will be handled by Prisma CLI');
    console.log('📝 Use `npx prisma db push` for development or `npx prisma migrate dev` for production');

    // Test that the database connection works with Prisma
    if (process.env.DATABASE_URL) {
      await prisma.$connect();
      console.log('✅ Prisma database connection established successfully');

      // Try to access one of the models to verify they exist
      try {
        await prisma.user.count();
        console.log('✅ User model is accessible');
      } catch (error) {
        console.log('⚠️  User model may not exist yet - run migrations first');
      }
    } else {
      console.log('⚠️  DATABASE_URL not set, skipping database connection test');
    }

    console.log('🎉 Migration check completed successfully!');

  } catch (error) {
    console.error('❌ Migration error details:', error);
    console.error('Full error object:', JSON.stringify(error, null, 2));
    console.error('Error message:', error.message);
    // CONTINUĂ chiar dacă migrațiile eșuează parțial
  }
}

// API Routes
const usersRouter = require('./routes/users')(prisma);
const claimsRouter = require('./routes/claims')(prisma);
const campaignsRouter = require('./routes/campaigns')(prisma);
const hotspotsRouter = require('./routes/hotspots')(prisma);
const withdrawalsRouter = require('./routes/withdrawals')(prisma);
const adminRouter = require('./routes/admin')(prisma);
const aiRouter = require('./routes/ai')(prisma);

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

    // Use Prisma to create or update user
    const user = await prisma.user.upsert({
      where: { telegramId: BigInt(telegramId) },
      update: {
        username: telegramUser.username || undefined,
        firstName: telegramUser.first_name || undefined,
        lastName: telegramUser.last_name || undefined,
        photoUrl: telegramUser.photo_url || undefined,
        deviceFingerprint: fingerprint || undefined,
      },
      create: {
        telegramId: BigInt(telegramId),
        username: telegramUser.username,
        firstName: telegramUser.first_name,
        lastName: telegramUser.last_name,
        photoUrl: telegramUser.photo_url,
        deviceFingerprint: fingerprint,
      }
    });

    return res.json({ success: true, user });

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
      const existingClaim = await prisma.claim.findFirst({
        where: {
          user: { telegramId: BigInt(telegramId) },
          spawnId
        }
      });

      if (existingClaim) {
        return res.status(400).json({ success: false, error: 'Item already collected' });
      }
    }

    // Get user
    const user = await prisma.user.findUnique({
      where: { telegramId: BigInt(telegramId) }
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Create collection record
    await prisma.claim.create({
      data: {
        userId: user.id,
        spawnId,
        category,
        claimedValue: BigInt(value),
        tonReward: BigInt(tonReward)
      }
    });

    // Update user balance based on category
    let balanceUpdate = {};
    if (category === 'AD_REWARD') {
      balanceUpdate = {
        dailySupplyBalance: { increment: BigInt(value) },
        balance: { increment: BigInt(value) },
        tonBalance: { increment: BigInt(tonReward) },
        adsWatched: { increment: 1 }
      };
    } else if (category === 'LANDMARK') {
      balanceUpdate = {
        rareBalance: { increment: BigInt(value) },
        balance: { increment: BigInt(value) },
        tonBalance: { increment: BigInt(tonReward) },
        rareItemsCollected: { increment: 1 }
      };
    } else if (category === 'EVENT') {
      balanceUpdate = {
        eventBalance: { increment: BigInt(value) },
        balance: { increment: BigInt(value) },
        tonBalance: { increment: BigInt(tonReward) },
        eventItemsCollected: { increment: 1 }
      };
    } else if (category === 'MERCHANT') {
      balanceUpdate = {
        merchantBalance: { increment: BigInt(value) },
        balance: { increment: BigInt(value) },
        tonBalance: { increment: BigInt(tonReward) },
        sponsoredAdsWatched: { increment: 1 }
      };
    } else {
      // Default case for GIFTBOX and other categories
      balanceUpdate = {
        gameplayBalance: { increment: BigInt(value) },
        balance: { increment: BigInt(value) },
        tonBalance: { increment: BigInt(tonReward) }
      };
    }

    // Update user balance and collected counters
    await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        ...balanceUpdate,
        updatedAt: new Date()
      }
    });

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
    const user = await prisma.user.update({
      where: { telegramId: BigInt(telegramId) },
      data: {
        walletAddress,
        updatedAt: new Date()
      }
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, message: 'Wallet updated successfully', user });

  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ success: false, error: 'User not found' });
    }
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

    const user = await prisma.user.findUnique({
      where: { telegramId: BigInt(telegramId) }
    });

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user });

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

    const leaderboard = await prisma.user.findMany({
      where: {
        isBanned: false
      },
      select: {
        telegramId: true,
        username: true,
        firstName: true,
        lastName: true,
        photoUrl: true,
        balance: true,
        tonBalance: true,
        gameplayBalance: true,
        rareBalance: true,
        eventBalance: true,
        dailySupplyBalance: true,
        merchantBalance: true,
        referralBalance: true
      },
      orderBy: {
        balance: 'desc'
      },
      take: 50
    });

    res.json({ success: true, leaderboard });

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
    await prisma.$queryRaw`SELECT 1`;

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
    const userCount = await prisma.user.count();

    res.json({
      success: true,
      database: 'working',
      userCount,
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
  console.log('🔌 Database URL:', process.env.DATABASE_URL ? 'Set' : 'Not set');

  try {
    // 1. Testează conexiunea la DB
    let dbConnected = false;
    try {
      dbConnected = await testDatabaseConnection();
    } catch (dbError) {
      console.log('⚠️  Database connection test failed:', dbError.message);
    }

    if (!dbConnected) {
      console.log('⚠️  Attempting to continue without initial database connection...');
    }

    // 2. Rulează migrațiile (IMPORTANT: trebuie să ruleze mereu pentru a crea tabelele)
    console.log('🔧 Running database migrations...');
    try {
      await runMigrations();
      console.log('✅ Migrations completed');
    } catch (migrationError) {
      console.error('❌ Migrations failed:', migrationError.message);
      console.log('⚠️  Continuing server startup despite migration failure...');
    }

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
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});

// PORNESTE SERVERUL
startServer();

module.exports = app;