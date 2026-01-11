const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const app = express();

// Use the port provided by Railway or default to 3000
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: '*', // Allow all origins during development
  credentials: true
}));
app.use(express.json());

// Special middleware to handle .tsx and .ts files by transpiling them to JavaScript
app.use((req, res, next) => {
  if (req.path.endsWith('.tsx') || req.path.endsWith('.ts')) {
    const fs = require('fs');
    const pathModule = require('path');
    const babel = require('@babel/core');

    const filePath = pathModule.join(__dirname, req.path);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');

      try {
        // Transpile TypeScript/JSX to JavaScript
        const result = babel.transformSync(content, {
          presets: [
            ['@babel/preset-react', { runtime: 'automatic' }],
            '@babel/preset-typescript'
          ],
          filename: req.path
        });

        res.setHeader('Content-Type', 'application/javascript');
        res.send(result.code);
      } catch (error) {
        console.error('Transpilation error:', error);
        res.status(500).send(`Transpilation error: ${error.message}`);
      }
    } else {
      next();
    }
  } else {
    next();
  }
});

// Serve static files with proper headers for ES modules
app.use(express.static('.', {
  setHeaders: (res, path) => {
    if (path.endsWith('.js') || path.endsWith('.jsx')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
  }
}));

// Special handling for index.html to ensure it's served for client-side routing
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), { headers: { 'Content-Type': 'text/html' } });
});

// Mock database (in production, use a real database like Redis or PostgreSQL)
const securityVerifications = {};

// Handle API routes first (before serving static files)

/**
 * Verifies Telegram WebApp initData to ensure the request is legitimate
 * @param {string} initDataRaw Raw initData string from Telegram WebApp
 * @param {string} botToken Your bot token
 * @returns {boolean} True if the initData is valid, false otherwise
 */
function verifyTelegramInitData(initDataRaw, botToken) {
  try {
    // Parse the initData
    const params = new URLSearchParams(initDataRaw);
    const hash = params.get('hash');
    params.delete('hash');

    // Sort parameters alphabetically
    const dataCheckArray = [];
    for (const [key, value] of params.entries()) {
      dataCheckArray.push(`${key}=${value}`);
    }
    dataCheckArray.sort();

    const dataCheckString = dataCheckArray.join('\n');

    // Create secret key using SHA256
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(botToken)
      .digest();

    // Create hash of data check string
    const calculatedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    // Compare hashes
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(calculatedHash));
  } catch (error) {
    console.error('Error verifying Telegram initData:', error);
    return false;
  }
}

/**
 * Verifies the HMAC signature of the security token
 * @param {string} token The JWT-like token from the native app
 * @returns {Object|null} Decoded payload if valid, null otherwise
 */
function verifyTokenSignature(token) {
  try {
    const [header, payload, signature] = token.split('.');

    if (!header || !payload || !signature) {
      console.error('Invalid token format');
      return null;
    }

    // Decode payload
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));

    // Recreate the payload string to verify signature
    const expectedPayloadString = Buffer.from(payload, 'base64').toString('utf8');

    // Verify HMAC signature using your secret key
    // In production, this should be stored securely (e.g., in environment variables)
    const hmacSecret = process.env.HMAC_SECRET || 'YOUR_SECRET_KEY_HERE';
    const expectedSignature = crypto
      .createHmac('sha256', hmacSecret)
      .update(expectedPayloadString)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const actualSignature = signature
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Compare signatures safely
    if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(actualSignature))) {
      console.error('Token signature verification failed');
      return null;
    }

    return decodedPayload;
  } catch (error) {
    console.error('Error verifying token signature:', error);
    return null;
  }
}

/**
 * API endpoint to check if a user has completed native security verification
 */
app.post('/checkSecurityVerification', async (req, res) => {
  try {
    const { telegramUserId, initData } = req.body;

    // Verify Telegram initData to ensure the request is legitimate
    if (!initData) {
      return res.status(400).json({ error: 'Missing Telegram initData' });
    }

    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) {
      return res.status(500).json({ error: 'Server configuration error: missing bot token' });
    }

    if (!verifyTelegramInitData(initData, botToken)) {
      return res.status(403).json({ error: 'Invalid Telegram initData' });
    }

    // Extract the actual telegramUserId from the initData to prevent spoofing
    const initDataParams = new URLSearchParams(initData);
    const userParam = initDataParams.get('user');
    if (!userParam) {
      return res.status(400).json({ error: 'Invalid Telegram initData: missing user data' });
    }

    const telegramUserData = JSON.parse(decodeURIComponent(userParam));
    const actualTelegramUserId = telegramUserData.id.toString();

    // Ensure the telegramUserId in the request matches the one from Telegram
    if (actualTelegramUserId !== telegramUserId) {
      return res.status(403).json({ error: 'Telegram user ID mismatch' });
    }

    // Check if security verification exists for this user
    const verificationData = securityVerifications[actualTelegramUserId];

    if (!verificationData) {
      return res.status(200).json({ verified: false });
    }

    // Check if verification has expired (24 hours)
    const now = Date.now();
    if (verificationData.expiresAt < now) {
      // Delete expired verification
      delete securityVerifications[actualTelegramUserId];
      return res.status(200).json({ verified: false });
    }

    // Return verification status
    res.status(200).json({
      verified: verificationData.verified,
      timestamp: verificationData.timestamp
    });
  } catch (error) {
    console.error('Error checking security verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * API endpoint to register a security verification from native app
 */
app.post('/registerSecurityVerification', async (req, res) => {
  try {
    const { telegramUserId, token, platform, initData } = req.body;

    if (!telegramUserId || !token || !platform || !initData) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify Telegram initData to ensure the request is legitimate
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) {
      return res.status(500).json({ error: 'Server configuration error: missing bot token' });
    }

    if (!verifyTelegramInitData(initData, botToken)) {
      return res.status(403).json({ error: 'Invalid Telegram initData' });
    }

    // Extract the actual telegramUserId from the initData to prevent spoofing
    const initDataParams = new URLSearchParams(initData);
    const userParam = initDataParams.get('user');
    if (!userParam) {
      return res.status(400).json({ error: 'Invalid Telegram initData: missing user data' });
    }

    const telegramUserData = JSON.parse(decodeURIComponent(userParam));
    const actualTelegramUserId = telegramUserData.id.toString();

    // Ensure the telegramUserId in the request matches the one from Telegram
    if (actualTelegramUserId !== telegramUserId) {
      return res.status(403).json({ error: 'Telegram user ID mismatch' });
    }

    // Verify the token signature
    const decodedToken = verifyTokenSignature(token);
    if (!decodedToken) {
      return res.status(403).json({ error: 'Invalid token signature' });
    }

    // Verify that the token contains the correct telegramUserId
    if (decodedToken.telegramUserId !== actualTelegramUserId) {
      return res.status(403).json({ error: 'Token telegramUserId mismatch' });
    }

    // Verify that the token is not expired (max 24h)
    const now = Date.now();
    const tokenTimestamp = decodedToken.timestamp;
    if (now - tokenTimestamp > 24 * 60 * 60 * 1000) { // 24 hours
      return res.status(403).json({ error: 'Token expired' });
    }

    // Verify that the platform matches
    if (decodedToken.platform !== platform) {
      return res.status(403).json({ error: 'Platform mismatch' });
    }

    // Create/update security verification record
    const verificationData = {
      telegramUserId: actualTelegramUserId,
      verified: decodedToken.verified,
      token,
      timestamp: Date.now(),
      expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours from now
    };

    securityVerifications[actualTelegramUserId] = verificationData;

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error registering security verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve the main app for all non-API routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle API routes specifically
app.get('/checkSecurityVerification', (req, res) => {
  res.status(405).json({ error: 'Method not allowed. Use POST.' });
});

app.get('/registerSecurityVerification', (req, res) => {
  res.status(405).json({ error: 'Method not allowed. Use POST.' });
});

// For any other non-API routes, serve the main app
app.get('*', (req, res) => {
  // Check if it's an API route
  if (req.path.startsWith('/checkSecurityVerification') || req.path.startsWith('/registerSecurityVerification')) {
    // This will be handled by the POST routes below
    res.status(404).json({ error: 'Method not allowed for GET. Use POST.' });
  } else {
    // Serve the main app
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.listen(PORT, () => {
  console.log(`Security server running on port ${PORT}`);
  console.log('Endpoints:');
  console.log(`- GET http://localhost:${PORT}/ (serves main app)`);
  console.log(`- POST http://localhost:${PORT}/checkSecurityVerification`);
  console.log(`- POST http://localhost:${PORT}/registerSecurityVerification`);
});