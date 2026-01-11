const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

// Use the port provided by Railway or default to 3000
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files with proper headers for ES modules
app.use('/dist', express.static('dist', {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript');
    } else if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    } else if (filePath.endsWith('.json')) {
      res.setHeader('Content-Type', 'application/json');
    } else if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
  }
}));

app.use(express.static('.', {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript');
    } else if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    } else if (filePath.endsWith('.json')) {
      res.setHeader('Content-Type', 'application/json');
    } else if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
  }
}));

// API routes for security verification
const securityVerifications = {};

// Specific route for the main JavaScript bundle
app.get('/dist/main.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist/main.js'), { headers: { 'Content-Type': 'application/javascript' } });
});

// Specific route for index.css
app.get('/index.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'src/index.css'), { headers: { 'Content-Type': 'text/css' } });
});

// Specific route for any file in dist directory
app.get('/dist/:filename', (req, res) => {
  const filename = req.params.filename;
  res.sendFile(path.join(__dirname, 'dist', filename), {
    headers: {
      'Content-Type': filename.endsWith('.js') ? 'application/javascript' :
                     filename.endsWith('.css') ? 'text/css' :
                     filename.endsWith('.json') ? 'application/json' : 'application/octet-stream'
    }
  });
});

// Health check endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Endpoint to check security verification
app.post('/checkSecurityVerification', async (req, res) => {
  try {
    const { telegramUserId } = req.body;
    
    // Check if user is verified
    const verification = securityVerifications[telegramUserId];
    
    if (verification && verification.expiresAt > Date.now()) {
      res.json({ verified: true, timestamp: verification.timestamp });
    } else {
      // Remove expired verification
      if (verification) {
        delete securityVerifications[telegramUserId];
      }
      res.json({ verified: false });
    }
  } catch (error) {
    console.error('Error checking security verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to register security verification
app.post('/registerSecurityVerification', async (req, res) => {
  try {
    const { telegramUserId, token, platform } = req.body;
    
    // Store verification (valid for 24 hours)
    securityVerifications[telegramUserId] = {
      token,
      platform,
      timestamp: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    };
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error registering security verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Handle client-side routing - serve index.html for all non-API and non-file routes
// NOTE: This must be placed AFTER all specific routes
app.get('*', (req, res) => {
  // Don't interfere with API routes
  if (req.path.startsWith('/checkSecurityVerification') || req.path.startsWith('/registerSecurityVerification')) {
    res.status(404).json({ error: 'API route not found' });
  } else {
    // Check if the request is for a file (has an extension like .js, .css, .json, etc.)
    const pathExt = path.extname(req.path);
    if (pathExt && pathExt !== '.html') {
      // This is a file request, let static middleware handle it
      // This shouldn't reach here if static middleware worked, but just in case
      res.status(404).send('File not found');
    } else {
      // This is a client-side route or HTML request, serve the main app
      res.sendFile(path.join(__dirname, 'index.html'), { headers: { 'Content-Type': 'text/html' } });
    }
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Endpoints:');
  console.log(`- GET http://localhost:${PORT}/ (serves app)`);
  console.log(`- POST http://localhost:${PORT}/checkSecurityVerification`);
  console.log(`- POST http://localhost:${PORT}/registerSecurityVerification`);
});