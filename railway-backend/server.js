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
    console.log('Current working directory:', process.cwd());
    console.log('Server file location:', __dirname);
    console.log('DATABASE_PUBLIC_URL exists:', !!process.env.DATABASE_PUBLIC_URL);
    console.log('DATABASE_PUBLIC_URL value:', process.env.DATABASE_PUBLIC_URL ? 'SET' : 'NOT SET');

    // Check if database URL is provided
    const connectionString = process.env.DATABASE_PUBLIC_URL;
    if (!connectionString) {
      throw new Error('No database connection string provided. Please set DATABASE_PUBLIC_URL environment variable.');
    }

    console.log('Using connection string (first 50 chars):', connectionString.substring(0, 50) + '...');

    client = new Client({
      connectionString: connectionString,
      ssl: {
        rejectUnauthorized: false
      },
    });

    console.log('Attempting to connect to database...');
    await client.connect();
    console.log('Connected to database for migrations');

    // Test the connection by running a simple query
    const result = await client.query('SELECT version();');
    console.log('Database version info:', result.rows[0].version);

    // Check if migration table exists
    console.log('Checking if migrations table exists...');
    const migrationTableExists = await client.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'migrations'
      );
    `);

    console.log('Migration table exists:', migrationTableExists.rows[0].exists);
    if (!migrationTableExists.rows[0].exists) {
      console.log('Creating migrations table...');
      // Create migrations table
      await client.query(`
        CREATE TABLE migrations (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) UNIQUE NOT NULL,
          executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Created migrations table');
    }

    // Check if schema migration has already been run
    console.log('Checking if schema migration has already been run...');
    const schemaMigrationExists = await client.query(
      'SELECT name FROM migrations WHERE name = $1',
      ['01_schema.sql']
    );

    console.log('Schema migration exists in migrations table:', schemaMigrationExists.rows.length > 0);
    if (schemaMigrationExists.rows.length === 0) {
      console.log('Schema migration not found, executing...');
      // Read and execute schema migration
      const fs = require('fs');
      const path = require('path');

      // Try the path from the railway-backend directory (one level up from routes)
      const schemaPath = path.join(__dirname, '..', 'migrations', '01_schema.sql');
      console.log('Reading schema file from:', schemaPath);

      // Check if file exists before trying to read it
      let finalSchemaPath = schemaPath; // Use a separate variable to avoid scope issues
      if (!fs.existsSync(schemaPath)) {
        // Try alternative path - from the root directory where server.js is located
        const altSchemaPath = path.join(__dirname, '../../migrations', '01_schema.sql');
        console.log('Schema file not found at primary path, trying alternative:', altSchemaPath);

        if (fs.existsSync(altSchemaPath)) {
          finalSchemaPath = altSchemaPath;
          console.log('Using alternative path for schema file');
        } else {
          // Try the path from the root directory directly
          const rootSchemaPath = path.join(__dirname, '../migrations', '01_schema.sql');
          console.log('Trying root directory path:', rootSchemaPath);

          if (fs.existsSync(rootSchemaPath)) {
            finalSchemaPath = rootSchemaPath;
            console.log('Using root directory path for schema file');
          } else {
            throw new Error(`Migration file does not exist at path: ${schemaPath}, alternative: ${altSchemaPath}, or root: ${rootSchemaPath}`);
          }
        }
      }

      const schemaSQL = fs.readFileSync(finalSchemaPath, 'utf8');
      console.log('Schema file read, length:', schemaSQL.length);

      console.log('Executing schema migration...');
      await client.query(schemaSQL);
      console.log('Schema migration executed successfully');

      // Record that this migration was executed
      await client.query(
        'INSERT INTO migrations (name) VALUES ($1)',
        ['01_schema.sql']
      );

      console.log('Recorded schema migration execution');
    } else {
      console.log('Schema migration already executed, skipping');
    }

    await client.end();
    console.log('Migration check completed');
  } catch (error) {
    console.error('Error running migrations:', error);
    console.error('Error stack:', error.stack);
    if (client) {
      try {
        await client.end();
      } catch (endError) {
        console.error('Error closing client:', endError);
      }
    }
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
    const PORT = process.env.PORT || 4173;
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
