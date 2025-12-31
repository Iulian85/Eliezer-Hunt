const express = require('express');
const { Client } = require('pg');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = new Client({
  connectionString: process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false, // Only use SSL for non-local connections
});

// Function to run migrations
async function runMigrations() {
  let client;
  try {
    console.log('Starting migration process...');
    console.log('Current working directory:', process.cwd());
    console.log('Server file location:', __dirname);
    console.log('DATABASE_PUBLIC_URL exists:', !!process.env.DATABASE_PUBLIC_URL);
    console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);

    client = new Client({
      connectionString: process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false
      },
    });

    console.log('Attempting to connect to database...');
    await client.connect();
    console.log('Connected to database for migrations');

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

      const schemaPath = path.join(__dirname, '..', 'migrations', '01_schema.sql');
      console.log('Reading schema file from:', schemaPath);

      // Check if file exists before trying to read it
      if (!fs.existsSync(schemaPath)) {
        throw new Error(`Migration file does not exist at path: ${schemaPath}`);
      }

      const schemaSQL = fs.readFileSync(schemaPath, 'utf8');
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

    // Basic route
    app.get('/', (req, res) => {
      res.json({ message: 'ELZR Hunt Railway Backend API' });
    });

    // Error handling middleware
    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).json({ error: 'Something went wrong!' });
    });

    // Start server
    const PORT = process.env.PORT || 8080;
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
