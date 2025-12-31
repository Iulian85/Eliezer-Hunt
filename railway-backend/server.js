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
  ssl: {
    rejectUnauthorized: false
  },
});

// Function to run migrations
async function runMigrations() {
  let client;
  try {
    client = new Client({
      connectionString: process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false
      },
    });

    await client.connect();
    console.log('Connected to database for migrations');

    // Check if migration table exists
    const migrationTableExists = await client.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'migrations'
      );
    `);

    if (!migrationTableExists.rows[0].exists) {
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
    const schemaMigrationExists = await client.query(
      'SELECT name FROM migrations WHERE name = $1',
      ['01_schema.sql']
    );

    if (schemaMigrationExists.rows.length === 0) {
      // Read and execute schema migration
      const fs = require('fs');
      const path = require('path');

      const schemaPath = path.join(__dirname, '..', 'migrations', '01_schema.sql');
      const schemaSQL = fs.readFileSync(schemaPath, 'utf8');

      await client.query(schemaSQL);

      // Record that this migration was executed
      await client.query(
        'INSERT INTO migrations (name) VALUES ($1)',
        ['01_schema.sql']
      );

      console.log('Executed schema migration successfully');
    } else {
      console.log('Schema migration already executed');
    }

    await client.end();
    console.log('Migration check completed');
  } catch (error) {
    console.error('Error running migrations:', error);
    if (client) {
      await client.end();
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
