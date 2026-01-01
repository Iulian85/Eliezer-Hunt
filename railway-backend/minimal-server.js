// Server Express minim pentru ELZR Hunt
const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware pentru parsarea JSON
app.use(express.json());

// Conexiune la bază de date
const pool = new Pool({
  connectionString: process.env.DATABASE_PUBLIC_URL,
  ssl: "prefer"
});

// Endpoint de bază
app.get('/', (req, res) => {
  res.json({ message: 'ELZR Hunt Backend - Server funcțional', status: 'ok' });
});

// Endpoint health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (error) {
    res.status(500).json({ status: 'unhealthy', database: 'error', error: error.message });
  }
});

// Creează tabelele la pornire
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    // Creează tabela users
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE NOT NULL,
        username VARCHAR(255),
        balance BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    console.log('Tabele create sau verificate cu succes');
  } catch (error) {
    console.error('Eroare la crearea tabelelor:', error.message);
  } finally {
    client.release();
  }
}

// Pornește serverul
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server pornit pe portul ${PORT}`);
    });
  } catch (error) {
    console.error('Eroare la pornirea serverului:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;