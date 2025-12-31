const express = require('express');
const { Client } = require('pg');
const router = express.Router();

// Database connection
const db = new Client({
  connectionString: process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Connect to database
db.connect();

// Get all hotspots
router.get('/', async (req, res) => {
  try {
    const query = 'SELECT * FROM hotspots ORDER BY created_at DESC';
    const result = await db.query(query);
    
    res.json({ hotspots: result.rows });
  } catch (error) {
    console.error('Error fetching hotspots:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new hotspot
router.post('/', async (req, res) => {
  try {
    const {
      id,
      name,
      lat,
      lng,
      radius,
      density,
      category,
      baseValue,
      logoUrl,
      customText,
      prizes,
      videoUrl
    } = req.body;

    const query = `
      INSERT INTO hotspots (
        id, name, lat, lng, radius, density, category, base_value, logo_url, custom_text, prizes, video_url
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `;

    const result = await db.query(query, [
      id, name, lat, lng, radius, density, category, baseValue, logoUrl, customText, prizes, videoUrl
    ]);

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating hotspot:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update a hotspot
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Build dynamic query based on provided fields
    const fields = Object.keys(updates);
    if (fields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const setClause = fields.map((field, index) => `"${field}" = $${index + 1}`).join(', ');
    const values = fields.map(field => updates[field]);
    values.push(id); // Add ID for WHERE clause

    const query = `UPDATE hotspots SET ${setClause} WHERE id = $${fields.length + 1} RETURNING *;`;
    const result = await db.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Hotspot not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating hotspot:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a hotspot
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const query = 'DELETE FROM hotspots WHERE id = $1 RETURNING *';
    const result = await db.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Hotspot not found' });
    }

    res.json({ message: 'Hotspot deleted successfully' });
  } catch (error) {
    console.error('Error deleting hotspot:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;