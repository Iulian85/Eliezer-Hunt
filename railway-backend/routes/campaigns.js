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

// Get all campaigns
router.get('/', async (req, res) => {
  try {
    const query = 'SELECT * FROM campaigns ORDER BY created_at DESC';
    const result = await db.query(query);
    
    res.json({ campaigns: result.rows });
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new campaign
router.post('/', async (req, res) => {
  try {
    const {
      ownerWallet,
      targetLat,
      targetLng,
      count,
      multiplier,
      durationDays,
      expiryDate,
      totalPrice,
      brandName,
      logoUrl,
      videoUrl,
      videoFileName,
      contactStreet,
      contactCity,
      contactZip,
      contactCountry,
      contactPhone,
      contactEmail,
      contactWebsite,
      status
    } = req.body;

    const query = `
      INSERT INTO campaigns (
        owner_wallet, target_lat, target_lng, count, multiplier, duration_days,
        expiry_date, total_price, brand_name, logo_url, video_url, video_file_name,
        contact_street, contact_city, contact_zip, contact_country, contact_phone,
        contact_email, contact_website, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
      RETURNING *;
    `;

    const result = await db.query(query, [
      ownerWallet, targetLat, targetLng, count, multiplier, durationDays,
      expiryDate, totalPrice, brandName, logoUrl, videoUrl, videoFileName,
      contactStreet, contactCity, contactZip, contactCountry, contactPhone,
      contactEmail, contactWebsite, status
    ]);

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update campaign status
router.put('/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const query = `
      UPDATE campaigns SET status = $1
      WHERE id = $2
      RETURNING *;
    `;

    const result = await db.query(query, [status, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating campaign status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a campaign
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const query = 'DELETE FROM campaigns WHERE id = $1 RETURNING *';
    const result = await db.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    res.json({ message: 'Campaign deleted successfully' });
  } catch (error) {
    console.error('Error deleting campaign:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;