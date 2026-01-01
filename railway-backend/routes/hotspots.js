const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Get all hotspots
router.get('/', async (req, res) => {
  try {
    const hotspots = await prisma.hotspot.findMany({
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({ hotspots });
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

    const hotspot = await prisma.hotspot.create({
      data: {
        id,
        name,
        lat: new Decimal(lat),
        lng: new Decimal(lng),
        radius: parseInt(radius) || 100,
        density: parseInt(density) || 10,
        category,
        baseValue: BigInt(baseValue || 100),
        logoUrl,
        customText,
        prizes,
        videoUrl
      }
    });

    res.json(hotspot);
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

    // Remove id from updates to avoid updating the primary key
    const { id: updateId, ...updateData } = updates;

    const hotspot = await prisma.hotspot.update({
      where: { id },
      data: updateData
    });

    res.json(hotspot);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'Hotspot not found' });
    }
    console.error('Error updating hotspot:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a hotspot
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.hotspot.delete({
      where: { id }
    });

    res.json({ message: 'Hotspot deleted successfully' });
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'Hotspot not found' });
    }
    console.error('Error deleting hotspot:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};