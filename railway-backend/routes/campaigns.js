const express = require('express');
const router = express.Router();

// Accept Prisma client as parameter
module.exports = (prisma) => {

// Get all campaigns
router.get('/', async (req, res) => {
  try {
    const campaigns = await prisma.campaign.findMany({
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({ campaigns });
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

    const campaign = await prisma.campaign.create({
      data: {
        ownerWallet,
        targetLat: new Decimal(targetLat),
        targetLng: new Decimal(targetLng),
        count: parseInt(count) || 1,
        multiplier: parseInt(multiplier) || 1,
        durationDays: parseInt(durationDays) || 1,
        expiryDate: expiryDate ? BigInt(expiryDate) : null,
        totalPrice: BigInt(totalPrice || 0),
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
        status: status || 'pending_review'
      }
    });

    res.json(campaign);
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

    const campaign = await prisma.campaign.update({
      where: { id: parseInt(id) },
      data: { status }
    });

    res.json(campaign);
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'Campaign not found' });
    }
    console.error('Error updating campaign status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a campaign
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.campaign.delete({
      where: { id: parseInt(id) }
    });

    res.json({ message: 'Campaign deleted successfully' });
  } catch (error) {
    if (error.code === 'P2025') { // Record not found error in Prisma
      return res.status(404).json({ error: 'Campaign not found' });
    }
    console.error('Error deleting campaign:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};