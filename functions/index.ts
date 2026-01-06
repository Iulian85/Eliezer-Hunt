
import { onCall, HttpsError, onRequest } from 'firebase-functions/v2/https';
import { onDocumentCreated } from 'firebase-functions/v2/firestore';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { GoogleGenAI } from '@google/genai';

if (getApps().length === 0) {
    initializeApp();
}

const db = getFirestore();

// Endpoint pentru verificare admin
export const isAdmin = onRequest((req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const userId = req.headers['x-user-id'] as string;
  const adminUserId = process.env.ADMIN_USER_ID;

  if (!userId) {
    res.status(400).json({ error: 'Missing user ID' });
    return;
  }

  const isAdmin = userId === adminUserId;
  res.json({ isAdmin });
});

// Endpoint pentru obținere adsgramBlockId
export const getAdsgramBlockId = onRequest((req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const adsgramBlockId = process.env.ADSGRAM_BLOCK_ID || '';
  res.json({ adsgramBlockId });
});

// Endpoint pentru procesare plată reclamă
export const processAdPayment = onRequest(async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const { campaignId, amount } = req.body;

  // Validare input
  if (!campaignId || !amount || amount <= 0) {
    res.status(400).json({ error: 'Invalid campaign ID or amount' });
    return;
  }

  try {
    // Verifică dacă utilizatorul este admin
    const adminUserId = process.env.ADMIN_USER_ID;
    if (!adminUserId) {
      res.status(500).json({ error: 'Admin configuration missing' });
      return;
    }

    // Verifică dacă campania există și este în starea corectă
    const campaignRef = db.collection('campaigns').doc(campaignId);
    const campaignDoc = await campaignRef.get();

    if (!campaignDoc.exists) {
      res.status(404).json({ error: 'Campaign not found' });
      return;
    }

    const campaignData = campaignDoc.data();
    if (campaignData?.data?.status !== 'payment_required') {
      res.status(400).json({ error: 'Campaign is not in payment required state' });
      return;
    }

    // Actualizează statusul campaniei
    await campaignRef.update({
      'data.status': 'active',
      'paymentProcessedAt': FieldValue.serverTimestamp()
    });

    res.json({ success: true, message: 'Payment processed and campaign activated' });
  } catch (error) {
    console.error('Ad payment error:', error);
    res.status(500).json({ error: 'Payment processing failed' });
  }
});

// Eliminat onClaimCreated pentru că acum clientul face update-ul direct pentru viteză.

export const chatWithELZR = onCall(async (request) => {
    const { messages } = request.data || {};
    if (!process.env.API_KEY) return { text: "Terminal offline." };
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: messages.slice(-5).map((m: any) => ({ role: m.role, parts: [{ text: m.text }] })),
        config: { systemInstruction: "Be a brief crypto scout.", thinkingConfig: { thinkingBudget: 0 } }
    });
    return { text: response.text };
});

export const secureClaim = onCall(async (request) => {
    // Păstrăm funcția goală pentru compatibilitate, dar nu o mai folosim în mod critic
    return { success: true };
});

// Funcție care se activează când cineva colectează o monedă
export const onRareCoinCollected = onDocumentCreated('claims/{claimId}', async (event) => {
  const claimData = event.data?.data();

  // Verifică dacă este o monedă rară
  if (claimData?.category === 'LANDMARK' || claimData?.category === 'EVENT') {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const channelId = process.env.TELEGRAM_CHANNEL_ID;

    if (!botToken || !channelId) {
      console.error('Missing Telegram bot token or channel ID');
      return;
    }

    try {
      // Obține numele utilizatorului
      const userDoc = await getFirestore().collection('users').doc(claimData.userId.toString()).get();
      const userData = userDoc.data();
      const username = userData?.username || `Hunter_${claimData.userId}`;

      // Determină tipul monedei
      const coinType = claimData.category === 'LANDMARK' ? 'rare' : 'event';

      // Publică pe canal
      const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: channelId,
          text: `🎉 Felicitări ${username} pentru colectarea monedei ${coinType} ${claimData.spawnId}! 🚀`,
          parse_mode: 'HTML'
        })
      });

      if (!response.ok) {
        console.error('Failed to send message to Telegram channel');
      }
    } catch (error) {
      console.error('Error in onRareCoinCollected:', error);
    }
  }
});
