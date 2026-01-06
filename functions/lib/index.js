"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.onRareCoinCollected = exports.secureClaim = exports.chatWithELZR = exports.processAdPayment = exports.getAdsgramBlockId = exports.isAdmin = void 0;
const https_1 = require("firebase-functions/v2/https");
const firestore_1 = require("firebase-functions/v2/firestore");
const app_1 = require("firebase-admin/app");
const firestore_2 = require("firebase-admin/firestore");
const genai_1 = require("@google/genai");
if ((0, app_1.getApps)().length === 0) {
    (0, app_1.initializeApp)();
}
const db = (0, firestore_2.getFirestore)();
exports.isAdmin = (0, https_1.onRequest)((req, res) => {
    if (req.method !== 'GET') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }
    const userId = req.headers['x-user-id'];
    const adminUserId = process.env.ADMIN_USER_ID;
    if (!userId) {
        res.status(400).json({ error: 'Missing user ID' });
        return;
    }
    const isAdmin = userId === adminUserId;
    res.json({ isAdmin });
});
exports.getAdsgramBlockId = (0, https_1.onRequest)((req, res) => {
    if (req.method !== 'GET') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }
    const adsgramBlockId = process.env.ADSGRAM_BLOCK_ID || '';
    res.json({ adsgramBlockId });
});
exports.processAdPayment = (0, https_1.onRequest)(async (req, res) => {
    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }
    const { campaignId, amount } = req.body;
    if (!campaignId || !amount || amount <= 0) {
        res.status(400).json({ error: 'Invalid campaign ID or amount' });
        return;
    }
    try {
        const adminUserId = process.env.ADMIN_USER_ID;
        if (!adminUserId) {
            res.status(500).json({ error: 'Admin configuration missing' });
            return;
        }
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
        await campaignRef.update({
            'data.status': 'active',
            'paymentProcessedAt': firestore_2.FieldValue.serverTimestamp()
        });
        res.json({ success: true, message: 'Payment processed and campaign activated' });
    }
    catch (error) {
        console.error('Ad payment error:', error);
        res.status(500).json({ error: 'Payment processing failed' });
    }
});
exports.chatWithELZR = (0, https_1.onCall)(async (request) => {
    const { messages } = request.data || {};
    if (!process.env.API_KEY)
        return { text: "Terminal offline." };
    const ai = new genai_1.GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: messages.slice(-5).map((m) => ({ role: m.role, parts: [{ text: m.text }] })),
        config: { systemInstruction: "Be a brief crypto scout.", thinkingConfig: { thinkingBudget: 0 } }
    });
    return { text: response.text };
});
exports.secureClaim = (0, https_1.onCall)(async (request) => {
    return { success: true };
});
exports.onRareCoinCollected = (0, firestore_1.onDocumentCreated)('claims/{claimId}', async (event) => {
    const claimData = event.data?.data();
    if (claimData?.category === 'LANDMARK' || claimData?.category === 'EVENT') {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const channelId = process.env.TELEGRAM_CHANNEL_ID;
        if (!botToken || !channelId) {
            console.error('Missing Telegram bot token or channel ID');
            return;
        }
        try {
            const userDoc = await (0, firestore_2.getFirestore)().collection('users').doc(claimData.userId.toString()).get();
            const userData = userDoc.data();
            const username = userData?.username || `Hunter_${claimData.userId}`;
            const coinType = claimData.category === 'LANDMARK' ? 'rare' : 'event';
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
        }
        catch (error) {
            console.error('Error in onRareCoinCollected:', error);
        }
    }
});
//# sourceMappingURL=index.js.map