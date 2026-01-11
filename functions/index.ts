
import * as crypto from 'crypto';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { onCall, HttpsError, onRequest } from 'firebase-functions/v2/https';
import { GoogleGenAI } from '@google/genai';
import { Request, Response } from 'express';

if (getApps().length === 0) {
    initializeApp();
}

const db = getFirestore();

// Interface for security verification data
interface SecurityVerification {
  telegramUserId: string;
  verified: boolean;
  token: string;
  timestamp: number;
  expiresAt: number;
}

/**
 * Verifies Telegram WebApp initData to ensure the request is legitimate
 * @param initDataRaw Raw initData string from Telegram WebApp
 * @param botToken Your bot token
 * @returns True if the initData is valid, false otherwise
 */
function verifyTelegramInitData(initDataRaw: string, botToken: string): boolean {
  try {
    const initData = new URLSearchParams(initDataRaw);
    const hash = initData.get('hash');
    initData.delete('hash');

    // Sort parameters alphabetically
    const dataCheckArray = Array.from(initData.entries())
      .map(([key, value]) => `${key}=${value}`)
      .sort();

    const dataCheckString = dataCheckArray.join('\n');

    // Create secret key using SHA256
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(botToken)
      .digest();

    // Create hash of data check string
    const calculatedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    // Compare hashes
    return crypto.timingSafeEqual(Buffer.from(hash!), Buffer.from(calculatedHash));
  } catch (error) {
    console.error('Error verifying Telegram initData:', error);
    return false;
  }
}

/**
 * Verifies the HMAC signature of the security token
 * @param token The JWT-like token from the native app
 * @returns Decoded payload if valid, null otherwise
 */
function verifyTokenSignature(token: string): any | null {
  try {
    const [header, payload, signature] = token.split('.');

    if (!header || !payload || !signature) {
      console.error('Invalid token format');
      return null;
    }

    // Decode payload
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));

    // Recreate the payload string to verify signature
    const expectedPayloadString = Buffer.from(payload, 'base64').toString('utf8');

    // Verify HMAC signature using your secret key
    // In production, this should be stored securely (e.g., in environment variables)
    const hmacSecret = process.env.HMAC_SECRET || 'YOUR_SECRET_KEY_HERE';
    const expectedSignature = crypto
      .createHmac('sha256', hmacSecret)
      .update(expectedPayloadString)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const actualSignature = signature
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Compare signatures safely
    if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(actualSignature))) {
      console.error('Token signature verification failed');
      return null;
    }

    return decodedPayload;
  } catch (error) {
    console.error('Error verifying token signature:', error);
    return null;
  }
}

/**
 * API endpoint to check if a user has completed native security verification
 */
export const checkSecurityVerification = onRequest(
  { cors: true },
  async (req: Request, res: Response) => {
    try {
      if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
      }

      const { telegramUserId, initData } = req.body;

      // Verify Telegram initData to ensure the request is legitimate
      if (!initData) {
        return res.status(400).json({ error: 'Missing Telegram initData' });
      }

      const botToken = process.env.TELEGRAM_BOT_TOKEN;
      if (!botToken) {
        return res.status(500).json({ error: 'Server configuration error: missing bot token' });
      }

      if (!verifyTelegramInitData(initData, botToken)) {
        return res.status(403).json({ error: 'Invalid Telegram initData' });
      }

      // Extract the actual telegramUserId from the initData to prevent spoofing
      const initDataParams = new URLSearchParams(initData);
      const userParam = initDataParams.get('user');
      if (!userParam) {
        return res.status(400).json({ error: 'Invalid Telegram initData: missing user data' });
      }

      const telegramUserData = JSON.parse(decodeURIComponent(userParam));
      const actualTelegramUserId = telegramUserData.id.toString();

      // Ensure the telegramUserId in the request matches the one from Telegram
      if (actualTelegramUserId !== telegramUserId) {
        return res.status(403).json({ error: 'Telegram user ID mismatch' });
      }

      // Query Firestore for security verification record
      const verificationDoc = await db
        .collection('security-verifications')
        .doc(actualTelegramUserId)
        .get();

      if (!verificationDoc.exists) {
        return res.status(200).json({ verified: false });
      }

      const verificationData = verificationDoc.data() as SecurityVerification;

      // Check if verification has expired (24 hours)
      const now = Date.now();
      if (verificationData.expiresAt < now) {
        // Delete expired verification
        await db.collection('security-verifications').doc(actualTelegramUserId).delete();
        return res.status(200).json({ verified: false });
      }

      // Return verification status
      res.status(200).json({
        verified: verificationData.verified,
        timestamp: verificationData.timestamp
      });
    } catch (error) {
      console.error('Error checking security verification:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * API endpoint to register a security verification from native app
 */
export const registerSecurityVerification = onRequest(
  { cors: true },
  async (req: Request, res: Response) => {
    try {
      if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
      }

      const { telegramUserId, token, platform, initData } = req.body;

      if (!telegramUserId || !token || !platform || !initData) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      // Verify Telegram initData to ensure the request is legitimate
      const botToken = process.env.TELEGRAM_BOT_TOKEN;
      if (!botToken) {
        return res.status(500).json({ error: 'Server configuration error: missing bot token' });
      }

      if (!verifyTelegramInitData(initData, botToken)) {
        return res.status(403).json({ error: 'Invalid Telegram initData' });
      }

      // Extract the actual telegramUserId from the initData to prevent spoofing
      const initDataParams = new URLSearchParams(initData);
      const userParam = initDataParams.get('user');
      if (!userParam) {
        return res.status(400).json({ error: 'Invalid Telegram initData: missing user data' });
      }

      const telegramUserData = JSON.parse(decodeURIComponent(userParam));
      const actualTelegramUserId = telegramUserData.id.toString();

      // Ensure the telegramUserId in the request matches the one from Telegram
      if (actualTelegramUserId !== telegramUserId) {
        return res.status(403).json({ error: 'Telegram user ID mismatch' });
      }

      // Verify the token signature
      const decodedToken = verifyTokenSignature(token);
      if (!decodedToken) {
        return res.status(403).json({ error: 'Invalid token signature' });
      }

      // Verify that the token contains the correct telegramUserId
      if (decodedToken.telegramUserId !== actualTelegramUserId) {
        return res.status(403).json({ error: 'Token telegramUserId mismatch' });
      }

      // Verify that the token is not expired (max 24h)
      const now = Date.now();
      const tokenTimestamp = decodedToken.timestamp;
      if (now - tokenTimestamp > 24 * 60 * 60 * 1000) { // 24 hours
        return res.status(403).json({ error: 'Token expired' });
      }

      // Verify that the platform matches
      if (decodedToken.platform !== platform) {
        return res.status(403).json({ error: 'Platform mismatch' });
      }

      // Create/update security verification record
      const verificationData: SecurityVerification = {
        telegramUserId: actualTelegramUserId,
        verified: decodedToken.verified,
        token,
        timestamp: Date.now(),
        expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours from now
      };

      await db
        .collection('security-verifications')
        .doc(actualTelegramUserId)
        .set(verificationData);

      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Error registering security verification:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Eliminat onClaimCreated pentru că acum clientul face update-ul direct pentru viteză.

export const chatWithELZR = onCall(async (request: any) => {
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

export const secureClaim = onCall(async (request: any) => {
    // Păstrăm funcția goală pentru compatibilitate, dar nu o mai folosim în mod critic
    return { success: true };
});
