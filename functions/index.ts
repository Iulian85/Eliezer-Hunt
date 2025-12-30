import * as functions from 'firebase-functions';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import { GoogleGenAI } from '@google/genai';

if (getApps().length === 0) {
    initializeApp();
}

const db = getFirestore();

// Funcție pentru verificarea autentificării utilizatorului
const authenticateUser = async (request: functions.https.CallableRequest): Promise<string> => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'The function must be called while authenticated.');
    }
    return request.auth.uid;
};

// Funcție pentru verificarea rate limiting-ului
const checkRateLimit = async (userId: string, action: string, limit: number, windowMs: number): Promise<boolean> => {
    const userRef = db.collection('rateLimits').doc(userId);
    const actionRef = userRef.collection('actions').doc(action);

    const now = Date.now();
    const windowStart = now - windowMs;

    const snapshot = await actionRef.get();
    const data = snapshot.data();

    if (!data) {
        // Prima utilizare a acțiunii în această fereastră de timp
        await actionRef.set({
            count: 1,
            windowStart: now
        });
        return true;
    }

    if (data.windowStart < windowStart) {
        // Noua fereastră de timp, resetează contorul
        await actionRef.set({
            count: 1,
            windowStart: now
        });
        return true;
    }

    if (data.count >= limit) {
        // Limita a fost atinsă
        return false;
    }

    // Incrementează contorul
    await actionRef.set({
        count: data.count + 1,
        windowStart: data.windowStart
    });

    return true;
};

// Eliminat onClaimCreated pentru că acum clientul face update-ul direct pentru viteză.

export const chatWithELZR = functions.https.onCall(async (request: functions.https.CallableRequest): Promise<{ text: string }> => {
    // Autentificare utilizator
    const userId = await authenticateUser(request);

    // Verificare rate limiting (maxim 10 apeluri pe minut)
    const rateLimitOk = await checkRateLimit(userId, 'chatWithELZR', 10, 60000);
    if (!rateLimitOk) {
        throw new functions.https.HttpsError('resource-exhausted', 'Rate limit exceeded. Please try again later.');
    }

    const { messages } = request.data || {};
    if (!process.env.API_KEY) return { text: "Terminal offline." };

    // Verificare dacă utilizatorul are permisiunea de a folosi AI
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists || !userDoc.data()?.aiAccess) {
        throw new functions.https.HttpsError('permission-denied', 'User does not have permission to use AI features.');
    }

    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: messages?.slice(-5).map((m: { role: string; text: string }) => ({ role: m.role, parts: [{ text: m.text }] })) || [],
        config: { systemInstruction: "Be a brief crypto scout.", thinkingConfig: { thinkingBudget: 0 } }
    });
    return { text: response.text };
});

export const secureClaim = functions.https.onCall(async (request: functions.https.CallableRequest): Promise<{ success: boolean }> => {
    // Autentificare utilizator
    await authenticateUser(request);

    // Păstrăm funcția goală pentru compatibilitate, dar nu o mai folosim în mod critic
    return { success: true };
});

// Funcție pentru a obține adresa de admin în mod sigur
export const getAdminWallet = functions.https.onCall(async (request: functions.https.CallableRequest): Promise<{ adminWalletAddress: string | undefined }> => {
    // Autentificare utilizator (poate fi utilă pentru logging sau permisiuni viitoare)
    await authenticateUser(request);

    // Returnăm adresa de admin - aceasta ar trebui setată ca variabilă de mediu
    const adminWalletAddress = process.env.ADMIN_WALLET_ADDRESS;

    if (!adminWalletAddress) {
        throw new functions.https.HttpsError('internal', 'Admin wallet address not configured.');
    }

    return { adminWalletAddress };
});