"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAdminWallet = exports.secureClaim = exports.chatWithELZR = void 0;
const functions = __importStar(require("firebase-functions"));
const app_1 = require("firebase-admin/app");
const firestore_1 = require("firebase-admin/firestore");
const genai_1 = require("@google/genai");
if ((0, app_1.getApps)().length === 0) {
    (0, app_1.initializeApp)();
}
const db = (0, firestore_1.getFirestore)();
const authenticateUser = async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'The function must be called while authenticated.');
    }
    return request.auth.uid;
};
const checkRateLimit = async (userId, action, limit, windowMs) => {
    const userRef = db.collection('rateLimits').doc(userId);
    const actionRef = userRef.collection('actions').doc(action);
    const now = Date.now();
    const windowStart = now - windowMs;
    const snapshot = await actionRef.get();
    const data = snapshot.data();
    if (!data) {
        await actionRef.set({
            count: 1,
            windowStart: now
        });
        return true;
    }
    if (data.windowStart < windowStart) {
        await actionRef.set({
            count: 1,
            windowStart: now
        });
        return true;
    }
    if (data.count >= limit) {
        return false;
    }
    await actionRef.set({
        count: data.count + 1,
        windowStart: data.windowStart
    });
    return true;
};
exports.chatWithELZR = functions.https.onCall(async (request) => {
    const userId = await authenticateUser(request);
    const rateLimitOk = await checkRateLimit(userId, 'chatWithELZR', 10, 60000);
    if (!rateLimitOk) {
        throw new functions.https.HttpsError('resource-exhausted', 'Rate limit exceeded. Please try again later.');
    }
    const { messages } = request.data || {};
    if (!process.env.API_KEY)
        return { text: "Terminal offline." };
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists || !userDoc.data()?.aiAccess) {
        throw new functions.https.HttpsError('permission-denied', 'User does not have permission to use AI features.');
    }
    const ai = new genai_1.GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: messages?.slice(-5).map((m) => ({ role: m.role, parts: [{ text: m.text }] })) || [],
        config: { systemInstruction: "Be a brief crypto scout.", thinkingConfig: { thinkingBudget: 0 } }
    });
    return { text: response.text };
});
exports.secureClaim = functions.https.onCall(async (request) => {
    await authenticateUser(request);
    return { success: true };
});
exports.getAdminWallet = functions.https.onCall(async (request) => {
    await authenticateUser(request);
    const adminWalletAddress = process.env.ADMIN_WALLET_ADDRESS;
    if (!adminWalletAddress) {
        throw new functions.https.HttpsError('internal', 'Admin wallet address not configured.');
    }
    return { adminWalletAddress };
});
//# sourceMappingURL=index.js.map