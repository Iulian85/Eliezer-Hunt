
import { initializeApp, getApps, getApp } from "@firebase/app";
import { 
    getFirestore, doc, getDoc, setDoc, updateDoc, collection, onSnapshot, query, orderBy, limit, getDocs,
    serverTimestamp, increment, deleteDoc, arrayUnion, addDoc
} from "@firebase/firestore";
import { getFunctions, httpsCallable } from "@firebase/functions";
import FingerprintJS from '@fingerprintjs/fingerprintjs';

import { UserState, HotspotCategory } from "../types";

// Validate required environment variables
const validateFirebaseConfig = () => {
  const requiredVars = [
    'VITE_FIREBASE_API_KEY',
    'VITE_FIREBASE_AUTH_DOMAIN',
    'VITE_FIREBASE_PROJECT_ID',
    'VITE_FIREBASE_STORAGE_BUCKET',
    'VITE_FIREBASE_MESSAGING_SENDER_ID',
    'VITE_FIREBASE_APP_ID'
  ];

  const missingVars = requiredVars.filter(varName => !import.meta.env[varName]);

  if (missingVars.length > 0) {
    console.error('Missing required Firebase environment variables:', missingVars);
    // Don't throw error to avoid breaking the app, but log it
  }
};

validateFirebaseConfig();

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID
};

let app;
let dbInstance = null;
let functionsInstance = null;

try {
    app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
    dbInstance = getFirestore(app);
    functionsInstance = getFunctions(app);
} catch (error) {
    console.error("Firebase initialization error:", error);
    // Keep dbInstance and functionsInstance as null
}

export const db = dbInstance;
export const functions = functionsInstance;

const sanitizeUserData = (data: any, defaults: UserState): UserState => {
    return {
        ...defaults,
        ...data,
        balance: Number(data.balance || 0),
        tonBalance: Number(data.tonBalance || 0),
        gameplayBalance: Number(data.gameplayBalance || 0),
        rareBalance: Number(data.rareBalance || 0),
        eventBalance: Number(data.eventBalance || 0),
        dailySupplyBalance: Number(data.dailySupplyBalance || 0),
        merchantBalance: Number(data.merchantBalance || 0),
        referralBalance: Number(data.referralBalance || 0),
        collectedIds: data.collectedIds || [],
        adsgramBlockId: data.adsgramBlockId || '',
        error: data.error || undefined
    };
};

export const subscribeToUserProfile = (tgId: number, defaults: UserState, callback: (userData: UserState) => void) => {
    if (!tgId || !db) {
        // If no db, simulate an empty user
        setTimeout(() => callback(defaults), 0);
        return () => {};
    }
    const docRef = doc(db, "users", String(tgId));
    return onSnapshot(docRef, (docSnap) => {
        if (docSnap.exists()) {
            callback(sanitizeUserData(docSnap.data(), defaults));
        } else {
            callback(defaults);
        }
    });
};

export const syncUserWithFirebase = async (userData: any, localState: UserState, fingerprint: string): Promise<UserState> => {
    if (!userData.id) return localState;
    if (!db) {
        // If no db connection, return local state with a warning
        console.warn("Firebase not initialized, using local state only");
        return localState;
    }

    const userIdStr = String(userData.id);
    const userDocRef = doc(db, "users", userIdStr);

    try {
        const userDoc = await getDoc(userDocRef);
        if (userDoc.exists()) {
            await updateDoc(userDocRef, {
                deviceFingerprint: fingerprint,
                lastActive: serverTimestamp(),
                photoUrl: userData.photoUrl || ''
            });
            return sanitizeUserData(userDoc.data(), localState);
        } else {
            const newUser: any = {
                telegramId: Number(userData.id),
                username: userData.username || `Hunter_${userIdStr.slice(-4)}`,
                photoUrl: userData.photoUrl || '',
                deviceFingerprint: fingerprint,
                joinedAt: serverTimestamp(),
                lastActive: serverTimestamp(),
                balance: 0, tonBalance: 0, gameplayBalance: 0, rareBalance: 0, eventBalance: 0, dailySupplyBalance: 0, merchantBalance: 0, referralBalance: 0,
                collectedIds: [], biometricEnabled: true, adsgramBlockId: process.env.VITE_ADSGRAM_BLOCK_ID || ''
            };
            await setDoc(userDocRef, newUser, { merge: true });
            return sanitizeUserData(newUser, localState);
        }
    } catch (e) {
        console.error("Firebase sync error:", e);
        // Return local state if there's an error
        return localState;
    }
};

/**
 * SALVARE INSTANTĂ (Client-Side Master)
 * Această funcție face update DIRECT în balanța utilizatorului pentru viteză maximă.
 */
export const saveCollectionToFirebase = async (tgId: number, spawnId: string, value: number, category?: HotspotCategory, tonReward: number = 0) => {
    if (!tgId || !db) return;

    // Validare pentru valori
    if (value < 0 || value > 10000) return; // Limită maximă pentru valoare
    if (tonReward < 0 || tonReward > 100) return; // Limită maximă pentru TON

    // Validare pentru spawnId
    if (!spawnId || spawnId.length > 50 || /[^a-zA-Z0-9-_]/.test(spawnId)) return;

    const userRef = doc(db, "users", String(tgId));
    const claimRef = collection(db, "claims");

    try {
        // Citim documentul utilizatorului pentru a obține valorile actuale
        const userDoc = await getDoc(userRef);

        // Dacă utilizatorul nu există, îl creăm cu date implicite
        if (!userDoc.exists()) {
            console.warn(`User document does not exist for tgId: ${tgId}, creating default user`);
            const defaultUserData = {
                telegramId: Number(tgId),
                balance: 0,
                tonBalance: 0,
                gameplayBalance: 0,
                rareBalance: 0,
                eventBalance: 0,
                dailySupplyBalance: 0,
                merchantBalance: 0,
                referralBalance: 0,
                collectedIds: [],
                lastActive: serverTimestamp(),
                deviceFingerprint: 'unknown',
                photoUrl: '',
                walletAddress: '',
                adsgramBlockId: '',
                referrals: 0,
                adsWatched: 0,
                rareItemsCollected: 0,
                eventItemsCollected: 0,
                sponsoredAdsWatched: 0
            };
            await setDoc(userRef, defaultUserData);
        }

        const userData = userDoc.exists() ? userDoc.data() : {
            balance: 0,
            tonBalance: 0,
            gameplayBalance: 0,
            rareBalance: 0,
            eventBalance: 0,
            dailySupplyBalance: 0,
            merchantBalance: 0,
            referralBalance: 0,
            collectedIds: [],
            lastActive: serverTimestamp(),
            deviceFingerprint: 'unknown',
            photoUrl: '',
            walletAddress: '',
            adsgramBlockId: '',
            referrals: 0,
            adsWatched: 0,
            rareItemsCollected: 0,
            eventItemsCollected: 0,
            sponsoredAdsWatched: 0
        };

        // Calculăm noile valori pentru balanțe
        const newBalance = (userData.balance || 0) + value;
        const newTonBalance = (userData.tonBalance || 0) + tonReward;
        const newGameplayBalance = (userData.gameplayBalance || 0) + (category === 'GIFTBOX' || !category ? value : 0);
        const newRareBalance = (userData.rareBalance || 0) + (category === 'LANDMARK' ? value : 0);
        const newEventBalance = (userData.eventBalance || 0) + (category === 'EVENT' ? value : 0);
        const newDailySupplyBalance = (userData.dailySupplyBalance || 0) + (category === 'AD_REWARD' ? value : 0);
        const newMerchantBalance = (userData.merchantBalance || 0) + (category === 'MERCHANT' ? value : 0);
        const newReferralBalance = (userData.referralBalance || 0) + 0; // Nu se modifică la colectare

        // Calculăm noile valori pentru contoare
        const newAdsWatched = (userData.adsWatched || 0) + (category === 'AD_REWARD' ? 1 : 0);
        const newRareItemsCollected = (userData.rareItemsCollected || 0) + (category === 'LANDMARK' ? 1 : 0);
        const newEventItemsCollected = (userData.eventItemsCollected || 0) + (category === 'EVENT' ? 1 : 0);
        const newSponsoredAdsWatched = (userData.sponsoredAdsWatched || 0) + (category === 'MERCHANT' ? 1 : 0);

        const updateData: any = {
            balance: newBalance,
            tonBalance: newTonBalance,
            gameplayBalance: newGameplayBalance,
            rareBalance: newRareBalance,
            eventBalance: newEventBalance,
            dailySupplyBalance: newDailySupplyBalance,
            merchantBalance: newMerchantBalance,
            referralBalance: newReferralBalance,
            lastActive: serverTimestamp()
        };

        // Adăugăm contoarele dacă sunt necesare
        if (category === 'AD_REWARD') {
            updateData.adsWatched = newAdsWatched;
            updateData.lastDailyClaim = Date.now();
        } else if (category === 'LANDMARK') {
            updateData.rareItemsCollected = newRareItemsCollected;
        } else if (category === 'EVENT') {
            updateData.eventItemsCollected = newEventItemsCollected;
        } else if (category === 'MERCHANT') {
            updateData.sponsoredAdsWatched = newSponsoredAdsWatched;
        }

        // Salvăm ID-ul ca să nu poată fi colectat de două ori (excepție reclamele zilnice)
        if (spawnId && !spawnId.startsWith('ad-')) {
            updateData.collectedIds = arrayUnion(spawnId);
        }

        // 1. Update balanță utilizator (Apare instant în Wallet prin onSnapshot)
        await updateDoc(userRef, updateData);

        // 2. Creăm LOG în claims cu status VERIFIED direct (Să nu mai stea în pending)
        await addDoc(claimRef, {
            userId: Number(tgId),
            spawnId: String(spawnId),
            category: category || 'URBAN',
            claimedValue: Number(value),
            tonReward: Number(tonReward),
            status: 'verified',
            timestamp: serverTimestamp()
        });

    } catch (e) {
        console.error("Critical Sync Error:", e);
    }
};

export const processReferralReward = async (referrerId: string, userId: number, userName: string) => {
    // Validare pentru referrerId și userId
    if (!referrerId || !userId || userId <= 0 || !db) return;

    // Validare pentru userName
    if (!userName || userName.length > 50) return;

    try {
        const refOwnerRef = doc(db, "users", String(referrerId));
        const newUserRef = doc(db, "users", String(userId));
        await updateDoc(refOwnerRef, {
            balance: increment(50),
            referralBalance: increment(50),
            referrals: increment(1),
            referralNames: arrayUnion(userName)
        });
        await updateDoc(newUserRef, { hasClaimedReferral: true });
    } catch (e) { console.error("Referral Error:", e); }
};

export const askGeminiProxy = async (messages: any[]) => {
    if (!functions) {
        return { text: "AI service not available." };
    }
    try {
        const chatFunc = httpsCallable(functions, 'chatWithELZR');
        const res: any = await chatFunc({ messages });
        return res.data;
    } catch (e) { return { text: "AI Node offline." }; }
};

export const getLeaderboard = async () => {
    if (!db) {
        return [];
    }
    const q = query(collection(db, "users"), orderBy("balance", "desc"), limit(50));
    const snapshot = await getDocs(q);
    return snapshot.docs.map((docSnap, index) => ({
        rank: index + 1,
        username: (docSnap.data() as any).username || "Hunter",
        score: Number((docSnap.data() as any).balance || 0)
    }));
};

export const resetUserInFirebase = async (targetUserId: number) => {
    const userRef = doc(db, "users", String(targetUserId));
    await updateDoc(userRef, { 
        balance: 0, tonBalance: 0, gameplayBalance: 0, rareBalance: 0, eventBalance: 0, 
        dailySupplyBalance: 0, merchantBalance: 0, referralBalance: 0, collectedIds: [] 
    });
    return { success: true };
};

export const subscribeToCampaigns = (cb: any) => {
    if (!db) {
        setTimeout(() => cb([]), 0);
        return () => {};
    }
    return onSnapshot(collection(db, "campaigns"), snap => cb(snap.docs.map(d => ({id: d.id, ...d.data()}))));
};
export const subscribeToHotspots = (cb: any) => {
    if (!db) {
        setTimeout(() => cb([]), 0);
        return () => {};
    }
    return onSnapshot(collection(db, "hotspots"), snap => cb(snap.docs.map(d => d.data())));
};
export const subscribeToWithdrawalRequests = (cb: (reqs: any[]) => void) => {
    if (!db) {
        setTimeout(() => cb([]), 0);
        return () => {};
    }
    return onSnapshot(query(collection(db, "withdrawal_requests"), orderBy("timestamp", "desc")), snap => cb(snap.docs.map(d => ({ id: d.id, ...d.data() }))));
};
export const updateWithdrawalStatus = async (id: string, status: string) => {
    if (!db) return;
    await updateDoc(doc(db, "withdrawal_requests", id), { status, processedAt: serverTimestamp() });
};
export const saveHotspotFirebase = async (h: any) => {
    if (!db) return;
    await setDoc(doc(db, "hotspots", h.id), h);
};
export const deleteHotspotFirebase = async (id: string) => {
    if (!db) return;
    await deleteDoc(doc(db, "hotspots", id));
};
export const deleteUserFirebase = async (id: string) => {
    if (!db) return;
    await deleteDoc(doc(db, "users", id));
};
export const toggleUserBan = async (id: string, b: boolean) => {
    if (!db) return;
    await updateDoc(doc(db, "users", String(id)), { isBanned: b });
};
export const toggleUserBiometricSetting = async (id: string, b: boolean) => {
    if (!db) return;
    await updateDoc(doc(db, "users", String(id)), { biometricEnabled: b });
};
export const createCampaignFirebase = async (c: any) => {
    if (!db) return;
    await setDoc(doc(db, "campaigns", c.id), c);
};
export const updateCampaignStatusFirebase = async (id: string, s: string) => {
    if (!db) return;
    await updateDoc(doc(db, "campaigns", id), { "data.status": s });
};
export const deleteCampaignFirebase = async (id: string) => {
    if (!db) return;
    await deleteDoc(doc(db, "campaigns", id));
};
export const updateUserWalletInFirebase = async (id: number, w: string) => {
    if (!db) return;
    await updateDoc(doc(db, "users", String(id)), { walletAddress: w });
};
export const getAllUsersAdmin = async () => {
    if (!db) return [];
    const snapshot = await getDocs(collection(db, "users"));
    return snapshot.docs.map(d => ({id: d.id, ...d.data()}));
};
export const processWithdrawTON = async (tgId: number, amount: number) => {
    if (!db) return false;
    await addDoc(collection(db, "withdrawal_requests"), { userId: Number(tgId), amount: Number(amount), status: "pending", timestamp: serverTimestamp() });
    return true;
};
export const markUserAirdropped = async (id: string, allocation: number) => {
    if (!db) return false;
    await updateDoc(doc(db, "users", String(id)), { isAirdropped: true, airdropAllocation: allocation, airdropTimestamp: serverTimestamp() });
    return true;
};
