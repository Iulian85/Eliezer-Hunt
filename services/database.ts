import { UserState, HotspotCategory } from "../types";

// This will be the new PostgreSQL service to replace Firebase functions
// We'll implement functions that interact with the Express.js PostgreSQL backend

// Base API URL for our Express.js backend
const API_BASE = import.meta.env.VITE_RAILWAY_BACKEND_URL || "http://localhost:5174";

// Helper function to make API requests
const apiRequest = async (endpoint: string, options: RequestInit = {}) => {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  return response.json();
};

// Sanitize user data to match UserState interface
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
    collectedIds: Array.isArray(data.collectedIds) ? data.collectedIds : [],
  };
};

// Subscribe to user profile (this would typically use WebSocket or polling in a real implementation)
export const subscribeToUserProfile = (tgId: number, defaults: UserState, callback: (userData: UserState) => void) => {
  if (!tgId) return () => {};
  
  // In a real implementation, this would use WebSocket or long polling
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(async () => {
    try {
      const userData = await getUserById(tgId);
      if (isActive) {
        callback(sanitizeUserData(userData, defaults));
      }
    } catch (error) {
      console.error("Error polling user data:", error);
    }
  }, 5000); // Poll every 5 seconds

  // Return unsubscribe function
  return () => {
    isActive = false;
    clearInterval(pollInterval);
  };
};

// Get user by Telegram ID
export const getUserById = async (tgId: number): Promise<UserState> => {
  try {
    const response = await apiRequest(`/api/get-user?telegramId=${tgId}`);
    return response.user;
  } catch (error) {
    console.error("Error getting user by ID:", error);
    // Return default user state if user doesn't exist
    return {
      telegramId: tgId,
      username: `Hunter_${tgId.toString().slice(-4)}`,
      photoUrl: "",
      deviceFingerprint: "",
      joinedAt: Date.now(),
      lastActive: Date.now(),
      balance: 0,
      tonBalance: 0,
      gameplayBalance: 0,
      rareBalance: 0,
      eventBalance: 0,
      dailySupplyBalance: 0,
      merchantBalance: 0,
      referralBalance: 0,
      collectedIds: [],
      biometricEnabled: true,
      isBanned: false,
      walletAddress: "",
      referrals: 0,
      referralNames: [],
      hasClaimedReferral: false,
      lastAdWatch: 0,
      lastDailyClaim: 0,
      adsWatched: 0,
      sponsoredAdsWatched: 0,
      rareItemsCollected: 0,
      eventItemsCollected: 0,
      lastInitData: null,
      location: null,
      screenshotLock: false,
      isAirdropped: false,
      airdropAllocation: 0,
      airdropTimestamp: null,
    };
  }
};

// Sync user with database
export const syncUserWithDatabase = async (userData: any, localState: UserState, fingerprint: string): Promise<UserState> => {
  if (!userData.id) return localState;

  try {
    // Sync user with new endpoint that handles Telegram auth and fingerprint
    // We need to format the data as if it came from Telegram WebApp
    const telegramInitData = `id=${userData.id}&first_name=${encodeURIComponent(userData.first_name || '')}&last_name=${encodeURIComponent(userData.last_name || '')}&username=${encodeURIComponent(userData.username || '')}&photo_url=${encodeURIComponent(userData.photo_url || '')}`;

    const response = await apiRequest("/api/sync-user", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: telegramInitData, // Pass the formatted Telegram data
        fingerprint: fingerprint,
      }),
    });

    return sanitizeUserData(response.user, localState);
  } catch (error) {
    console.error("Error syncing user with database:", error);
    return localState;
  }
};

// Save collection to database
export const saveCollectionToDatabase = async (tgId: number, spawnId: string, value: number, category?: HotspotCategory, tonReward: number = 0, location?: any) => {
  if (!tgId) return;

  try {
    // Use the new collect endpoint that handles all the logic
    const telegramInitData = `id=${tgId}`;

    await apiRequest("/api/collect", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: telegramInitData, // Pass minimal Telegram data
        spawnId: spawnId,
        value: value,
        category: category || "URBAN",
        tonReward: tonReward,
        location: location
      }),
    });
  } catch (error) {
    console.error("Critical Sync Error:", error);
  }
};

// Process referral reward
export const processReferralReward = async (referrerId: string, userId: number, userName: string) => {
  try {
    // For now, we'll keep the existing logic since referral endpoints weren't specified in the prompt
    // In a real implementation, you'd need to add referral-specific endpoints to the Bun.js server
    console.warn("Referral functionality needs to be implemented in the Bun.js server");
  } catch (error) {
    console.error("Referral Error:", error);
  }
};

// Get leaderboard
export const getLeaderboard = async () => {
  try {
    const response = await apiRequest("/api/get-leaderboard");
    return response.leaderboard;
  } catch (error) {
    console.error("Error getting leaderboard:", error);
    return [];
  }
};

// Reset user
export const resetUserInDatabase = async (targetUserId: number) => {
  try {
    // For now, we'll keep the existing logic since reset endpoint wasn't specified in the prompt
    // In a real implementation, you'd need to add a reset-specific endpoint to the Bun.js server
    console.warn("Reset user functionality needs to be implemented in the Bun.js server");
    return { success: false };
  } catch (error) {
    console.error("Error resetting user:", error);
    return { success: false };
  }
};

// Campaign functions
export const subscribeToCampaigns = (cb: any) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(async () => {
    if (isActive) {
      try {
        const campaigns = await getAllCampaigns();
        cb(campaigns);
      } catch (error) {
        console.error("Error polling campaigns:", error);
      }
    }
  }, 10000); // Poll every 10 seconds

  // Return unsubscribe function
  return () => {
    isActive = false;
    clearInterval(pollInterval);
  };
};

export const getAllCampaigns = async () => {
  try {
    const response = await apiRequest("/api/campaigns");
    return response.campaigns;
  } catch (error) {
    console.error("Error getting campaigns:", error);
    return [];
  }
};

export const createCampaignDatabase = async (campaign: any) => {
  try {
    const response = await apiRequest("/api/campaigns", {
      method: "POST",
      body: JSON.stringify(campaign),
    });
    return response;
  } catch (error) {
    console.error("Error creating campaign:", error);
    throw error;
  }
};

export const updateCampaignStatusDatabase = async (id: string, status: string) => {
  try {
    const response = await apiRequest(`/api/campaigns/${id}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    return response;
  } catch (error) {
    console.error("Error updating campaign status:", error);
    throw error;
  }
};

export const deleteCampaignDatabase = async (id: string) => {
  try {
    const response = await apiRequest(`/api/campaigns/${id}`, {
      method: "DELETE",
    });
    return response;
  } catch (error) {
    console.error("Error deleting campaign:", error);
    throw error;
  }
};

// Hotspot functions
export const subscribeToHotspots = (cb: any) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(async () => {
    if (isActive) {
      try {
        const hotspots = await getAllHotspots();
        cb(hotspots);
      } catch (error) {
        console.error("Error polling hotspots:", error);
      }
    }
  }, 10000); // Poll every 10 seconds

  // Return unsubscribe function
  return () => {
    isActive = false;
    clearInterval(pollInterval);
  };
};

export const getAllHotspots = async () => {
  try {
    const response = await apiRequest("/api/hotspots");
    return response.hotspots;
  } catch (error) {
    console.error("Error getting hotspots:", error);
    return [];
  }
};

export const saveHotspotDatabase = async (hotspot: any) => {
  try {
    const response = await apiRequest("/api/hotspots", {
      method: "POST",
      body: JSON.stringify(hotspot),
    });
    return response;
  } catch (error) {
    console.error("Error saving hotspot:", error);
    throw error;
  }
};

export const deleteHotspotDatabase = async (id: string) => {
  try {
    const response = await apiRequest(`/api/hotspots/${id}`, {
      method: "DELETE",
    });
    return response;
  } catch (error) {
    console.error("Error deleting hotspot:", error);
    throw error;
  }
};

// Withdrawal functions
export const subscribeToWithdrawalRequests = (cb: (reqs: any[]) => void) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(async () => {
    if (isActive) {
      try {
        const requests = await getAllWithdrawalRequests();
        cb(requests);
      } catch (error) {
        console.error("Error polling withdrawal requests:", error);
      }
    }
  }, 15000); // Poll every 15 seconds

  // Return unsubscribe function
  return () => {
    isActive = false;
    clearInterval(pollInterval);
  };
};

export const getAllWithdrawalRequests = async () => {
  try {
    const response = await apiRequest("/api/withdrawals");
    return response.requests;
  } catch (error) {
    console.error("Error getting withdrawal requests:", error);
    return [];
  }
};

export const updateWithdrawalStatus = async (id: string, status: string) => {
  try {
    const response = await apiRequest(`/api/withdrawals/${id}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    return response;
  } catch (error) {
    console.error("Error updating withdrawal status:", error);
    throw error;
  }
};

// User management functions
export const updateUserWalletInDatabase = async (id: number, walletAddress: string) => {
  try {
    // Use the new update-wallet endpoint that handles Telegram auth
    const telegramInitData = `id=${id}`;

    const response = await apiRequest("/api/update-wallet", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: telegramInitData, // Pass minimal Telegram data
        walletAddress: walletAddress
      }),
    });
    return response;
  } catch (error) {
    console.error("Error updating user wallet:", error);
    throw error;
  }
};

export const deleteUserDatabase = async (id: string) => {
  try {
    const response = await apiRequest(`/api/users/${id}`, {
      method: "DELETE",
    });
    return response;
  } catch (error) {
    console.error("Error deleting user:", error);
    throw error;
  }
};

export const toggleUserBan = async (id: string, isBanned: boolean) => {
  try {
    const response = await apiRequest(`/api/users/${id}/ban`, {
      method: "PUT",
      body: JSON.stringify({ isBanned }),
    });
    return response;
  } catch (error) {
    console.error("Error toggling user ban:", error);
    throw error;
  }
};

export const toggleUserBiometricSetting = async (id: string, enabled: boolean) => {
  try {
    const response = await apiRequest(`/api/users/${id}/biometric`, {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    });
    return response;
  } catch (error) {
    console.error("Error toggling user biometric setting:", error);
    throw error;
  }
};

export const getAllUsersAdmin = async () => {
  try {
    const response = await apiRequest("/api/users");
    return response.users;
  } catch (error) {
    console.error("Error getting all users:", error);
    return [];
  }
};

// Withdrawal processing
export const processWithdrawTON = async (tgId: number, amount: number) => {
  try {
    const telegramInitData = `id=${tgId}`;

    const response = await apiRequest("/api/withdrawals", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: telegramInitData, // Pass minimal Telegram data
        amount: Number(amount),
        status: "pending",
      }),
    });
    return response;
  } catch (error) {
    console.error("Error processing TON withdrawal:", error);
    return { success: false };
  }
};

// Airdrop functions
export const markUserAirdropped = async (id: string, allocation: number) => {
  try {
    const response = await apiRequest(`/api/users/${id}/airdrop`, {
      method: "POST",
      body: JSON.stringify({ allocation }),
    });
    return response;
  } catch (error) {
    console.error("Error marking user airdropped:", error);
    return { success: false };
  }
};

// Get admin wallet (this would be implemented in the backend)
export const getAdminWallet = async () => {
  try {
    const response = await apiRequest("/api/admin/wallet");
    return response;
  } catch (error) {
    console.error("Error getting admin wallet:", error);
    return null;
  }
};

// AI Chat function (would proxy to backend)
export const askGeminiProxy = async (messages: any[]) => {
  try {
    const response = await apiRequest("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ messages }),
    });
    return response;
  } catch (error) {
    console.error("Error with AI chat:", error);
    return { text: "AI Node offline." };
  }
};