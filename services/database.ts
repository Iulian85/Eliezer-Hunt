import { UserState, HotspotCategory, LeaderboardEntry, Campaign, HotspotDefinition } from "../types.ts";

interface WithdrawalRequest {
  id: string;
  userId: string;
  amount: number;
  status: string;
  createdAt: number;
  updatedAt: number;
  walletAddress?: string;
}

// Supabase Edge Functions service
// Base API URL for Supabase Edge Functions
const SUPABASE_PROJECT_URL = import.meta.env.VITE_SUPABASE_PROJECT_URL; // e.g., "https://xxxxx.supabase.co"
const SUPABASE_FUNCTION_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY; // Supabase anon key

// Construct the full API base URL for Supabase Edge Functions
const API_BASE = SUPABASE_PROJECT_URL ? `${SUPABASE_PROJECT_URL}/functions/v1` : "http://localhost:8080";

// Helper function to make API requests to Supabase Edge Functions
const apiRequest = async (endpoint: string, options: RequestInit = {}): Promise<any> => {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${SUPABASE_FUNCTION_KEY}`,
      ...options.headers,
    },
  });

  if (!response.ok) {
    // Log the error response for debugging
    const errorText = await response.text();
    console.error(`API request failed: ${response.status} ${response.statusText}`, errorText);
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  return response.json();
};

// Sanitize user data to match UserState interface
const sanitizeUserData = (data: Partial<UserState>, defaults: UserState): UserState => {
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
export const subscribeToUserProfile = (tgId: number, defaults: UserState, callback: (userData: UserState) => void): (() => void) => {
  if (!tgId) return () => {};

  // In a real implementation, this would use WebSocket or long polling
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(() => {
    getUserById(tgId)
      .then(userData => {
        if (isActive) {
          callback(sanitizeUserData(userData, defaults));
        }
      })
      .catch(error => {
        console.error("Error polling user data:", error);
      });
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
    const response = await apiRequest(`/getUser`, {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${tgId}` // Pass minimal Telegram data
      }),
    });
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
      lastInitData: "",
      location: null,
      screenshotLock: false,
      isAirdropped: false,
      airdropAllocation: 0,
      airdropTimestamp: null,
    };
  }
};

// Sync user with database
export const syncUserWithDatabase = async (userData: Record<string, unknown>, localState: UserState, fingerprint: string): Promise<UserState> => {
  if (!userData) return localState;

  try {
    // Extract Telegram init data from WebApp
    const telegramInitData = userData;

    const response = await apiRequest("/sync-user", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: telegramInitData,
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
export const saveCollectionToDatabase = async (tgId: number, spawnId: string, value: number, category?: HotspotCategory, tonReward: number = 0, location?: Record<string, unknown>): Promise<void> => {
  if (!tgId) return;

  try {
    // Use the collect endpoint that handles all the logic
    await apiRequest("/collect", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${tgId}`, // Minimal Telegram data for now
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
export const processReferralReward = async (referrerId: string, userId: number, userName: string): Promise<void> => {
  try {
    await apiRequest("/referrals", {
      method: "POST",
      body: JSON.stringify({
        referrerId,
        userId,
        userName
      }),
    });
  } catch (error) {
    console.error("Referral Error:", error);
  }
};

// Get leaderboard
export const getLeaderboard = async (): Promise<LeaderboardEntry[]> => {
  try {
    const response = await apiRequest("/leaderboard");
    return response.leaderboard;
  } catch (error) {
    console.error("Error getting leaderboard:", error);
    return [];
  }
};

// Reset user
export const resetUserInDatabase = async (targetUserId: number): Promise<{ success: boolean }> => {
  try {
    const response = await apiRequest(`/admin/reset-user`, {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${targetUserId}`, // Pass minimal Telegram data
        userId: targetUserId
      }),
    });
    return response;
  } catch (error) {
    console.error("Error resetting user:", error);
    return { success: false };
  }
};

// Campaign functions
export const subscribeToCampaigns = (cb: (campaigns: Campaign[]) => void): (() => void) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(() => {
    if (isActive) {
      getAllCampaigns()
        .then(campaigns => {
          cb(campaigns);
        })
        .catch(error => {
          console.error("Error polling campaigns:", error);
        });
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
    const response = await apiRequest("/campaigns");
    return response.campaigns;
  } catch (error) {
    console.error("Error getting campaigns:", error);
    return [];
  }
};

export const createCampaignDatabase = async (campaign: Campaign): Promise<Campaign> => {
  try {
    const response: { campaign: Campaign } = await apiRequest("/campaigns", {
      method: "POST",
      body: JSON.stringify(campaign),
    });
    return response.campaign;
  } catch (error) {
    console.error("Error creating campaign:", error);
    throw error;
  }
};

export const updateCampaignStatusDatabase = async (id: string, status: string): Promise<Campaign> => {
  try {
    const response: { campaign: Campaign } = await apiRequest(`/campaigns/${id}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    return response.campaign;
  } catch (error) {
    console.error("Error updating campaign status:", error);
    throw error;
  }
};

export const deleteCampaignDatabase = async (id: string): Promise<{ success: boolean }> => {
  try {
    const response: { success: boolean } = await apiRequest(`/campaigns/${id}`, {
      method: "DELETE",
    });
    return response;
  } catch (error) {
    console.error("Error deleting campaign:", error);
    throw error;
  }
};

// Hotspot functions
export const subscribeToHotspots = (cb: (hotspots: HotspotDefinition[]) => void): (() => void) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(() => {
    if (isActive) {
      getAllHotspots()
        .then(hotspots => {
          cb(hotspots);
        })
        .catch(error => {
          console.error("Error polling hotspots:", error);
        });
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
    const response = await apiRequest("/hotspots");
    return response.hotspots;
  } catch (error) {
    console.error("Error getting hotspots:", error);
    return [];
  }
};

export const saveHotspotDatabase = async (hotspot: HotspotDefinition): Promise<HotspotDefinition> => {
  try {
    const response: { hotspot: HotspotDefinition } = await apiRequest("/hotspots", {
      method: "POST",
      body: JSON.stringify(hotspot),
    });
    return response.hotspot;
  } catch (error) {
    console.error("Error saving hotspot:", error);
    throw error;
  }
};

export const deleteHotspotDatabase = async (id: string): Promise<{ success: boolean }> => {
  try {
    const response: { success: boolean } = await apiRequest(`/hotspots/${id}`, {
      method: "DELETE",
    });
    return response;
  } catch (error) {
    console.error("Error deleting hotspot:", error);
    throw error;
  }
};

// Withdrawal functions
export const subscribeToWithdrawalRequests = (cb: (reqs: WithdrawalRequest[]) => void) => {
  // In a real implementation, this would use WebSocket
  // For now, we'll use a simple polling approach
  let isActive = true;
  const pollInterval = setInterval(() => {
    if (isActive) {
      getAllWithdrawalRequests()
        .then(requests => {
          cb(requests);
        })
        .catch(error => {
          console.error("Error polling withdrawal requests:", error);
        });
    }
  }, 15000); // Poll every 15 seconds

  // Return unsubscribe function
  return () => {
    isActive = false;
    clearInterval(pollInterval);
  };
};

export const getAllWithdrawalRequests = async (): Promise<WithdrawalRequest[]> => {
  try {
    const response: { requests: WithdrawalRequest[] } = await apiRequest("/withdrawals");
    return response.requests;
  } catch (error) {
    console.error("Error getting withdrawal requests:", error);
    return [];
  }
};

export const updateWithdrawalStatus = async (id: string, status: string): Promise<WithdrawalRequest> => {
  try {
    const response: { request: WithdrawalRequest } = await apiRequest(`/withdrawals/${id}/status`, {
      method: "PUT",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Pass minimal Telegram data
        status
      }),
    });
    return response.request;
  } catch (error) {
    console.error("Error updating withdrawal status:", error);
    throw error;
  }
};

// User management functions
export const updateUserWalletInDatabase = async (id: number, walletAddress: string): Promise<{ success: boolean; user?: UserState }> => {
  try {
    const response: { success: boolean; user?: UserState } = await apiRequest("/updateWallet", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Minimal Telegram data for now
        walletAddress: walletAddress
      }),
    });
    return response;
  } catch (error) {
    console.error("Error updating user wallet:", error);
    throw error;
  }
};

export const deleteUserDatabase = async (id: string): Promise<{ success: boolean }> => {
  try {
    const response: { success: boolean } = await apiRequest(`/admin/users/${id}`, {
      method: "DELETE",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Pass minimal Telegram data
      }),
    });
    return response;
  } catch (error) {
    console.error("Error deleting user:", error);
    throw error;
  }
};

export const toggleUserBan = async (id: string, isBanned: boolean): Promise<{ success: boolean; user?: UserState }> => {
  try {
    const response: { success: boolean; user?: UserState } = await apiRequest(`/users/${id}/ban`, {
      method: "PUT",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Pass minimal Telegram data
        isBanned
      }),
    });
    return response;
  } catch (error) {
    console.error("Error toggling user ban:", error);
    throw error;
  }
};

export const toggleUserBiometricSetting = async (id: string, enabled: boolean): Promise<{ success: boolean; user?: UserState }> => {
  try {
    const response: { success: boolean; user?: UserState } = await apiRequest(`/users/${id}/biometric`, {
      method: "PUT",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Pass minimal Telegram data
        enabled
      }),
    });
    return response;
  } catch (error) {
    console.error("Error toggling user biometric setting:", error);
    throw error;
  }
};

export const getAllUsersAdmin = async (): Promise<UserState[]> => {
  try {
    const response: { users: UserState[] } = await apiRequest("/admin/users");
    return response.users;
  } catch (error) {
    console.error("Error getting all users:", error);
    return [];
  }
};

// Withdrawal processing
export const processWithdrawTON = async (tgId: number, amount: number): Promise<{ success: boolean; withdrawal?: WithdrawalRequest }> => {
  try {
    const response: { success: boolean; withdrawal?: WithdrawalRequest } = await apiRequest("/withdrawals", {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${tgId}`, // Minimal Telegram data for now
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
export const markUserAirdropped = async (id: string, allocation: number): Promise<{ success: boolean; user?: UserState }> => {
  try {
    const response: { success: boolean; user?: UserState } = await apiRequest(`/users/${id}/airdrop`, {
      method: "POST",
      body: JSON.stringify({
        telegramInitData: `id=${id}`, // Pass minimal Telegram data
        allocation
      }),
    });
    return response;
  } catch (error) {
    console.error("Error marking user airdropped:", error);
    return { success: false };
  }
};

// Get admin wallet (this would be implemented in the backend)
export const getAdminWallet = async (): Promise<{ address: string; balance: number } | null> => {
  try {
    const response: { address: string; balance: number } = await apiRequest("/admin/wallet");
    return response;
  } catch (error) {
    console.error("Error getting admin wallet:", error);
    return null;
  }
};

// AI Chat function (would proxy to backend)
export const askGeminiProxy = async (messages: { role: string; content: string }[]): Promise<{ text: string }> => {
  try {
    const response: { text: string } = await apiRequest("/ai/chat", {
      method: "POST",
      body: JSON.stringify({ messages }),
    });
    return response;
  } catch (error) {
    console.error("Error with AI chat:", error);
    return { text: "AI Node offline." };
  }
};