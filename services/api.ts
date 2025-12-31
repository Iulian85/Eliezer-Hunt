import { User } from '../types';

const API_BASE = process.env.VITE_BUN_FUNCTION_URL || process.env.VITE_RAILWAY_BACKEND_URL || 'http://localhost:8080/api';

interface CollectData {
  userId: number;
  spawnId: string;
  category?: string;
  claimedValue: number;
  tonReward?: number;
  status?: string;
}

interface UpdateBalanceData {
  balance?: number;
  tonBalance?: number;
  gameplayBalance?: number;
  rareBalance?: number;
  eventBalance?: number;
  dailySupplyBalance?: number;
  merchantBalance?: number;
  referralBalance?: number;
  collectedIds?: string[];
}

export const api = {
  // Get user by Telegram ID
  getUser: async (telegramId: string): Promise<{ user: User }> => {
    const response = await fetch(`${API_BASE}/users/${telegramId}`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Create or update user
  createUser: async (userData: Partial<User>): Promise<{ user: User }> => {
    const response = await fetch(`${API_BASE}/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Update user balance
  updateUserBalance: async (telegramId: string, balanceData: UpdateBalanceData): Promise<{ user: User }> => {
    const response = await fetch(`${API_BASE}/users/${telegramId}/update-balance`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(balanceData),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Collect item/coin
  collect: async (collectData: CollectData): Promise<{ claim: any }> => {
    const response = await fetch(`${API_BASE}/collect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(collectData),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Watch ad and earn points
  watchAd: async (telegramId: string, rewardAmount?: number): Promise<any> => {
    const response = await fetch(`${API_BASE}/users/${telegramId}/watch-ad`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rewardAmount: rewardAmount || 10 }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Watch sponsored ad
  watchSponsoredAd: async (telegramId: string, rewardAmount?: number): Promise<any> => {
    const response = await fetch(`${API_BASE}/users/${telegramId}/watch-sponsored-ad`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rewardAmount: rewardAmount || 50 }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Claim daily reward
  claimDailyReward: async (telegramId: string): Promise<any> => {
    const response = await fetch(`${API_BASE}/dailyReward`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ telegramId }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  // Verify Telegram user (if needed)
  verifyTelegram: async (initData: string): Promise<any> => {
    const response = await fetch(`${API_BASE}/verifyTelegram`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ initData }),
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  },
};