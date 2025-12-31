
import { UserState } from '../types';

/**
 * STORAGE SERVICE DEACTIVATED
 * All data must persist ONLY in PostgreSQL via Railway backend to prevent client-side balance manipulation.
 */

export const loadState = (): UserState | null => {
    return null; // Force fetch from PostgreSQL every time via backend API
};

export const saveState = (state: UserState) => {
    // Disabled for security
};

export const resetState = () => {
    // Local storage is not used
};

export const loadCampaigns = () => [];
export const saveCampaigns = () => null;
export const loadCustomHotspots = () => [];
export const saveCustomHotspots = () => null;
