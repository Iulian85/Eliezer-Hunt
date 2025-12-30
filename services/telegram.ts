import { createHmac } from 'crypto';

interface TelegramUserData {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: number;
  hash: string;
  user?: {
    id: number;
    first_name: string;
    last_name?: string;
    username?: string;
    photo_url?: string;
    is_bot?: boolean;
    language_code?: string;
  };
}

export const validateTelegramWebAppData = (initData: string, botToken: string): boolean => {
  try {
    // Parse the init data
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');
    
    // Sort the parameters alphabetically
    const sortedParams = Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    const dataCheckString = sortedParams.map(([key, value]) => `${key}=${value}`).join('\n');
    
    // Create the secret key using the bot token
    const secretKey = createHmac('sha256', 'WebAppData').update(botToken).digest();
    
    // Calculate the hash
    const calculatedHash = createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    
    // Compare the calculated hash with the provided hash
    return calculatedHash === hash;
  } catch (error) {
    console.error('Error validating Telegram WebApp data:', error);
    return false;
  }
};

export const parseTelegramWebAppData = (initData: string): TelegramUserData | null => {
  try {
    const params = new URLSearchParams(initData);
    const userData: any = {};

    for (const [key, value] of params) {
      if (key === 'user') {
        // If there's a user parameter, parse it and use its properties as the main user data
        const parsedUser = JSON.parse(decodeURIComponent(value));
        // Copy the user properties to the root level
        Object.assign(userData, parsedUser);
        // Also keep the original user object
        userData.user = parsedUser;
      } else {
        userData[key] = isNaN(Number(value)) ? value : Number(value);
      }
    }

    return userData as TelegramUserData;
  } catch (error) {
    console.error('Error parsing Telegram WebApp data:', error);
    return null;
  }
};