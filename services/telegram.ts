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

// Helper function to create HMAC SHA256 hash using Web Crypto API
async function createHmacSha256(key: string, message: string): Promise<string> {
  // Create the secret key using the bot token
  const encoder = new TextEncoder();
  const botTokenBuffer = encoder.encode(key);

  // Import the key for HMAC operations
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    botTokenBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const messageBuffer = encoder.encode(message);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageBuffer);

  // Convert to hex string
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export const validateTelegramWebAppData = async (initData: string, botToken: string): Promise<boolean> => {
  try {
    // Check if initData is in the format "id=123456" (simplified format for development)
    if (initData.startsWith('id=')) {
      // This is a simplified format, we'll accept it for development purposes
      return true;
    }

    // Parse the init data
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) {
      console.error('No hash found in init data');
      return false;
    }
    params.delete('hash');

    // Sort the parameters alphabetically
    const sortedParams = Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    const dataCheckString = sortedParams.map(([key, value]) => `${key}=${value}`).join('\n');

    // Calculate the hash using Web Crypto API
    const calculatedHash = await createHmacSha256(botToken, dataCheckString);

    // Compare the calculated hash with the provided hash (case insensitive)
    return calculatedHash.toLowerCase() === hash.toLowerCase();
  } catch (error) {
    console.error('Error validating Telegram WebApp data:', error);
    // In development, we might want to be more permissive
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