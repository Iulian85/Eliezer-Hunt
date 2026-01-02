import { serve } from "@std/http";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Get admin user ID from environment variable
const ADMIN_USER_ID = Deno.env.get("ADMIN_USER_ID");
if (!ADMIN_USER_ID) {
  console.error("ADMIN_USER_ID is not set in environment variables");
}

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests = 20, windowMs = 60000) {
  const key = `${userId}:${action}`;
  const now = Date.now();
  const windowStart = now - windowMs;

  const limit = rateLimits.get(key);

  if (!limit || limit.windowStart < windowStart) {
    // Reset the rate limit
    rateLimits.set(key, { count: 1, windowStart: now });
    return true;
  }

  if (limit.count >= maxRequests) {
    return false; // Rate limit exceeded
  }

  // Increment the count
  rateLimits.set(key, { count: limit.count + 1, windowStart: now });
  return true;
}

// Helper function to create HMAC SHA256 hash using Web Crypto API
async function createHmacSha256(key: string, message: string): Promise<string> {
  // Create the secret key using the bot token
  const encoder = new TextEncoder();
  const keyBuffer = encoder.encode('WebAppData');
  const botTokenBuffer = encoder.encode(key);

  // Import the key for HMAC operations
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Sign the bot token with the key to get the secret
  const secretBuffer = await crypto.subtle.sign('HMAC', cryptoKey, botTokenBuffer);

  // Now sign the dataCheckString with the secret
  const dataCheckKey = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const messageBuffer = encoder.encode(message);
  const signature = await crypto.subtle.sign('HMAC', dataCheckKey, messageBuffer);

  // Convert to hex string
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Telegram authentication verification
async function verifyTelegramData(initData: string) {
  const botToken = Deno.env.get("TELEGRAM_BOT_TOKEN") || "";
  if (!botToken) {
    console.error("TELEGRAM_BOT_TOKEN is not set in environment variables");
    // For development/testing, allow simplified format without verification
    if (typeof initData === "string" && initData.startsWith("id=")) {
      const params = new URLSearchParams(initData);
      const id = params.get("id");
      if (id) {
        return { id: parseInt(id) };
      }
    }
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) {
      // For development/testing, allow simplified format without hash
      if (typeof initData === "string" && initData.startsWith("id=")) {
        const params = new URLSearchParams(initData);
        const id = params.get("id");
        if (id) {
          return { id: parseInt(id) };
        }
      }
      console.error("No hash found in Telegram init data");
      return null;
    }

    params.delete("hash");

    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    // Calculate the hash using Web Crypto API
    const calculatedHash = await createHmacSha256(botToken, dataCheckString);

    if (calculatedHash.toLowerCase() !== hash.toLowerCase()) {
      console.error("Telegram auth hash verification failed");
      return null;
    }

    const userParam = params.get("user");
    if (!userParam) {
      console.error("No user parameter found in Telegram init data");
      return null;
    }

    return JSON.parse(decodeURIComponent(userParam));
  } catch (error) {
    console.error("Telegram verification error:", error);
    // For development/testing, allow simplified format without verification
    if (typeof initData === "string" && initData.startsWith("id=")) {
      const params = new URLSearchParams(initData);
      const id = params.get("id");
      if (id) {
        return { id: parseInt(id) };
      }
    }
    return null;
  }
}

serve(async (req: Request) => {
  try {
    const url = new URL(req.url);
    const pathParts = url.pathname.split('/').filter(Boolean);

    // Extract the actual endpoint after /admin
    const endpoint = pathParts[1] || '';

    // Verify admin access
    const telegramInitData = url.searchParams.get('initData') || (req.method === 'POST' ? (await req.json()).telegramInitData : null);

    if (!telegramInitData) {
      return new Response(JSON.stringify({ success: false, error: "Telegram init data required for admin access" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const telegramUser = await verifyTelegramData(telegramInitData);
    if (!telegramUser || !ADMIN_USER_ID || telegramUser.id.toString() !== ADMIN_USER_ID.toString()) {
      return new Response(JSON.stringify({ success: false, error: "Admin access required" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    const adminId = telegramUser.id.toString();

    // Check rate limit
    if (!checkRateLimit(adminId, `admin_${endpoint}`)) {
      return new Response(JSON.stringify({ success: false, error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    switch (endpoint) {
      case 'users':
        if (req.method === 'GET') {
          // Get all users
          const { data: users, error } = await supabase
            .from("users")
            .select("*")
            .order("created_at", { ascending: false });

          if (error) {
            throw error;
          }

          return new Response(JSON.stringify({ success: true, users }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        break;

      case 'toggle-ban':
        if (req.method === 'PUT') {
          const { userId, isBanned } = await req.json();

          const { data: user, error } = await supabase
            .from("users")
            .update({ is_banned: isBanned })
            .eq("telegram_id", userId)
            .select()
            .single();

          if (error) {
            throw error;
          }

          return new Response(JSON.stringify({ success: true, user }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        break;

      case 'wallet':
        if (req.method === 'GET') {
          // Return admin wallet address from environment
          const adminWalletAddress = Deno.env.get("ADMIN_WALLET_ADDRESS");

          return new Response(JSON.stringify({
            success: true,
            adminWalletAddress
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        break;

      default:
        return new Response(JSON.stringify({ success: false, error: "Admin endpoint not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
    }

    return new Response(JSON.stringify({ success: false, error: "Method not allowed for this endpoint" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Admin error:", error);
    return new Response(JSON.stringify({ success: false, error: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});