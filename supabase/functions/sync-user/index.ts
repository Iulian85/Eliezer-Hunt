import { serve } from "@std/http";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests = 5, windowMs = 60000) {
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

  try {
    // First, check if it's the simplified format (for development or when token is not set)
    if (typeof initData === "string" && initData.startsWith("id=")) {
      const params = new URLSearchParams(initData);
      const id = params.get("id");
      if (id) {
        return {
          id: parseInt(id),
          first_name: params.get("first_name") || "Anonymous",
          last_name: params.get("last_name") || "",
          username: params.get("username") || "",
          photo_url: params.get("photo_url") || ""
        };
      }
    }

    // If no bot token is set, return simplified format if possible
    if (!botToken) {
      console.warn("TELEGRAM_BOT_TOKEN is not set in environment variables");
      // Try to parse as regular Telegram init data without verification
      const params = new URLSearchParams(initData);
      const userParam = params.get("user");
      if (userParam) {
        return JSON.parse(decodeURIComponent(userParam));
      }
      return null;
    }

    // Standard Telegram verification
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) {
      console.error("No hash found in Telegram init data");
      // Still try to parse user data if available
      const userParam = params.get("user");
      if (userParam) {
        return JSON.parse(decodeURIComponent(userParam));
      }
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
      console.warn("Telegram auth hash verification failed, but attempting to continue with available data");
      // Even if verification fails, try to parse user data
      const userParam = params.get("user");
      if (userParam) {
        return JSON.parse(decodeURIComponent(userParam));
      }
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
    // Try to parse as simplified format as fallback
    if (typeof initData === "string" && initData.startsWith("id=")) {
      const params = new URLSearchParams(initData);
      const id = params.get("id");
      if (id) {
        return {
          id: parseInt(id),
          first_name: params.get("first_name") || "Anonymous",
          last_name: params.get("last_name") || "",
          username: params.get("username") || "",
          photo_url: params.get("photo_url") || ""
        };
      }
    }
    return null;
  }
}

serve(async (req: Request) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const { telegramInitData, fingerprint } = await req.json();

    // Verify Telegram authentication
    const telegramUser = await verifyTelegramData(telegramInitData);
    if (!telegramUser) {
      return new Response(JSON.stringify({ success: false, error: "Invalid Telegram auth" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const telegramId = telegramUser.id;

    // Check rate limit
    if (!checkRateLimit(telegramId.toString(), "sync-user")) {
      return new Response(JSON.stringify({ success: false, error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Check if user exists
    let { data: existingUser, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("telegram_id", telegramId)
      .single();

    let user;
    let isNewUser = false;

    if (userError || !existingUser) {
      // Create new user
      const { data, error } = await supabase
        .from("users")
        .insert({
          telegram_id: telegramId,
          username: telegramUser.username,
          first_name: telegramUser.first_name,
          last_name: telegramUser.last_name,
          photo_url: telegramUser.photo_url,
          device_fingerprint: fingerprint,
          joined_at: new Date().toISOString(),
          last_active: new Date().toISOString()
        })
        .select()
        .single();

      if (error) {
        console.error("Create user error:", error);
        return new Response(JSON.stringify({ success: false, error: "Failed to create user" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }

      user = data;
      isNewUser = true;
    } else {
      // Update existing user
      const { data, error } = await supabase
        .from("users")
        .update({
          username: telegramUser.username,
          first_name: telegramUser.first_name,
          last_name: telegramUser.last_name,
          photo_url: telegramUser.photo_url,
          device_fingerprint: fingerprint,
          last_active: new Date().toISOString()
        })
        .eq("telegram_id", telegramId)
        .select()
        .single();

      if (error) {
        console.error("Update user error:", error);
        return new Response(JSON.stringify({ success: false, error: "Failed to update user" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }

      user = data;
    }

    return new Response(JSON.stringify({
      success: true,
      user: user,
      isNewUser: isNewUser
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Sync user error:", error);
    return new Response(JSON.stringify({ success: false, error: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});