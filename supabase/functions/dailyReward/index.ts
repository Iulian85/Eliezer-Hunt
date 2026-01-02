import { serve } from "@std/http";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests = 5, windowMs = 3600000) { // 1 hour window
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
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const { telegramInitData, adsgramReward } = await req.json();

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
    if (!checkRateLimit(telegramId.toString(), "dailyReward")) {
      return new Response(JSON.stringify({ success: false, error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Get user
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("telegram_id", telegramId)
      .single();

    if (!user) {
      return new Response(JSON.stringify({ success: false, error: "User not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Check if user has already claimed today's reward
    const today = new Date().toISOString().split('T')[0];
    const lastClaimDate = user.last_daily_claim ? new Date(user.last_daily_claim).toISOString().split('T')[0] : null;

    if (lastClaimDate === today) {
      return new Response(JSON.stringify({ success: false, error: "Daily reward already claimed today" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Calculate reward amount (could be based on adsgramReward or fixed amount)
    const rewardAmount = adsgramReward || 1000; // Default to 1000 if no adsgram reward provided

    // Update user's daily supply balance and last claim time
    const { error: updateUserError } = await supabase
      .from("users")
      .update({
        daily_supply_balance: Number(user.daily_supply_balance) + rewardAmount,
        balance: Number(user.balance) + rewardAmount,
        last_daily_claim: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq("telegram_id", telegramId);

    if (updateUserError) {
      console.error("Update user error:", updateUserError);
      return new Response(JSON.stringify({ success: false, error: "Failed to update user" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: "Daily reward claimed successfully",
      reward: rewardAmount
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Daily reward error:", error);
    return new Response(JSON.stringify({ success: false, error: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});