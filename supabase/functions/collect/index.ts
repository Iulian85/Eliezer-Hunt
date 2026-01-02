import { serve } from "@std/http";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests = 10, windowMs = 60000) {
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
    const { telegramInitData, spawnId, value, category, tonReward, location } = await req.json();

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
    if (!checkRateLimit(telegramId.toString(), "collect")) {
      return new Response(JSON.stringify({ success: false, error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Check if collection already exists (except for ads)
    if (!spawnId.startsWith("ad-")) {
      const { data: existingClaim, error: claimError } = await supabase
        .from("claims")
        .select("id")
        .eq("user_id", telegramId)
        .eq("spawn_id", spawnId)
        .single();

      if (existingClaim && !claimError) {
        return new Response(JSON.stringify({ success: false, error: "Item already collected" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
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

    // Create collection record
    const { error: claimError } = await supabase
      .from("claims")
      .insert({
        user_id: user.id,
        spawn_id: spawnId,
        category,
        claimed_value: value,
        ton_reward: tonReward || 0
      });

    if (claimError) {
      console.error("Claim creation error:", claimError);
      return new Response(JSON.stringify({ success: false, error: "Failed to create claim" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Update user balance based on category
    let balanceUpdate = {};
    if (category === "AD_REWARD") {
      balanceUpdate = {
        daily_supply_balance: Number(user.daily_supply_balance) + value,
        balance: Number(user.balance) + value,
        ton_balance: Number(user.ton_balance) + (tonReward || 0),
        ads_watched: Number(user.ads_watched) + 1
      };
    } else if (category === "LANDMARK") {
      balanceUpdate = {
        rare_balance: Number(user.rare_balance) + value,
        balance: Number(user.balance) + value,
        ton_balance: Number(user.ton_balance) + (tonReward || 0),
        rare_items_collected: Number(user.rare_items_collected) + 1
      };
    } else if (category === "EVENT") {
      balanceUpdate = {
        event_balance: Number(user.event_balance) + value,
        balance: Number(user.balance) + value,
        ton_balance: Number(user.ton_balance) + (tonReward || 0),
        event_items_collected: Number(user.event_items_collected) + 1
      };
    } else if (category === "MERCHANT") {
      balanceUpdate = {
        merchant_balance: Number(user.merchant_balance) + value,
        balance: Number(user.balance) + value,
        ton_balance: Number(user.ton_balance) + (tonReward || 0),
        sponsored_ads_watched: Number(user.sponsored_ads_watched) + 1
      };
    } else {
      // Default case for GIFTBOX and other categories
      balanceUpdate = {
        gameplay_balance: Number(user.gameplay_balance) + value,
        balance: Number(user.balance) + value,
        ton_balance: Number(user.ton_balance) + (tonReward || 0)
      };
    }

    // Update user balance and collected counters
    const { error: updateUserError } = await supabase
      .from("users")
      .update({
        ...balanceUpdate,
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

    return new Response(JSON.stringify({ success: true, message: "Collection saved successfully" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Collect error:", error);
    return new Response(JSON.stringify({ success: false, error: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});