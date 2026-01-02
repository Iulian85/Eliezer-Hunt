import { serve } from "@std/http";
import { createClient } from "@supabase/supabase-js";

// Initialize Supabase client
const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Rate limiting storage
const rateLimits = new Map();

// Check rate limit for a user and action
function checkRateLimit(userId: string, action: string, maxRequests = 10, windowMs = 30000) { // 30 seconds window
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

serve(async (req: Request) => {
  if (req.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    // Check rate limit (use a generic key for leaderboard)
    if (!checkRateLimit("leaderboard", "getLeaderboard")) {
      return new Response(JSON.stringify({ success: false, error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Get top 50 users by balance
    const { data: leaderboard, error: leaderboardError } = await supabase
      .from("users")
      .select("telegram_id, username, first_name, last_name, photo_url, balance, ton_balance, gameplay_balance, rare_balance, event_balance, daily_supply_balance, merchant_balance, referral_balance")
      .eq("is_banned", false)
      .order("balance", { ascending: false })
      .limit(50);

    if (leaderboardError) {
      console.error("Get leaderboard error:", leaderboardError);
      return new Response(JSON.stringify({ success: false, error: "Failed to get leaderboard" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Add ranks to the results
    const rankedLeaderboard = leaderboard.map((user, index) => ({
      ...user,
      rank: index + 1
    }));

    return new Response(JSON.stringify({
      success: true,
      leaderboard: rankedLeaderboard
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Leaderboard error:", error);
    return new Response(JSON.stringify({ success: false, error: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});