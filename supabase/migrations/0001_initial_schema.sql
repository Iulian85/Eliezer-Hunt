-- Supabase Schema for Eliezer Hunt Game

-- Users table
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    telegram_id BIGINT UNIQUE NOT NULL,
    username TEXT,
    photo_url TEXT,
    device_fingerprint TEXT,
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    last_active TIMESTAMPTZ DEFAULT NOW(),
    balance INTEGER DEFAULT 0,
    ton_balance INTEGER DEFAULT 0,
    gameplay_balance INTEGER DEFAULT 0,
    rare_balance INTEGER DEFAULT 0,
    event_balance INTEGER DEFAULT 0,
    daily_supply_balance INTEGER DEFAULT 0,
    merchant_balance INTEGER DEFAULT 0,
    referral_balance INTEGER DEFAULT 0,
    collected_ids TEXT[] DEFAULT '{}',
    biometric_enabled BOOLEAN DEFAULT true,
    is_banned BOOLEAN DEFAULT false,
    wallet_address TEXT,
    referrals INTEGER DEFAULT 0,
    referral_names TEXT[] DEFAULT '{}',
    has_claimed_referral BOOLEAN DEFAULT false,
    last_ad_watch BIGINT DEFAULT 0,
    last_daily_claim BIGINT DEFAULT 0,
    ads_watched INTEGER DEFAULT 0,
    sponsored_ads_watched INTEGER DEFAULT 0,
    rare_items_collected INTEGER DEFAULT 0,
    event_items_collected INTEGER DEFAULT 0,
    screenshot_lock BOOLEAN DEFAULT false,
    is_airdropped BOOLEAN DEFAULT false,
    airdrop_allocation INTEGER DEFAULT 0,
    airdrop_timestamp TIMESTAMPTZ,
    last_init_data TEXT,
    country_code TEXT,
    ban_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for users table
CREATE INDEX idx_users_telegram_id ON users(telegram_id);
CREATE INDEX idx_users_wallet_address ON users(wallet_address);
CREATE INDEX idx_users_device_fingerprint ON users(device_fingerprint);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Campaigns table
CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_wallet TEXT NOT NULL,
    target_coords JSONB NOT NULL, -- {lat: number, lng: number}
    count INTEGER NOT NULL DEFAULT 1,
    multiplier INTEGER NOT NULL DEFAULT 1,
    duration_days INTEGER NOT NULL DEFAULT 1,
    expiry_date TIMESTAMPTZ,
    total_price INTEGER NOT NULL DEFAULT 0,
    data JSONB NOT NULL, -- SponsorData object
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'pending_review', -- AdStatus enum
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for campaigns table
CREATE INDEX idx_campaigns_owner_wallet ON campaigns(owner_wallet);
CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_expiry_date ON campaigns(expiry_date);

CREATE TRIGGER update_campaigns_updated_at 
    BEFORE UPDATE ON campaigns 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Hotspots table
CREATE TABLE hotspots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    coords JSONB NOT NULL, -- {lat: number, lng: number}
    radius INTEGER NOT NULL DEFAULT 100,
    density INTEGER NOT NULL DEFAULT 1,
    category TEXT NOT NULL, -- HotspotCategory enum
    base_value INTEGER NOT NULL DEFAULT 1,
    logo_url TEXT,
    custom_text TEXT,
    prizes INTEGER[],
    video_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for hotspots table
CREATE INDEX idx_hotspots_coords ON hotspots USING GIN (coords);
CREATE INDEX idx_hotspots_category ON hotspots(category);

CREATE TRIGGER update_hotspots_updated_at 
    BEFORE UPDATE ON hotspots 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Collections table (for tracking collected spawn points)
CREATE TABLE collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    spawn_id TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    category TEXT, -- HotspotCategory enum
    ton_reward INTEGER DEFAULT 0,
    location JSONB, -- {lat: number, lng: number}
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for collections table
CREATE INDEX idx_collections_user_id ON collections(user_id);
CREATE INDEX idx_collections_spawn_id ON collections(spawn_id);
CREATE INDEX idx_collections_collected_at ON collections(collected_at);

-- Referrals table
CREATE TABLE referrals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    user_name TEXT,
    reward_amount INTEGER DEFAULT 0,
    claimed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for referrals table
CREATE INDEX idx_referrals_referrer_id ON referrals(referrer_id);
CREATE INDEX idx_referrals_user_id ON referrals(user_id);

-- Withdrawal requests table
CREATE TABLE withdrawal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,
    status TEXT DEFAULT 'pending', -- pending, approved, rejected, processed
    wallet_address TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for withdrawal requests table
CREATE INDEX idx_withdrawal_requests_user_id ON withdrawal_requests(user_id);
CREATE INDEX idx_withdrawal_requests_status ON withdrawal_requests(status);

CREATE TRIGGER update_withdrawal_requests_updated_at 
    BEFORE UPDATE ON withdrawal_requests 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Leaderboard view (materialized view for performance)
CREATE MATERIALIZED VIEW leaderboard_view AS
SELECT 
    u.id,
    u.telegram_id,
    u.username,
    (u.balance + u.ton_balance + u.gameplay_balance + u.rare_balance + u.event_balance + u.daily_supply_balance + u.merchant_balance + u.referral_balance) AS total_score,
    u.rare_items_collected,
    u.event_items_collected,
    u.ads_watched,
    u.referrals
FROM users u
WHERE u.is_banned = false
ORDER BY total_score DESC;

-- Index for leaderboard view
CREATE INDEX idx_leaderboard_total_score ON leaderboard_view(total_score);

-- Function to refresh leaderboard
CREATE OR REPLACE FUNCTION refresh_leaderboard()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW leaderboard_view;
END;
$$ LANGUAGE plpgsql;

-- RLS (Row Level Security) policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE hotspots ENABLE ROW LEVEL SECURITY;
ALTER TABLE collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE referrals ENABLE ROW LEVEL SECURITY;
ALTER TABLE withdrawal_requests ENABLE ROW LEVEL SECURITY;

-- Policies for users table
CREATE POLICY "Users are only viewable by themselves" ON users
    FOR SELECT USING (auth.uid() = id OR auth.role() = 'service_role');

CREATE POLICY "Users can update their own profile" ON users
    FOR UPDATE USING (auth.uid() = id OR auth.role() = 'service_role');

-- Policies for campaigns table
CREATE POLICY "Campaigns are viewable by all authenticated users" ON campaigns
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Users can create their own campaigns" ON campaigns
    FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Users can update their own campaigns" ON campaigns
    FOR UPDATE USING (auth.uid() = (SELECT id FROM users WHERE wallet_address = owner_wallet));

-- Policies for hotspots table
CREATE POLICY "Hotspots are viewable by all authenticated users" ON hotspots
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Admins can manage hotspots" ON hotspots
    FOR ALL TO service_role USING (true);

-- Storage for user profile images
INSERT INTO storage.buckets (id, name, public) VALUES ('user-avatars', 'user-avatars', true);

-- Policies for storage
CREATE POLICY "Public access for user avatars" ON storage.objects FOR SELECT TO public USING (bucket_id = 'user-avatars');
CREATE POLICY "Authenticated users can upload avatars" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'user-avatars');
CREATE POLICY "Authenticated users can update their avatars" ON storage.objects FOR UPDATE TO authenticated USING (bucket_id = 'user-avatars');

-- Function to get user by Telegram ID
CREATE OR REPLACE FUNCTION get_user_by_telegram_id(telegram_id_param BIGINT)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_data jsonb;
BEGIN
    SELECT jsonb_build_object(
        'id', u.id,
        'telegramId', u.telegram_id,
        'username', u.username,
        'photoUrl', u.photo_url,
        'deviceFingerprint', u.device_fingerprint,
        'joinedAt', u.joined_at,
        'lastActive', u.last_active,
        'balance', u.balance,
        'tonBalance', u.ton_balance,
        'gameplayBalance', u.gameplay_balance,
        'rareBalance', u.rare_balance,
        'eventBalance', u.event_balance,
        'dailySupplyBalance', u.daily_supply_balance,
        'merchantBalance', u.merchant_balance,
        'referralBalance', u.referral_balance,
        'collectedIds', u.collected_ids,
        'biometricEnabled', u.biometric_enabled,
        'isBanned', u.is_banned,
        'walletAddress', u.wallet_address,
        'referrals', u.referrals,
        'referralNames', u.referral_names,
        'hasClaimedReferral', u.has_claimed_referral,
        'lastAdWatch', u.last_ad_watch,
        'lastDailyClaim', u.last_daily_claim,
        'adsWatched', u.ads_watched,
        'sponsoredAdsWatched', u.sponsored_ads_watched,
        'rareItemsCollected', u.rare_items_collected,
        'eventItemsCollected', u.event_items_collected,
        'screenshotLock', u.screenshot_lock,
        'isAirdropped', u.is_airdropped,
        'airdropAllocation', u.airdrop_allocation,
        'airdropTimestamp', u.airdrop_timestamp,
        'lastInitData', u.last_init_data,
        'countryCode', u.country_code,
        'banCount', u.ban_count
    ) INTO user_data
    FROM users u
    WHERE u.telegram_id = telegram_id_param;

    RETURN user_data;
END;
$$;

-- Function to sync user with database
CREATE OR REPLACE FUNCTION sync_user(telegram_init_data_param jsonb, fingerprint_param TEXT)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_id BIGINT;
    user_data jsonb;
    user_exists BOOLEAN;
BEGIN
    -- Extract telegram user ID from init data
    user_id := (telegram_init_data_param->'user'->>'id')::BIGINT;

    -- Check if user exists
    SELECT EXISTS(SELECT 1 FROM users WHERE telegram_id = user_id) INTO user_exists;

    IF NOT user_exists THEN
        -- Create new user
        INSERT INTO users (telegram_id, username, photo_url, device_fingerprint)
        VALUES (
            user_id,
            telegram_init_data_param->'user'->>'first_name',
            telegram_init_data_param->'user'->>'photo_url',
            fingerprint_param
        );
    ELSE
        -- Update existing user
        UPDATE users 
        SET 
            last_active = NOW(),
            device_fingerprint = COALESCE(device_fingerprint, fingerprint_param),
            username = COALESCE(username, telegram_init_data_param->'user'->>'first_name'),
            photo_url = COALESCE(photo_url, telegram_init_data_param->'user'->>'photo_url')
        WHERE telegram_id = user_id;
    END IF;

    -- Return user data
    SELECT get_user_by_telegram_id(user_id) INTO user_data;
    RETURN user_data;
END;
$$;

-- Function to save collection
CREATE OR REPLACE FUNCTION save_collection(telegram_id_param BIGINT, spawn_id_param TEXT, value_param INTEGER, category_param TEXT, ton_reward_param INTEGER, location_param JSONB)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    user_id BIGINT;
BEGIN
    -- Get user ID from telegram ID
    SELECT id INTO user_id FROM users WHERE telegram_id = telegram_id_param;

    IF user_id IS NOT NULL THEN
        -- Insert collection record
        INSERT INTO collections (user_id, spawn_id, value, category, ton_reward, location)
        VALUES (user_id, spawn_id_param, value_param, category_param, ton_reward_param, location_param);

        -- Update user balance based on category
        IF category_param = 'AD_REWARD' THEN
            UPDATE users 
            SET 
                balance = balance + value_param,
                last_ad_watch = EXTRACT(EPOCH FROM NOW())::BIGINT,
                ads_watched = ads_watched + 1
            WHERE id = user_id;
        ELSIF category_param = 'MERCHANT' THEN
            UPDATE users 
            SET 
                merchant_balance = merchant_balance + value_param
            WHERE id = user_id;
        ELSE
            UPDATE users 
            SET 
                balance = balance + value_param
            WHERE id = user_id;
        END IF;
    END IF;
END;
$$;

-- Function to process referral
CREATE OR REPLACE FUNCTION process_referral(referrer_id_param TEXT, user_id_param BIGINT, user_name_param TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    referrer_db_id BIGINT;
    existing_referral BOOLEAN;
BEGIN
    -- Get referrer database ID
    SELECT id INTO referrer_db_id FROM users WHERE telegram_id = (referrer_id_param::BIGINT);

    IF referrer_db_id IS NOT NULL THEN
        -- Check if referral already exists
        SELECT EXISTS(
            SELECT 1 FROM referrals 
            WHERE referrer_id = referrer_db_id AND user_id = user_id_param
        ) INTO existing_referral;

        IF NOT existing_referral THEN
            -- Insert referral record
            INSERT INTO referrals (referrer_id, user_id, user_name)
            VALUES (referrer_db_id, user_id_param, user_name_param);

            -- Update referrer's referral count and balance
            UPDATE users 
            SET 
                referrals = referrals + 1,
                referral_balance = referral_balance + 1000, -- 1000 tokens for referral
                balance = balance + 1000
            WHERE id = referrer_db_id;

            -- Update referrer's referral names
            UPDATE users 
            SET referral_names = array_append(referral_names, user_name_param)
            WHERE id = referrer_db_id;
        END IF;
    END IF;
END;
$$;

-- Function to get leaderboard
CREATE OR REPLACE FUNCTION get_leaderboard()
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    leaderboard_data jsonb;
BEGIN
    SELECT jsonb_agg(
        jsonb_build_object(
            'rank', rank,
            'username', username,
            'score', total_score
        ) ORDER BY rank
    ) INTO leaderboard_data
    FROM (
        SELECT 
            ROW_NUMBER() OVER (ORDER BY total_score DESC) AS rank,
            COALESCE(username, 'Anonymous_' || telegram_id::TEXT) AS username,
            total_score
        FROM leaderboard_view
        LIMIT 100
    ) ranked_users;

    RETURN leaderboard_data;
END;
$$;

-- Function to update user wallet
CREATE OR REPLACE FUNCTION update_user_wallet(telegram_id_param BIGINT, wallet_address_param TEXT)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_data jsonb;
BEGIN
    UPDATE users 
    SET wallet_address = wallet_address_param
    WHERE telegram_id = telegram_id_param;

    SELECT get_user_by_telegram_id(telegram_id_param) INTO user_data;
    RETURN user_data;
END;
$$;

-- Function to toggle user ban
CREATE OR REPLACE FUNCTION toggle_user_ban(telegram_id_param BIGINT, is_banned_param BOOLEAN)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_data jsonb;
BEGIN
    UPDATE users 
    SET 
        is_banned = is_banned_param,
        ban_count = CASE 
            WHEN is_banned_param THEN ban_count + 1 
            ELSE ban_count 
        END
    WHERE telegram_id = telegram_id_param;

    SELECT get_user_by_telegram_id(telegram_id_param) INTO user_data;
    RETURN user_data;
END;
$$;

-- Function to toggle biometric setting
CREATE OR REPLACE FUNCTION toggle_biometric_setting(telegram_id_param BIGINT, enabled_param BOOLEAN)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_data jsonb;
BEGIN
    UPDATE users 
    SET biometric_enabled = enabled_param
    WHERE telegram_id = telegram_id_param;

    SELECT get_user_by_telegram_id(telegram_id_param) INTO user_data;
    RETURN user_data;
END;
$$;

-- Function to mark user airdropped
CREATE OR REPLACE FUNCTION mark_user_airdropped(telegram_id_param BIGINT, allocation_param INTEGER)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    user_data jsonb;
BEGIN
    UPDATE users 
    SET 
        is_airdropped = true,
        airdrop_allocation = allocation_param,
        airdrop_timestamp = NOW()
    WHERE telegram_id = telegram_id_param;

    SELECT get_user_by_telegram_id(telegram_id_param) INTO user_data;
    RETURN user_data;
END;
$$;

-- Refresh the leaderboard materialized view periodically
-- This would typically be done with a scheduled function in Supabase