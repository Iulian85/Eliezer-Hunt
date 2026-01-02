-- Enable the pgcrypto extension for cryptographic functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  telegram_id BIGINT UNIQUE NOT NULL,
  username TEXT,
  first_name TEXT,
  last_name TEXT,
  photo_url TEXT,
  device_fingerprint TEXT,
  balance BIGINT DEFAULT 0,
  ton_balance BIGINT DEFAULT 0,
  gameplay_balance BIGINT DEFAULT 0,
  rare_balance BIGINT DEFAULT 0,
  event_balance BIGINT DEFAULT 0,
  daily_supply_balance BIGINT DEFAULT 0,
  merchant_balance BIGINT DEFAULT 0,
  referral_balance BIGINT DEFAULT 0,
  biometric_enabled BOOLEAN DEFAULT true,
  is_banned BOOLEAN DEFAULT false,
  wallet_address TEXT,
  referrals INTEGER DEFAULT 0,
  has_claimed_referral BOOLEAN DEFAULT false,
  ads_watched INTEGER DEFAULT 0,
  sponsored_ads_watched INTEGER DEFAULT 0,
  rare_items_collected INTEGER DEFAULT 0,
  event_items_collected INTEGER DEFAULT 0,
  screenshot_lock BOOLEAN DEFAULT false,
  is_airdropped BOOLEAN DEFAULT false,
  airdrop_allocation BIGINT DEFAULT 0,
  last_daily_claim TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create the claims table
CREATE TABLE IF NOT EXISTS claims (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  spawn_id TEXT NOT NULL,
  category TEXT,
  claimed_value BIGINT DEFAULT 0,
  ton_reward BIGINT DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create the campaigns table
CREATE TABLE IF NOT EXISTS campaigns (
  id BIGSERIAL PRIMARY KEY,
  owner_wallet TEXT NOT NULL,
  target_lat DECIMAL NOT NULL,
  target_lng DECIMAL NOT NULL,
  count INTEGER DEFAULT 1,
  multiplier INTEGER DEFAULT 1,
  duration_days INTEGER DEFAULT 1,
  expiry_date BIGINT,
  total_price BIGINT DEFAULT 0,
  brand_name TEXT,
  logo_url TEXT,
  video_url TEXT,
  video_file_name TEXT,
  contact_street TEXT,
  contact_city TEXT,
  contact_zip TEXT,
  contact_country TEXT,
  contact_phone TEXT,
  contact_email TEXT,
  contact_website TEXT,
  status TEXT DEFAULT 'pending_review',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create the hotspots table
CREATE TABLE IF NOT EXISTS hotspots (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  lat DECIMAL NOT NULL,
  lng DECIMAL NOT NULL,
  radius INTEGER DEFAULT 100,
  density INTEGER DEFAULT 10,
  category TEXT,
  base_value BIGINT DEFAULT 100,
  logo_url TEXT,
  custom_text TEXT,
  prizes TEXT, -- JSON array of numbers as text
  video_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create the withdrawal_requests table
CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  amount BIGINT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  processed_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
CREATE INDEX IF NOT EXISTS idx_claims_spawn_id ON claims(spawn_id);
CREATE INDEX IF NOT EXISTS idx_claims_created_at ON claims(created_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_owner_wallet ON campaigns(owner_wallet);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON withdrawal_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON withdrawal_requests(status);

-- Enable Row Level Security (RLS)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE hotspots ENABLE ROW LEVEL SECURITY;
ALTER TABLE withdrawal_requests ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for users table
CREATE POLICY users_select_own ON users FOR SELECT USING (
  telegram_id::text = auth.uid()::text OR is_admin_user()
);
CREATE POLICY users_update_own ON users FOR UPDATE USING (
  telegram_id::text = auth.uid()::text OR is_admin_user()
) WITH CHECK (
  telegram_id::text = auth.uid()::text OR is_admin_user()
);
CREATE POLICY users_insert_own ON users FOR INSERT WITH CHECK (
  telegram_id::text = auth.uid()::text OR is_admin_user()
);

-- Create RLS policies for claims table
CREATE POLICY claims_select_own ON claims FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = claims.user_id AND telegram_id::text = auth.uid()::text)
);
CREATE POLICY claims_insert_own ON claims FOR INSERT WITH CHECK (
  EXISTS (SELECT 1 FROM users WHERE id = claims.user_id AND telegram_id::text = auth.uid()::text)
);
CREATE POLICY claims_update_own ON claims FOR UPDATE USING (
  EXISTS (SELECT 1 FROM users WHERE id = claims.user_id AND telegram_id::text = auth.uid()::text)
);

-- Create RLS policies for campaigns table
CREATE POLICY campaigns_select_all ON campaigns FOR SELECT USING (true);
CREATE POLICY campaigns_insert_own ON campaigns FOR INSERT WITH CHECK (
  is_admin_user() OR owner_wallet = (
    SELECT wallet_address FROM users WHERE telegram_id::text = auth.uid()::text
  )
);
CREATE POLICY campaigns_update_own ON campaigns FOR UPDATE USING (
  is_admin_user() OR owner_wallet = (
    SELECT wallet_address FROM users WHERE telegram_id::text = auth.uid()::text
  )
);
CREATE POLICY campaigns_delete_own ON campaigns FOR DELETE USING (
  is_admin_user()
);

-- Create RLS policies for hotspots table
CREATE POLICY hotspots_select_all ON hotspots FOR SELECT USING (true);
CREATE POLICY hotspots_insert_admin ON hotspots FOR INSERT WITH CHECK (is_admin_user());
CREATE POLICY hotspots_update_admin ON hotspots FOR UPDATE USING (is_admin_user());
CREATE POLICY hotspots_delete_admin ON hotspots FOR DELETE USING (is_admin_user());

-- Create RLS policies for withdrawal_requests table
CREATE POLICY withdrawal_requests_select_own ON withdrawal_requests FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = withdrawal_requests.user_id AND telegram_id::text = auth.uid()::text)
);
CREATE POLICY withdrawal_requests_insert_own ON withdrawal_requests FOR INSERT WITH CHECK (
  EXISTS (SELECT 1 FROM users WHERE id = withdrawal_requests.user_id AND telegram_id::text = auth.uid()::text)
);
CREATE POLICY withdrawal_requests_update_own ON withdrawal_requests FOR UPDATE USING (
  EXISTS (SELECT 1 FROM users WHERE id = withdrawal_requests.user_id AND telegram_id::text = auth.uid()::text)
);

-- Create function to check if user is admin
CREATE OR REPLACE FUNCTION is_admin_user()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  admin_user_id TEXT;
BEGIN
  SELECT current_setting('app.admin_user_id', true) INTO admin_user_id;
  RETURN auth.uid()::text = admin_user_id;
END;
$$;

-- Create function to get current user ID
CREATE OR REPLACE FUNCTION current_user_telegram_id() 
RETURNS BIGINT 
LANGUAGE plpgsql 
SECURITY DEFINER
AS $$
BEGIN
  RETURN auth.uid()::BIGINT;
END;
$$;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;