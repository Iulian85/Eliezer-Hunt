/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_PROJECT_URL: string;
  readonly VITE_SUPABASE_ANON_KEY: string;
  readonly VITE_ADSGRAM_BLOCK_ID: string;
  readonly VITE_GEMINI_API_KEY: string;
  readonly VITE_TELEGRAM_BOT_TOKEN: string;
  readonly VITE_BOT_TOKEN: string;
  readonly ADMIN_WALLET_ADDRESS: string;
  // Add other environment variables as needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}