export {};

declare global {
  interface GlobalThis {
    Telegram?: {
      WebApp?: any;
      BiometricManager?: any;
      HapticFeedback?: any;
    };
    Adsgram?: any;
    Safari?: any;
    StatusBar?: any;
    device?: any;
    devtools?: any;
  }
}
