declare global {
    interface Window {
        Adsgram?: {
            init: (params: { blockId: string }) => {
                show: () => Promise<void>;
            };
        };
    }
}

// Define a type for the global Adsgram object
type GlobalWithAdsgram = typeof globalThis & {
    Adsgram?: {
        init: (params: { blockId: string }) => {
            show: () => Promise<void>;
        };
    };
};

// Helper to dynamically load the script if missing
const loadAdsgramScript = (): Promise<void> => {
    return new Promise<void>((resolve, reject) => {
        if ((globalThis as GlobalWithAdsgram).Adsgram) {
            resolve();
            return;
        }

        const script = document.createElement('script');
        script.src = "https://sad.adsgram.ai/js/sad.min.js";
        script.async = true;
        script.onload = () => {
            resolve();
        };
        script.onerror = () => {
            reject(new Error("AdsgramScriptError"));
        };
        document.body.appendChild(script);
    });
};

// Uses the blockId from environment variables or passed parameter
export const showRewardedAd = async (blockId: string): Promise<boolean> => {
    try {
        if (!blockId || blockId.trim() === '') {
            return false;
        }

        await loadAdsgramScript();

        const globalWithAdsgram = globalThis as GlobalWithAdsgram;
        if (!globalWithAdsgram.Adsgram) {
            return false;
        }

        const AdController = globalWithAdsgram.Adsgram.init({
            blockId
        });

        await AdController.show();
        return true;

    } catch (_error) {
        return false;
    }
};