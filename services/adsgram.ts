declare global {
    interface Window {
        Adsgram?: {
            init: (params: { blockId: string }) => {
                show: () => Promise<void>;
            };
        };
    }
}

// Helper to dynamically load the script if missing
const loadAdsgramScript = (): Promise<void> => {
    return new Promise((resolve, reject) => {
        if (window.Adsgram) {
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

        if (!window.Adsgram) {
            return false;
        }

        const AdController = window.Adsgram.init({
            blockId
        });

        await AdController.show();
        return true;

    } catch (error) {
        return false;
    }
};