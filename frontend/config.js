/**
 * ByteTrail Cloud & Local Deployment Configuration
 * 
 * Automatically resolves active backend:
 * 1. Local FastAPI (http://127.0.0.1:8000)
 * 2. Cloud Render Production API (https://bytetrail.onrender.com)
 */
(function() {
    if (typeof window === "undefined") return;

    const LOCAL_BACKEND = "http://127.0.0.1:8000";
    const CLOUD_BACKEND = "https://bytetrail.onrender.com";
    const FALLBACK_CLOUD = "https://bytetrail-prototype.onrender.com";

    const isLocal = window.location.hostname === "localhost" || 
                    window.location.hostname === "127.0.0.1" || 
                    window.location.protocol === "file:";

    if (isLocal) {
        window.BYTETRAIL_BACKEND_URL = LOCAL_BACKEND;
        // Background check: if local backend is not running, fall back to cloud backend
        fetch(`${LOCAL_BACKEND}/ping`, { mode: "cors" })
            .catch(() => {
                window.BYTETRAIL_BACKEND_URL = CLOUD_BACKEND;
                if (typeof checkBackendStatus === "function") checkBackendStatus();
            });
    } else {
        window.BYTETRAIL_BACKEND_URL = CLOUD_BACKEND;
    }
})();
