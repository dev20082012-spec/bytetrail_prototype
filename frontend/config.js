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
        fetch(`${LOCAL_BACKEND}/ping`, { mode: "cors" })
            .catch(() => {
                window.BYTETRAIL_BACKEND_URL = CLOUD_BACKEND;
                if (typeof checkBackendStatus === "function") checkBackendStatus();
            });
    } else {
        window.BYTETRAIL_BACKEND_URL = CLOUD_BACKEND;
    }
})();