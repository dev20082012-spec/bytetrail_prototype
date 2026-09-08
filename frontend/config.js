/**
 * ByteTrail Cloud Deployment Configuration
 * 
 * Auto-detects local backend vs cloud deployment.
 */
if (typeof window !== "undefined") {
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" || window.location.protocol === "file:") {
        window.BYTETRAIL_BACKEND_URL = "http://127.0.0.1:8000";
    } else {
        // Dynamically bind to current origin (e.g. https://bytetrail-prototype.onrender.com)
        window.BYTETRAIL_BACKEND_URL = window.location.origin || "https://bytetrail-prototype.onrender.com";
    }
}

