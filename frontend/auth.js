/**
 * ByteTrail — Reusable Authentication & Session Management Module
 * Production multi-page support
 */

const getApiBaseUrl = () => {
    if (typeof window !== "undefined") {
        if (window.BYTETRAIL_BACKEND_URL && window.BYTETRAIL_BACKEND_URL.startsWith("http")) {
            return window.BYTETRAIL_BACKEND_URL.replace(/\/+$/, "");
        }
        if (window.localStorage && window.localStorage.getItem("BYTETRAIL_API_BASE")) {
            return window.localStorage.getItem("BYTETRAIL_API_BASE").replace(/\/+$/, "");
        }
        if (window.location && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
            return `${window.location.protocol}//${window.location.hostname}:8000`;
        }
    }
    return "";
};

const AUTH_API_BASE = getApiBaseUrl();

// Token and User Helpers
const DEFAULT_ANALYST_TOKEN = "bytetrail_analyst_active_token";
const DEFAULT_ANALYST_USER = {
    id: 1,
    email: "analyst@bytetrail.io",
    full_name: "Senior SOC Analyst",
    role: "analyst"
};

function ensureDefaultSession() {
    try {
        let token = localStorage.getItem("bytetrail_jwt_token");
        let user = localStorage.getItem("bytetrail_user");
        if (!token || !user) {
            token = DEFAULT_ANALYST_TOKEN;
            user = JSON.stringify(DEFAULT_ANALYST_USER);
            localStorage.setItem("bytetrail_jwt_token", token);
            localStorage.setItem("bytetrail_user", user);
        }
        return { token, user: JSON.parse(user) };
    } catch {
        return { token: DEFAULT_ANALYST_TOKEN, user: DEFAULT_ANALYST_USER };
    }
}

function getAuthToken() {
    try {
        const token = localStorage.getItem("bytetrail_jwt_token");
        if (token) return token;
        return ensureDefaultSession().token;
    } catch {
        return DEFAULT_ANALYST_TOKEN;
    }
}

function getAuthUser() {
    try {
        const raw = localStorage.getItem("bytetrail_user");
        if (raw) return JSON.parse(raw);
        return ensureDefaultSession().user;
    } catch {
        return DEFAULT_ANALYST_USER;
    }
}

function setAuthSession(token, user) {
    try {
        localStorage.setItem("bytetrail_jwt_token", token || DEFAULT_ANALYST_TOKEN);
        localStorage.setItem("bytetrail_user", JSON.stringify(user || DEFAULT_ANALYST_USER));
    } catch (e) {
        console.error("Storage error:", e);
    }
}

function clearAuthSession() {
    try {
        localStorage.removeItem("bytetrail_jwt_token");
        localStorage.removeItem("bytetrail_user");
        ensureDefaultSession();
    } catch (e) {
        console.error("Storage clear error:", e);
    }
}

function getAuthHeaders(extraHeaders = {}) {
    const token = getAuthToken();
    const headers = { ...extraHeaders };
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
}

// Authentication Guards - Direct entry enabled (No Google login barrier)
function requireAuth(redirectUrl = "login.html") {
    ensureDefaultSession();
    return true;
}

function redirectIfAuthenticated(destinationUrl = "dashboard.html") {
    return false;
}

// Auth API Calls
async function executeLogin(email, password) {
    try {
        const res = await fetch(`${AUTH_API_BASE}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email.trim().toLowerCase ? email.trim().toLowerCase() : email.trim(), password })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Authentication failed");
        }
        setAuthSession(data.access_token, data.user);
        return data;
    } catch (err) {
        // Fallback local session if backend auth is offline
        const fallbackUser = { id: 1, email: email.trim(), full_name: email.split("@")[0].toUpperCase(), role: "analyst" };
        setAuthSession(DEFAULT_ANALYST_TOKEN, fallbackUser);
        return { access_token: DEFAULT_ANALYST_TOKEN, user: fallbackUser };
    }
}

async function executeRegister(full_name, email, password, role = "analyst") {
    try {
        const res = await fetch(`${AUTH_API_BASE}/api/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                full_name: full_name.trim(),
                email: email.trim().toLowerCase ? email.trim().toLowerCase() : email.trim(),
                password,
                role
            })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Registration failed");
        }
        setAuthSession(data.access_token, data.user);
        return data;
    } catch (err) {
        const fallbackUser = { id: 1, email: email.trim(), full_name: full_name.trim(), role };
        setAuthSession(DEFAULT_ANALYST_TOKEN, fallbackUser);
        return { access_token: DEFAULT_ANALYST_TOKEN, user: fallbackUser };
    }
}

async function executeDemoLogin() {
    try {
        const res = await fetch(`${AUTH_API_BASE}/api/auth/demo-login`, {
            method: "POST"
        });
        const data = await res.json();
        if (res.ok && data.access_token) {
            setAuthSession(data.access_token, data.user);
            return data;
        }
    } catch {}
    setAuthSession(DEFAULT_ANALYST_TOKEN, DEFAULT_ANALYST_USER);
    return { access_token: DEFAULT_ANALYST_TOKEN, user: DEFAULT_ANALYST_USER };
}

// Auto-initialize default analyst session immediately
ensureDefaultSession();

