
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const ROOT_DIR = __dirname;

const MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
    ".eml": "message/rfc822",
    ".txt": "text/plain; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf"
};

const requestHandler = (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    let pathname = decodeURIComponent(parsedUrl.pathname);

    let safePath = path.normalize(path.join(ROOT_DIR, pathname));
    if (!safePath.startsWith(ROOT_DIR)) {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end("403 Forbidden");
        return;
    }

    if (pathname === "/" || pathname === "") {
        safePath = path.join(ROOT_DIR, "index.html");
    }

    fs.stat(safePath, (err, stats) => {
        if (!err && stats.isFile()) {
            serveFile(safePath, res);
            return;
        }

        if (!err && stats.isDirectory()) {
            const indexFile = path.join(safePath, "index.html");
            if (fs.existsSync(indexFile)) {
                serveFile(indexFile, res);
                return;
            }
        }

        const htmlFallback = safePath + ".html";
        if (fs.existsSync(htmlFallback) && fs.statSync(htmlFallback).isFile()) {
            serveFile(htmlFallback, res);
            return;
        }

        const notFoundPath = path.join(ROOT_DIR, "index.html");
        if (fs.existsSync(notFoundPath)) {
            serveFile(notFoundPath, res);
            return;
        }

        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("404 Not Found");
    });
};

function serveFile(filePath, res) {
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(500, { "Content-Type": "text/plain" });
            res.end("500 Internal Server Error");
            return;
        }
        res.writeHead(200, {
            "Content-Type": contentType,
            "Cache-Control": "no-cache, no-store, must-revalidate"
        });
        res.end(data);
    });
}

function startServer(port) {
    const srv = http.createServer(requestHandler);

    srv.on("error", (err) => {
        if (err.code === "EADDRINUSE") {
            console.warn(`⚠️  Port ${port} is in use, trying port ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error("❌ Server error:", err);
        }
    });

    srv.listen(port, HOST, () => {
        const displayHost = HOST === "0.0.0.0" ? "localhost" : HOST;
        console.log("\n" + "=".repeat(62));
        console.log("🛡️  ByteTrail SOC Threat Intelligence Platform Frontend");
        console.log("=".repeat(62));
        console.log(`🌐 Server running at: http://${displayHost}:${port}`);
        console.log(`🚀 Landing Page:      http://${displayHost}:${port}/index.html`);
        console.log(`📊 SOC Dashboard:     http://${displayHost}:${port}/dashboard.html`);
        console.log(`🔐 Login Portal:      http://${displayHost}:${port}/login.html`);
        console.log(`📡 Cloud API Base:    https://bytetrail.onrender.com`);
        console.log("⚡ Hot-reload active with nodemon");
        console.log("=".repeat(62) + "\n");
    });

    return srv;
}

const currentServer = startServer(Number(PORT));

module.exports = currentServer;
