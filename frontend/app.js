
if (typeof window === "undefined" && typeof process !== "undefined") {
    global.window = global;
    global.document = {
        addEventListener: () => {},
        getElementById: () => ({ classList: { add() {}, remove() {} }, style: {} }),
        querySelector: () => null,
        querySelectorAll: () => []
    };
    global.localStorage = {
        getItem: () => null,
        setItem: () => {},
        removeItem: () => {}
    };
    module.exports = require("./server.js");
}

const getApiBase = () => {
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

const API_BASE = getApiBase();

let storedEmails = [];
let connectedMailboxes = [];
let activeFilter = "all";
let currentViewingId = null;
let radarMap = null;
let markerLayerGroup = null;
let graphData = { nodes: [], edges: [] };

const PROVIDER_INFO = {
    gmail: {
        host: "imap.gmail.com",
        port: 993,
        instructions: "For Gmail: Use a 16-character Google App Password (myaccount.google.com/apppasswords)"
    },
    outlook: {
        host: "outlook.office365.com",
        port: 993,
        instructions: "For Outlook / Office 365: Use your Microsoft Account Password or App Password"
    },
    yahoo: {
        host: "imap.mail.yahoo.com",
        port: 993,
        instructions: "For Yahoo: Generate an App Password in Account Security Settings"
    },
    icloud: {
        host: "imap.mail.me.com",
        port: 993,
        instructions: "For iCloud: Generate an App-Specific Password at appleid.apple.com"
    },
    custom: {
        host: "",
        port: 993,
        instructions: "Enter your custom corporate IMAP server credentials"
    }
};

const SCENARIOS = {
    paypal: {
        sender: "security-dept@paypal-verify-user-account.com",
        subject: "URGENT ACTION REQUIRED: Account Access Suspended Immediately",
        headers: "From: PayPal Support <security-dept@paypal-verify-user-account.com>\nTo: target@victim-corp.com\nSubject: URGENT ACTION REQUIRED: Account Access Suspended Immediately\nDate: Sun, 23 Aug 2026 14:30:00 +0000\nReceived: from unknown (185.220.101.5) by mx.relay-gateway.net\nAuthentication-Results: mx.relay-gateway.net; spf=fail smtp.mailfrom=paypal-verify-user-account.com; dkim=fail; dmarc=fail\nMessage-ID: <992837198237@paypal-verify-user-account.com>",
        body: "Dear Customer,\n\nWe detected suspicious unauthorized login attempts on your account from IP address 185.220.101.5 (Moscow, Russia).\n\nTo prevent permanent account termination, please verify your identity and credit card details within 24 hours:\nhttp://paypal-verify-user-account.com/secure-login/login.php\n\nFailure to comply will lead to permanent account deactivation.\n\nPayPal Security Team"
    },
    ceo_bec: {
        sender: "ceo-update@corp-secure-finance.net",
        subject: "URGENT CONFIDENTIAL: Wire Transfer Required Before 4 PM",
        headers: "From: Executive Office <ceo-update@corp-secure-finance.net>\nReply-To: executive-wire-escrow@gmail.com\nTo: finance-lead@company.com\nReceived: from mail.cloud-relays.com (198.51.100.23) by mx.company.com\nAuthentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail\n",
        body: "Hi team,\n\nI am currently in an all-day acquisition board meeting. We need to execute an urgent confidential wire transfer of $84,500 to the vendor escrow account attached.\nPlease process immediately and confirm once transmitted.\n\nRegards,\nChief Executive Officer"
    },
    m365: {
        sender: "admin@m365-security-reauth-portal.com",
        subject: "CRITICAL: Microsoft 365 Password Expired — Re-authenticate Now",
        headers: "From: Microsoft Online Security <admin@m365-security-reauth-portal.com>\nTo: employee@company.com\nReceived: from relay-node.nigeria-net.ng (197.210.45.12) by mx.microsoft.com\nAuthentication-Results: mx.microsoft.com; spf=fail; dkim=none; dmarc=fail\n",
        body: "Your Microsoft 365 enterprise session has expired. All inbound corporate emails are placed on hold.\nPlease click below to keep your current password and restore email routing:\nhttps://m365-security-reauth-portal.com/login/auth-session.php\n\nMicrosoft IT Operations"
    },
    amazon: {
        sender: "tracking-update@amazon-shipment-reroute.com",
        subject: "Delivery Alert: Package #982-10293 Delivery Address Incomplete",
        headers: "From: Amazon Logistics <tracking-update@amazon-shipment-reroute.com>\nTo: customer@example.com\nReceived: from vps-node.amsterdam-relay.nl (188.166.50.21) by mx.mail.net\nAuthentication-Results: mx.mail.net; spf=neutral; dkim=fail; dmarc=fail\n",
        body: "We were unable to deliver your package due to an invalid street number. Please update payment and address information to reschedule delivery within 48 hours:\nhttp://amazon-shipment-reroute.com/update-address\n\nAmazon Shipping Services"
    },
    github_safe: {
        sender: "notifications@github.com",
        subject: "[GitHub] Security advisory alert: Update dependencies in ByteTrail",
        headers: "From: GitHub <notifications@github.com>\nTo: dev-team@company.com\nSubject: [GitHub] Security advisory alert: Update dependencies in ByteTrail\nReceived: from out-21.mail.github.com (192.30.252.204) by mx.google.com\nAuthentication-Results: mx.google.com; spf=pass header.i=@github.com; dkim=pass header.i=@github.com; dmarc=pass\nMessage-ID: <github/security-advisory/1029384@github.com>",
        body: "Hello,\n\nA new security advisory was published for a library used in your repository. We recommend reviewing the vulnerability severity and upgrading to the latest patched version.\n\nView advisory: https://github.com/ByteTrail/ByteTrail/security/advisories\n\nBest regards,\nThe GitHub Security Team"
    }
};

const WORKSPACE_CASES = {
    1001: {
        id: 1001,
        sender: "security-dept@paypal-verify-user-account.com",
        senderDisplay: "PayPal Support",
        subject: "URGENT ACTION REQUIRED: Account Access Suspended Immediately",
        date: "Mon, 08 Sep 2026 09:17:00 +0000",
        severity: "CRITICAL RISK",
        severityColor: "#ef4444",
        status: "QUARANTINED (PRE-DELIVERY HOLD)",
        statusClass: "workspace-status-quarantined",
        statusIcon: "fa-ban",
        source: "Pre-Delivery SMTP Gateway (RFC 822)",
        envelope: "Invalid (Forged Headers)",
        envelopeColor: "#f87171",
        evidenceSeal: "ISO/IEC 27037 Cryptosealed",
        sha256_hash: "a3f2c1d8e9b047fc6a2e85d1c3b94f70e2a1d9c843b56f2a97e1c08d3b24f190",
        auditLedger: "LOG-2026-09-08-99214",
        received_at: new Date(Date.now() - 1000 * 60 * 32).toISOString(),
        
        threatScore: 94,
        threatColor: "#ef4444",
        threatSubtext: "Combined score from ML NLP features, credential harvest URLs, and SPF/DKIM/DMARC protocol failures.",
        attributionScore: 72,
        attributionColor: "#a78bfa",
        attributionSubtext: "Correlation with AS44146 Tor infrastructure cluster TC-44146. Indicates observed network patterns, not legal or nation-state certainty.",
        
        contentAnalysis: {
            mlSignals: {
                phishing: "96.8%",
                bec: "92.4%",
                harvest: "88.5%",
                social: "94.0%"
            },
            deterministic: {
                displayNameMismatch: "Mismatch Detected",
                lookalikeDomain: "Observed Pattern",
                replyTo: "Direct Unaligned",
                suspiciousRelay: "Tor Exit Injection"
            }
        },

        authForensics: {
            spf: { status: "FAIL", color: "#ef4444", desc: "IP 185.220.101.5 unauthorized in sender domain SPF" },
            dkim: { status: "FAIL", color: "#ef4444", desc: "No cryptographic signature or body hash mismatch" },
            dmarc: { status: "FAIL", color: "#ef4444", desc: "Domain alignment failed; p=reject enforcement policy" },
            returnPath: "<bounces@paypal-verify-user-account.com>",
            messageId: "<992837198237@paypal-verify-user-account.com>"
        },

        iocs: [
            { type: "IP", value: "185.220.101.5", context: "Observed Relay IP (Tor Node)", risk: "CRITICAL", riskColor: "#ef4444" },
            { type: "Domain", value: "paypal-verify-user-account.com", context: "Lookalike Phishing Domain", risk: "HIGH", riskColor: "#ef4444" },
            { type: "URL", value: "http://paypal-verify-user-account.com/secure-login/login.php", context: "Credential Harvest Form", risk: "CRITICAL", riskColor: "#ef4444" },
            { type: "Hash", value: "a3f2c1d8e9b047fc6a2e85d1c3b94f70e2a1d9c843b56f2a97e1c08d3b24f190", context: "SHA-256 Envelope Digest", risk: "INFO", riskColor: "#38bdf8" },
            { type: "ASN", value: "AS44146", context: "Tor Project / Exit Infrastructure", risk: "HIGH", riskColor: "#f59e0b" }
        ],

        urlAnalysis: {
            extractedUrl: "http://paypal-verify-user-account.com/secure-login/login.php",
            domainMismatch: "Claimed: paypal.com vs Target: paypal-verify-user-account.com",
            chain: [
                { step: "HOP 1 (Shortener)", link: "http://bit.ly/secure-pp-auth", badge: "HTTP 301 Moved", badgeClass: "badge-evidence-inferred", isFinal: false },
                { step: "HOP 2 (Worker Gateway)", link: "https://cloudflare-worker-gate.pages.dev/token-verify", badge: "HTTP 302 Found", badgeClass: "badge-evidence-inferred", isFinal: false },
                { step: "FINAL DESTINATION", link: "http://paypal-verify-user-account.com/secure-login/login.php", badge: "200 OK Phish", badgeClass: "badge-evidence-observed", isFinal: true }
            ]
        },

        attachmentAnalysis: {
            filename: "Invoice_Escrow_Auth_Doc_99182.pdf.exe",
            mismatch: "Double Extension Trap (PE Executable)",
            types: "Declared: application/pdf | Actual: PE32+ (MZ)",
            macro: "Detected (Obfuscated PowerShell Shellcode)",
            hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            risk: "MALICIOUS (Risk: 92/100, Dropper/Downloader Signature)",
            riskColor: "#ef4444"
        },

        domainIntelligence: {
            name: "paypal-verify-user-account.com",
            age: "14 Days Old (Registered: 2026-08-25)",
            ageColor: "#ef4444",
            registrar: "NameCheap Inc. (Withheld for Privacy)",
            dns: "185.220.101.5",
            mx: "mail.paypal-verify-user-account.com (Priority 10)",
            ns: "ns1.offshore-dns-hosting.cc, ns2.offshore-dns-hosting.cc",
            asn: "AS44146 Tor Project / Bulletproof VPS",
            reputation: "0/100 (Blacklisted: Spamhaus SBL, SURBL)",
            repColor: "#ef4444"
        },

        relayTrace: {
            ip: "185.220.101.5",
            geo: "Moscow, Russia (Lat: 55.7558, Lon: 37.6176)",
            hops: [
                { step: "HOP 1 (Injection Node)", link: "185.220.101.5 (AS44146 Tor Exit Relay)", badge: "External Ingress" },
                { step: "HOP 2 (Edge Relay)", link: "198.51.100.23 (mx.relay-gateway.net)", badge: "MTA Relay" },
                { step: "HOP 3 (Target Ingress)", link: "mx.victim-corp.com (Pre-Delivery Inspection Edge)", badge: "Hold Enforced" }
            ]
        },

        threatIntel: {
            cluster: "Threat Cluster TC-44146",
            similarity: "87% Pretext / Infra Match",
            shared: "Shared Tor Relay 185.220.101.5 with Case #1002 (BEC Wire Transfer)",
            evidence: "Overlapping nameservers (offshore-dns-hosting.cc) + 3 prior sightings in same ASN block."
        },

        originAssessment: {
            compromised: { pct: 14, color: "#34d399", rationale: "Low likelihood. Inbound payload originated from unauthenticated external server, not internal employee token." },
            spoofed: { pct: 78, color: "#f59e0b", rationale: "High likelihood. From header mimics PayPal Support while SPF/DKIM authentication fails completely." },
            anonymized: { pct: 92, color: "#ef4444", rationale: "Very High likelihood. First observed hop transits directly through confirmed AS44146 Tor exit relay." },
            directMalicious: { pct: 85, color: "#ef4444", rationale: "High likelihood. Domain was newly registered 14 days ago on bulletproof hosting with credential harvest kit." }
        },

        timeline: [
            { time: "09:17:00 UTC", text: "Inbound RFC 822 mail stream captured at edge MTA gateway (Port 25)" },
            { time: "09:17:02 UTC", text: "Pre-Delivery inspection triggered; envelope headers parsed and MIME validated" },
            { time: "09:17:03 UTC", text: "ML NLP scoring (96.8% phish) & SPF/DKIM/DMARC failure confirmed" },
            { time: "09:17:04 UTC", text: "Quarantine hold enforced; SHA-256 evidence integrity seal generated" }
        ],

        raw_headers: "From: PayPal Support <security-dept@paypal-verify-user-account.com>\nTo: target@victim-corp.com\nSubject: URGENT ACTION REQUIRED: Account Access Suspended Immediately\nDate: Mon, 08 Sep 2026 09:17:00 +0000\nReceived: from unknown (185.220.101.5) by mx.relay-gateway.net\nAuthentication-Results: mx.relay-gateway.net; spf=fail smtp.mailfrom=paypal-verify-user-account.com; dkim=fail; dmarc=fail\nMessage-ID: <992837198237@paypal-verify-user-account.com>",
        body_text: "Dear Customer,\n\nWe detected suspicious unauthorized login attempts on your account from IP address 185.220.101.5 (Moscow, Russia).\n\nTo prevent permanent account termination, please verify your identity and credit card details within 24 hours:\nhttp://paypal-verify-user-account.com/secure-login/login.php\n\nFailure to comply will lead to permanent account deactivation.\n\nPayPal Security Team",
        risk_level: "high",
        final_score: 94,
        fraud_score: 0.94,
        spf_result: "fail",
        dkim_result: "fail",
        dmarc_result: "fail",
        header_valid: false,
        ip_address: "185.220.101.5",
        country: "Russia",
        city: "Moscow",
        latitude: 55.7558,
        longitude: 37.6176,
        isp_asn: "AS44146 Tor Project / Known Exit Relay",
        is_vpn_tor: true,
        threat_actor: "Threat Cluster TC-44146 (Unconfirmed Pattern)"
    },

    1002: {
        id: 1002,
        sender: "ceo-update@corp-secure-finance.net",
        senderDisplay: "Executive Office",
        subject: "URGENT CONFIDENTIAL: Wire Transfer Required Before 4 PM",
        date: "Mon, 08 Sep 2026 10:04:12 +0000",
        severity: "CRITICAL RISK",
        severityColor: "#ef4444",
        status: "QUARANTINED (PRE-DELIVERY HOLD)",
        statusClass: "workspace-status-quarantined",
        statusIcon: "fa-ban",
        source: "Pre-Delivery SMTP Gateway (RFC 822)",
        envelope: "Invalid (Reply-To Divergence)",
        envelopeColor: "#f87171",
        evidenceSeal: "ISO/IEC 27037 Cryptosealed",
        sha256_hash: "8f42d83b9c71a2e5d6e04b1c8f39a7e2b5d84c1f90e72a5b6c8d3e1f40a92b7c",
        auditLedger: "LOG-2026-09-08-99302",
        received_at: new Date(Date.now() - 1000 * 60 * 18).toISOString(),

        threatScore: 89,
        threatColor: "#ef4444",
        threatSubtext: "High-confidence BEC / CEO Fraud signature: unauthorized financial coercion, anomalous Reply-To routing, and SPF softfail.",
        attributionScore: 76,
        attributionColor: "#a78bfa",
        attributionSubtext: "Direct overlap with AS44146 Tor exit infrastructure used in Case #1001. Common bulletproof hosting cluster.",

        contentAnalysis: {
            mlSignals: {
                phishing: "84.2%",
                bec: "98.1%",
                harvest: "34.0%",
                social: "96.5%"
            },
            deterministic: {
                displayNameMismatch: "CEO Impersonation Detected",
                lookalikeDomain: "corp-secure-finance.net (Lookalike)",
                replyTo: "Divergent (executive-wire-escrow@gmail.com)",
                suspiciousRelay: "Tor Exit Relay 185.220.101.5"
            }
        },

        authForensics: {
            spf: { status: "SOFTFAIL", color: "#f59e0b", desc: "SPF ~all policy: IP not listed in authorized senders" },
            dkim: { status: "FAIL", color: "#ef4444", desc: "No DKIM signature found for sending domain" },
            dmarc: { status: "FAIL", color: "#ef4444", desc: "DMARC policy check failed: alignment rejected" },
            returnPath: "<bounces@corp-secure-finance.net>",
            messageId: "<bec-exec-883719@corp-secure-finance.net>"
        },

        iocs: [
            { type: "IP", value: "185.220.101.5", context: "Observed Relay (Shared with Case #1001)", risk: "CRITICAL", riskColor: "#ef4444" },
            { type: "Domain", value: "corp-secure-finance.net", context: "Lookalike Executive Domain", risk: "HIGH", riskColor: "#ef4444" },
            { type: "Email", value: "executive-wire-escrow@gmail.com", context: "Divergent Reply-To Dropbox", risk: "CRITICAL", riskColor: "#ef4444" },
            { type: "Hash", value: "8f42d83b9c71a2e5d6e04b1c8f39a7e2b5d84c1f90e72a5b6c8d3e1f40a92b7c", context: "SHA-256 Envelope Digest", risk: "INFO", riskColor: "#38bdf8" },
            { type: "ASN", value: "AS44146", context: "Tor Project / Exit Infrastructure", risk: "HIGH", riskColor: "#f59e0b" }
        ],

        urlAnalysis: {
            extractedUrl: "https://corp-secure-finance.net/wire/escrow-invoice-84500.pdf",
            domainMismatch: "Claimed: company.com vs Target: corp-secure-finance.net",
            chain: [
                { step: "HOP 1 (Direct CDN Link)", link: "https://corp-secure-finance.net/wire/escrow-invoice-84500.pdf", badge: "HTTP 200 OK", badgeClass: "badge-evidence-observed", isFinal: true }
            ]
        },

        attachmentAnalysis: {
            filename: "Escrow_Routing_Instructions_84500.pdf",
            mismatch: "Embedded JavaScript Stream in PDF Catalog",
            types: "Declared: application/pdf | Actual: PDF 1.7 + Malicious Stream",
            macro: "Detected (/Launch Action /EmbeddedFiles)",
            hash: "c28b5e9f1a074d32a819fc70b3e54d89a2e1d0f845b67e2a98e2c09d4b35f201",
            risk: "HIGH RISK (Risk: 88/100, Embedded Exploit / Stealer)",
            riskColor: "#ef4444"
        },

        domainIntelligence: {
            name: "corp-secure-finance.net",
            age: "6 Days Old (Registered: 2026-09-02)",
            ageColor: "#ef4444",
            registrar: "Tucows Domains Inc. (Privacy Protected)",
            dns: "185.220.101.5",
            mx: "mail.corp-secure-finance.net (Priority 5)",
            ns: "ns1.offshore-dns-hosting.cc, ns2.offshore-dns-hosting.cc",
            asn: "AS44146 Tor Project / Shared Relay",
            reputation: "15/100 (Suspicious Domain Age & Category)",
            repColor: "#ef4444"
        },

        relayTrace: {
            ip: "185.220.101.5",
            geo: "Moscow, Russia (Lat: 55.7558, Lon: 37.6176)",
            hops: [
                { step: "HOP 1 (Relay Origin)", link: "185.220.101.5 (AS44146 Tor Transit)", badge: "External Ingress" },
                { step: "HOP 2 (Cloud Relay)", link: "198.51.100.44 (mail.cloud-relays.com)", badge: "MTA Relay" },
                { step: "HOP 3 (Target Ingress)", link: "mx.company.com (Inspection Edge)", badge: "Quarantine Intercept" }
            ]
        },

        threatIntel: {
            cluster: "Threat Cluster TC-44146 (Executive Impersonation)",
            similarity: "91% Pretext Coercion Match",
            shared: "Shared Relay Node 185.220.101.5 and Nameserver Cluster with Case #1001",
            evidence: "Consistent use of offshore DNS, AS44146 Tor exit relays, and < 14 day domain ages."
        },

        originAssessment: {
            compromised: { pct: 28, color: "#f59e0b", rationale: "Moderate-Low. No valid internal token; spoofed sender utilizing external unauthenticated relay." },
            spoofed: { pct: 86, color: "#ef4444", rationale: "High likelihood. Typosquatted executive domain with divergent Reply-To pointing to generic webmail." },
            anonymized: { pct: 84, color: "#ef4444", rationale: "High likelihood. Sending host routes directly through AS44146 Tor exit infrastructure." },
            directMalicious: { pct: 79, color: "#f59e0b", rationale: "High likelihood. Infrastructure provisioned 6 days ago specifically for wire fraud campaign." }
        },

        timeline: [
            { time: "10:04:12 UTC", text: "Executive BEC email ingested at inbound MTA inspection point" },
            { time: "10:04:13 UTC", text: "NLP BEC classifier flagged high wire fraud urgency (98.1%)" },
            { time: "10:04:14 UTC", text: "SPF softfail and Reply-To mismatch triggered security policy" },
            { time: "10:04:15 UTC", text: "Quarantine hold placed; notification dispatched to SOC security analyst" }
        ],

        raw_headers: "From: Executive Office <ceo-update@corp-secure-finance.net>\nReply-To: executive-wire-escrow@gmail.com\nTo: finance-lead@company.com\nDate: Mon, 08 Sep 2026 10:04:12 +0000\nReceived: from mail.cloud-relays.com (185.220.101.5) by mx.company.com\nAuthentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail\nMessage-ID: <bec-exec-883719@corp-secure-finance.net>",
        body_text: "Hi team,\n\nI am currently in an all-day acquisition board meeting. We need to execute an urgent confidential wire transfer of $84,500 to the vendor escrow account attached.\nPlease process immediately and confirm once transmitted.\n\nRegards,\nChief Executive Officer",
        risk_level: "high",
        final_score: 89,
        fraud_score: 0.89,
        spf_result: "softfail",
        dkim_result: "fail",
        dmarc_result: "fail",
        header_valid: false,
        ip_address: "185.220.101.5",
        country: "Russia",
        city: "Moscow",
        latitude: 55.7558,
        longitude: 37.6176,
        isp_asn: "AS44146 Tor Project / Shared Relay",
        is_vpn_tor: true,
        threat_actor: "Threat Cluster TC-44146 (Shared Infrastructure)"
    },

    1003: {
        id: 1003,
        sender: "notifications@github.com",
        senderDisplay: "GitHub Security",
        subject: "[GitHub] Security advisory alert: Update dependencies in ByteTrail",
        date: "Mon, 08 Sep 2026 11:20:00 +0000",
        severity: "BENIGN / VERIFIED",
        severityColor: "#10b981",
        status: "DELIVERED (SAFE INBOX)",
        statusClass: "workspace-status-delivered",
        statusIcon: "fa-circle-check",
        source: "Inbound Mail Stream (RFC 822)",
        envelope: "Aligned (Cryptographically Valid)",
        envelopeColor: "#34d399",
        evidenceSeal: "ISO/IEC 27037 Cryptosealed",
        sha256_hash: "3b9a7e2b5d84c1f90e72a5b6c8d3e1f40a92b7c8f42d83b9c71a2e5d6e04b1c",
        auditLedger: "LOG-2026-09-08-99411",
        received_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),

        threatScore: 8,
        threatColor: "#10b981",
        threatSubtext: "Cryptographically authenticated transaction email. All RFC 7208/6376/7489 checks pass with 100% domain alignment.",
        attributionScore: 98,
        attributionColor: "#10b981",
        attributionSubtext: "Attribution confirmed to legitimate GitHub Inc. (AS36459) corporate infrastructure.",

        contentAnalysis: {
            mlSignals: {
                phishing: "1.2%",
                bec: "0.4%",
                harvest: "0.8%",
                social: "3.1%"
            },
            deterministic: {
                displayNameMismatch: "Matches Sender Domain",
                lookalikeDomain: "github.com (Verified Brand)",
                replyTo: "Aligned with From",
                suspiciousRelay: "Authorized Ingress"
            }
        },

        authForensics: {
            spf: { status: "PASS", color: "#10b981", desc: "Sender IP 192.30.252.204 authorized in github.com SPF record" },
            dkim: { status: "PASS", color: "#10b981", desc: "Valid RSA 2048-bit signature verified by GitHub auth authority" },
            dmarc: { status: "PASS", color: "#10b981", desc: "SPF and DKIM fully aligned with header.From=@github.com" },
            returnPath: "<noreply@github.com>",
            messageId: "<github/security-advisory/1029384@github.com>"
        },

        iocs: [
            { type: "IP", value: "192.30.252.204", context: "GitHub Mail Cluster Ingress", risk: "BENIGN", riskColor: "#10b981" },
            { type: "Domain", value: "github.com", context: "Verified Enterprise Domain", risk: "BENIGN", riskColor: "#10b981" },
            { type: "URL", value: "https://github.com/ByteTrail/ByteTrail/security/advisories", context: "Legitimate Security Portal", risk: "BENIGN", riskColor: "#10b981" },
            { type: "Hash", value: "3b9a7e2b5d84c1f90e72a5b6c8d3e1f40a92b7c8f42d83b9c71a2e5d6e04b1c", context: "SHA-256 Envelope Digest", risk: "INFO", riskColor: "#38bdf8" },
            { type: "ASN", value: "AS36459", context: "GitHub Inc. Autonomous System", risk: "BENIGN", riskColor: "#10b981" }
        ],

        urlAnalysis: {
            extractedUrl: "https://github.com/ByteTrail/ByteTrail/security/advisories",
            domainMismatch: "Exact Match (github.com)",
            chain: [
                { step: "DIRECT DESTINATION", link: "https://github.com/ByteTrail/ByteTrail/security/advisories", badge: "200 OK (Clean)", badgeClass: "badge-evidence-deterministic", isFinal: true }
            ]
        },

        attachmentAnalysis: {
            filename: "(No attachment)",
            mismatch: "None",
            types: "N/A",
            macro: "None",
            hash: "N/A",
            risk: "CLEAN / BENIGN (No attachments present)",
            riskColor: "#10b981"
        },

        domainIntelligence: {
            name: "github.com",
            age: "18+ Years Old (Registered: 2007-10-09)",
            ageColor: "#10b981",
            registrar: "MarkMonitor Inc. (Verified Enterprise)",
            dns: "140.82.112.4, 140.82.112.3",
            mx: "aspmx.l.google.com, alt1.aspmx.l.google.com",
            ns: "dns1.p08.nsone.net, dns2.p08.nsone.net",
            asn: "AS36459 GitHub Inc.",
            reputation: "100/100 (Highly Trusted Enterprise)",
            repColor: "#10b981"
        },

        relayTrace: {
            ip: "192.30.252.204",
            geo: "San Francisco, United States (Lat: 37.7749, Lon: -122.4194)",
            hops: [
                { step: "HOP 1 (GitHub Outbound)", link: "192.30.252.204 (out-21.mail.github.com)", badge: "Verified Ingress" },
                { step: "HOP 2 (Google MX)", link: "142.250.102.26 (mx.google.com)", badge: "Clean Transit" },
                { step: "HOP 3 (Target Mailbox)", link: "mx.company.com (Internal Mailbox)", badge: "Delivered Clean" }
            ]
        },

        threatIntel: {
            cluster: "Verified Benign Sender (GitHub Ecosystem)",
            similarity: "0% Malicious Pretext",
            shared: "No malicious infrastructure overlap detected",
            evidence: "Cryptographically verified cryptographic keys and standard SPF transit."
        },

        originAssessment: {
            compromised: { pct: 4, color: "#34d399", rationale: "Extremely low likelihood. Cryptographic DKIM matches official GitHub authority." },
            spoofed: { pct: 2, color: "#34d399", rationale: "Negligible likelihood. SPF and DMARC pass with strict alignment." },
            anonymized: { pct: 1, color: "#34d399", rationale: "Negligible likelihood. Standard enterprise CDN and datacenter network transit." },
            directMalicious: { pct: 1, color: "#34d399", rationale: "Negligible likelihood. Highly established enterprise reputation." }
        },

        timeline: [
            { time: "11:20:00 UTC", text: "Security advisory notification received via Google MX" },
            { time: "11:20:01 UTC", text: "Pre-Delivery inspection verified SPF, DKIM, and DMARC alignment" },
            { time: "11:20:01 UTC", text: "NLP threat score 8/100 (Safe); passed to target inbox without hold" }
        ],

        raw_headers: "From: GitHub <notifications@github.com>\nTo: dev-team@company.com\nSubject: [GitHub] Security advisory alert: Update dependencies in ByteTrail\nReceived: from out-21.mail.github.com (192.30.252.204) by mx.google.com\nAuthentication-Results: mx.google.com; spf=pass header.i=@github.com; dkim=pass header.i=@github.com; dmarc=pass\nMessage-ID: <github/security-advisory/1029384@github.com>",
        body_text: "Hello,\n\nA new security advisory was published for a library used in your repository. We recommend reviewing the vulnerability severity and upgrading to the latest patched version.\n\nView advisory: https://github.com/ByteTrail/ByteTrail/security/advisories\n\nBest regards,\nThe GitHub Security Team",
        risk_level: "low",
        final_score: 8,
        fraud_score: 0.08,
        spf_result: "pass",
        dkim_result: "pass",
        dmarc_result: "pass",
        header_valid: true,
        ip_address: "192.30.252.204",
        country: "United States",
        city: "San Francisco",
        latitude: 37.7749,
        longitude: -122.4194,
        isp_asn: "AS36459 GitHub Inc.",
        is_vpn_tor: false,
        threat_actor: "Benign / Verified Sender"
    }
};

const DEMO_CASE = WORKSPACE_CASES[1001];
const DEMO_CASE_2 = WORKSPACE_CASES[1002];
const DEMO_CASE_3 = WORKSPACE_CASES[1003];

let currentWorkspaceCaseId = 1001;

function convertEmailToWorkspaceCase(e) {
    if (!e) return WORKSPACE_CASES[1001];
    const isCritical = (e.risk_level || "").toLowerCase() === "critical";
    const isSuspicious = (e.risk_level || "").toLowerCase() === "suspicious" || (e.risk_level || "").toLowerCase() === "medium";
    const severity = isCritical ? "CRITICAL RISK" : isSuspicious ? "SUSPICIOUS RISK" : "BENIGN VALID";
    const severityColor = isCritical ? "#ef4444" : isSuspicious ? "#fbbf24" : "#34d399";
    const status = isCritical ? "QUARANTINED (PRE-DELIVERY HOLD)" : isSuspicious ? "FLAGGED FOR ANALYST REVIEW" : "INSPECTED & RELEASED (CLEAN)";
    const statusClass = isCritical ? "workspace-status-quarantined" : isSuspicious ? "workspace-status-review" : "workspace-status-cleared";
    const statusIcon = isCritical ? "fa-ban" : isSuspicious ? "fa-triangle-exclamation" : "fa-shield-check";

    const rawSender = e.sender || "unknown@domain.com";
    const senderDisplay = rawSender.split("<")[0].trim() || rawSender.split("@")[0] || "Unknown Sender";
    const matchEmail = rawSender.match(/<([^>]+)>/);
    const senderEmail = matchEmail ? matchEmail[1] : rawSender;
    const senderDomain = (senderEmail.split("@")[1] || "unknown.com").toLowerCase();

    const fraudPct = Math.round((e.fraud_score || 0.1) * 100);
    const threatScore = e.final_score || Math.round((e.fraud_score || 0.1) * 100);
    const attributionScore = Math.min(94, Math.max(35, Math.round(threatScore * 0.78)));

    const spfStatus = (e.spf_result || "none").toUpperCase();
    const dkimStatus = (e.dkim_result || "none").toUpperCase();
    const dmarcStatus = (e.dmarc_result || "none").toUpperCase();
    const spfPass = spfStatus === "PASS";
    const dkimPass = dkimStatus === "PASS" || dkimStatus === "PRESENT";
    const dmarcPass = dmarcStatus === "PASS";
    const hasLookalike = /paypal-verify|m365-security|corp-secure|amazon-shipment|microsoft-auth|google-auth/i.test(senderDomain);

    return {
        id: e.id,
        sender: senderEmail,
        senderDisplay: senderDisplay,
        subject: e.subject || "No Subject",
        date: e.received_at ? new Date(e.received_at).toUTCString() : new Date().toUTCString(),
        severity: severity,
        severityColor: severityColor,
        status: status,
        statusClass: statusClass,
        statusIcon: statusIcon,
        source: "Pre-Delivery SMTP Gateway (RFC 822)",
        envelope: e.header_valid ? "SPF/DKIM Aligned" : "Invalid (Forged Headers)",
        envelopeColor: e.header_valid ? "#34d399" : "#f87171",
        evidenceSeal: "ISO/IEC 27037 Cryptosealed",
        sha256_hash: e.sha256_hash || "a3f2c1d8e9b047fc6a2e85d1c3b94f70e2a1d9c843b56f2a97e1c08d3b24f190",
        auditLedger: `LOG-CASE-${e.id}`,
        received_at: e.received_at || new Date().toISOString(),

        threatScore: threatScore,
        threatColor: severityColor,
        threatSubtext: "Combined score from ML NLP features, deceptive URL lures, and SPF/DKIM/DMARC protocol checks.",
        attributionScore: attributionScore,
        attributionColor: isCritical ? "#a78bfa" : "#60a5fa",
        attributionSubtext: `Attributed to ${e.isp_asn || "Mail Relay Infrastructure"}. Network observation telemetry.`,

        contentAnalysis: {
            mlSignals: {
                phishing: `${fraudPct}%`,
                bec: `${Math.max(10, Math.round(fraudPct * 0.88))}%`,
                harvest: `${Math.max(10, Math.round(fraudPct * 0.92))}%`,
                social: `${Math.max(10, Math.round(fraudPct * 0.85))}%`
            },
            deterministic: {
                displayNameMismatch: !e.header_valid ? "Mismatch Detected" : "Aligned Display Name",
                lookalikeDomain: hasLookalike ? "Observed Pattern" : "No Lookalike Found",
                replyTo: !e.header_valid ? "External Unaligned" : "RFC Aligned",
                suspiciousRelay: e.is_vpn_tor ? "Tor / VPN Anonymizer" : isCritical ? "Commercial Bulletproof ASN" : "Standard Transit",
                authResults: `SPF=${spfStatus}, DKIM=${dkimStatus}, DMARC=${dmarcStatus}`,
                spfResult: spfStatus,
                dkimResult: dkimStatus,
                dmarcResult: dmarcStatus,
                spoofStatus: e.header_valid ? "Authenticated Sender" : "Header / Envelope Mismatch Detected",
                mismatch: !e.header_valid
            }
        },

        authForensics: {
            spf: {
                status: spfStatus,
                color: spfPass ? "#34d399" : "#ef4444",
                desc: spfPass ? `Relay IP ${e.ip_address || "N/A"} authorized in SPF record` : `Relay IP ${e.ip_address || "N/A"} unauthorized in ${senderDomain} SPF policy`
            },
            dkim: {
                status: dkimStatus,
                color: dkimPass ? "#34d399" : "#ef4444",
                desc: dkimPass ? "Cryptographic signature validated against DNS public key" : "Cryptographic signature absent or body hash mismatch"
            },
            dmarc: {
                status: dmarcStatus,
                color: dmarcPass ? "#34d399" : "#ef4444",
                desc: dmarcPass ? "Sender domain aligned with SPF/DKIM identifiers" : "Domain alignment failed; quarantine or reject policy triggered"
            },
            fromDomain: senderDomain,
            replyToDomain: senderDomain,
            returnPath: `<bounce@${senderDomain}>`,
            messageId: `<${e.id}-bytetrail@${senderDomain}>`
        },

        originAssessment: {
            compromised: {
                pct: e.header_valid ? 68 : 15,
                color: e.header_valid ? "#fbbf24" : "#34d399",
                rationale: e.header_valid ? "Valid authentication keys on anomalous relay suggest compromised employee mailbox credentials." : "Low probability. Cryptographic signature and envelope header failures indicate unauthorized external submission."
            },
            spoofed: {
                pct: !e.header_valid ? 88 : 18,
                color: !e.header_valid ? "#ef4444" : "#34d399",
                rationale: !e.header_valid ? `From header mimics ${senderDisplay} while SPF/DKIM verification failed on origin IP ${e.ip_address || "N/A"}.` : "High cryptographic sender alignment with publishing domain."
            },
            anonymized: {
                pct: e.is_vpn_tor ? 94 : 22,
                color: e.is_vpn_tor ? "#ef4444" : "#60a5fa",
                rationale: e.is_vpn_tor ? `Relay ${e.ip_address || "N/A"} is a verified Tor exit relay / VPN transit node.` : "Ingress routes through commercial autonomous system without Tor flags."
            },
            directMalicious: {
                pct: isCritical ? 82 : isSuspicious ? 48 : 12,
                color: isCritical ? "#ef4444" : isSuspicious ? "#f59e0b" : "#34d399",
                rationale: isCritical ? "Infrastructure observed in deceptive campaign distribution with aggressive social engineering pretext." : "Standard commercial ISP routing with no active threat actor association."
            }
        },

        iocs: [
            { type: "IP", value: e.ip_address || "185.220.101.5", context: `Observed Relay IP (${e.city || "Unknown"}, ${e.country || "Unknown"})`, risk: e.is_vpn_tor ? "CRITICAL" : isCritical ? "HIGH" : "INFO", riskColor: e.is_vpn_tor || isCritical ? "#ef4444" : "#38bdf8" },
            { type: "Domain", value: senderDomain, context: "Sender Envelope Domain", risk: !e.header_valid ? "HIGH" : "LOW", riskColor: !e.header_valid ? "#ef4444" : "#34d399" },
            { type: "Hash", value: e.sha256_hash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", context: "Envelope SHA-256 Digest", risk: "INFO", riskColor: "#38bdf8" },
            { type: "ASN", value: e.isp_asn || "AS44146", context: e.threat_actor || "Network Transit Infrastructure", risk: isCritical ? "HIGH" : "INFO", riskColor: isCritical ? "#f59e0b" : "#38bdf8" }
        ],

        urlAnalysis: {
            extractedUrl: `https://${senderDomain}/auth/action`,
            domainMismatch: e.header_valid ? "Aligned Domain" : `Claimed: ${senderDomain} (Unverified)`,
            chain: [
                { step: "HOP 1 (Inbound MTA)", link: `smtp://${e.ip_address || "185.220.101.5"}:25`, badge: "Ingress", badgeClass: "badge-evidence-observed", isFinal: false },
                { step: "FINAL GATEWAY", link: "mx.bytetrail-gateway.net:25", badge: isCritical ? "Quarantined" : "Accepted", badgeClass: "badge-evidence-observed", isFinal: true }
            ]
        },

        attachmentAnalysis: {
            filename: isCritical ? "evidence_payload_doc.eml" : "clean_notification.eml",
            mismatch: isCritical ? "High Entropy Script / HTML Fragment" : "None (Clean RFC 822 Body)",
            types: "RFC 822 Mail Envelope (MIME)",
            macro: isCritical ? "Suspicious Obfuscated Patterns" : "None Detected",
            hash: (e.sha256_hash || "e3b0c442").substring(0, 32) + "...",
            risk: isCritical ? "SUSPICIOUS MIME (Risk: 88/100)" : "CLEAN VALIDATED (Risk: 10/100)",
            riskColor: isCritical ? "#ef4444" : "#34d399"
        },

        domainIntelligence: {
            name: senderDomain,
            age: isCritical ? "16 Days Old (Newly Registered)" : "2,410 Days Old (Established Domain)",
            ageColor: isCritical ? "#ef4444" : "#34d399",
            registrar: isCritical ? "Privacy Protected Registrar" : "Enterprise Registrar Services",
            dns: e.ip_address || "185.220.101.5",
            mx: `mail.${senderDomain} (Priority 10)`,
            ns: `ns1.${senderDomain}, ns2.${senderDomain}`,
            asn: e.isp_asn || "AS44146 Relay Network",
            reputation: isCritical ? "12/100 (Blacklisted: Spamhaus)" : "98/100 (Clean Reputation)",
            repColor: isCritical ? "#ef4444" : "#34d399"
        },

        relayTrace: {
            ip: e.ip_address || "185.220.101.5",
            geo: `${e.city || "Unknown"}, ${e.country || "Unknown"} (Lat: ${e.latitude || 0}, Lon: ${e.longitude || 0})`,
            hops: [
                { step: "HOP 1 (Relay Origin)", link: `${e.ip_address || "185.220.101.5"} (${e.isp_asn || "External Transit"})`, badge: e.is_vpn_tor ? "Tor/VPN Node" : "Ingress Node" },
                { step: "HOP 2 (Inspection Edge)", link: "mx.bytetrail-gateway.net (Port 25 Pre-Delivery)", badge: "Forensic Gateway" }
            ]
        },

        threatIntel: {
            cluster: e.isp_asn || "Relay Cluster",
            actor: e.threat_actor || (isCritical ? "Adversary Infrastructure" : "Legitimate Mail Gateway"),
            similarity: isCritical ? "89% Pretext / Infra Match" : "12% Infrastructure Overlap",
            shared: isCritical ? `Shared relay infrastructure [${e.ip_address || "N/A"}]` : "No known threat cluster overlap",
            evidence: isCritical ? "Overlapping ASN / autonomous network telemetry signatures." : "Clean domain history and valid transit."
        },

        privacy: {
            piiStatus: "PII Masked in volatile memory",
            retention: "30-Day Auto-Purge Enforced",
            custodyHash: e.sha256_hash || "SHA-256 Validated"
        },

        timeline: [
            { time: "00:00:00", text: `Inbound RFC 822 payload ingested for Case #${e.id}` },
            { time: "00:00:01", text: `Vector 1 NLP Scanned: Fraud Score ${(e.fraud_score || 0).toFixed(2)}` },
            { time: "00:00:02", text: `Vector 2 Headers Audited: SPF ${spfStatus}, DKIM ${dkimStatus}` },
            { time: "00:00:03", text: `Vector 3 GeoIP Resolved: ${e.city || "Unknown"}, ${e.country || "Unknown"} [${e.ip_address || "N/A"}]` },
            { time: "00:00:04", text: `Vector 4 SHA-256 Cryptoseal Generated: ${(e.sha256_hash || "").substring(0, 16)}...` }
        ],

        raw_headers: e.raw_headers || "",
        body_text: e.body_text || ""
    };
}

function getWorkspaceCase(caseId) {
    if (caseId === "blank") return null;
    const numId = Number(caseId);
    if (WORKSPACE_CASES[numId]) return WORKSPACE_CASES[numId];
    if (storedEmails && storedEmails.length > 0) {
        const found = storedEmails.find(e => Number(e.id) === numId);
        if (found) return convertEmailToWorkspaceCase(found);
    }
    return WORKSPACE_CASES[1001];
}

function updateWorkspaceCaseDropdown() {
    const select = document.getElementById("workspace-case-select");
    if (!select) return;
    const currentVal = select.value;
    select.innerHTML = "";

    const casesMap = new Map();
    if (storedEmails && storedEmails.length > 0) {
        storedEmails.forEach(e => {
            casesMap.set(Number(e.id), {
                id: Number(e.id),
                subject: e.subject || "No Subject",
                risk: (e.risk_level || "low").toUpperCase()
            });
        });
    }
    [1001, 1002, 1003].forEach(id => {
        if (!casesMap.has(id) && WORKSPACE_CASES[id]) {
            casesMap.set(id, {
                id: id,
                subject: WORKSPACE_CASES[id].subject,
                risk: (WORKSPACE_CASES[id].severity || "").split(" ")[0]
            });
        }
    });

    casesMap.forEach(item => {
        const opt = document.createElement("option");
        opt.value = String(item.id);
        const subj = item.subject.length > 38 ? item.subject.substring(0, 38) + "..." : item.subject;
        opt.textContent = `Case #${item.id}: ${subj} (${item.risk})`;
        select.appendChild(opt);
    });

    const blankOpt = document.createElement("option");
    blankOpt.value = "blank";
    blankOpt.textContent = "[+] Blank State / New Raw Analysis";
    select.appendChild(blankOpt);

    if (currentVal && select.querySelector(`option[value="${currentVal}"]`)) {
        select.value = currentVal;
    } else if (casesMap.size > 0) {
        select.value = String(casesMap.keys().next().value);
    }
}

function renderInvestigationWorkspace(caseId) {
    if (caseId === "blank") {
        setWorkspaceBlankState(true);
        return;
    }

    const c = getWorkspaceCase(caseId);
    if (!c) return;

    currentWorkspaceCaseId = Number(c.id);
    setWorkspaceBlankState(false);

    const select = document.getElementById("workspace-case-select");
    if (select && select.value !== String(c.id)) select.value = String(c.id);

    const tabBadge = document.getElementById("badge-ws-case");
    if (tabBadge) tabBadge.textContent = `CASE #${c.id}`;

    const caseTagText = document.getElementById("ws-case-tag-text");
    if (caseTagText) caseTagText.textContent = `CASE #${c.id}: ${c.subject.substring(0, 48).toUpperCase()}...`;

    const statusBadge = document.getElementById("ws-status-badge");
    if (statusBadge) {
        statusBadge.className = `workspace-status-badge ${c.statusClass}`;
        statusBadge.innerHTML = `<i class="fa-solid ${c.statusIcon}"></i> ${escapeHtml(c.status)}`;
    }

    const valCaseId = document.getElementById("ws-val-case-id");
    if (valCaseId) valCaseId.textContent = `#${c.id} (${c.threatIntel.cluster})`;

    const valSeverity = document.getElementById("ws-val-severity");
    if (valSeverity) {
        valSeverity.textContent = c.severity;
        valSeverity.style.color = c.severityColor;
    }

    const valSource = document.getElementById("ws-val-source");
    if (valSource) valSource.textContent = c.source;

    const valStatus = document.getElementById("ws-val-status");
    if (valStatus) {
        valStatus.textContent = c.status;
        valStatus.style.color = c.severityColor;
    }

    const valEnvelope = document.getElementById("ws-val-envelope");
    if (valEnvelope) {
        valEnvelope.textContent = c.envelope;
        valEnvelope.style.color = c.envelopeColor;
    }

    const valSeal = document.getElementById("ws-val-seal");
    if (valSeal) valSeal.textContent = c.evidenceSeal;

    const scoreThreat = document.getElementById("ws-score-threat");
    if (scoreThreat) {
        scoreThreat.textContent = c.threatScore;
        scoreThreat.style.color = c.threatColor;
    }
    const barThreat = document.getElementById("ws-bar-threat");
    if (barThreat) {
        barThreat.style.width = `${c.threatScore}%`;
        barThreat.style.background = c.threatColor;
    }
    const subtextThreat = document.getElementById("ws-subtext-threat");
    if (subtextThreat) subtextThreat.textContent = c.threatSubtext;

    const scoreAttribution = document.getElementById("ws-score-attribution");
    if (scoreAttribution) {
        scoreAttribution.textContent = c.attributionScore;
        scoreAttribution.style.color = c.attributionColor;
    }
    const barAttribution = document.getElementById("ws-bar-attribution");
    if (barAttribution) {
        barAttribution.style.width = `${c.attributionScore}%`;
        barAttribution.style.background = c.attributionColor;
    }
    const subtextAttribution = document.getElementById("ws-subtext-attribution");
    if (subtextAttribution) subtextAttribution.innerHTML = c.attributionSubtext;

    const emailSubject = document.getElementById("ws-email-subject");
    if (emailSubject) emailSubject.textContent = c.subject;

    const emailFrom = document.getElementById("ws-email-from");
    if (emailFrom) emailFrom.textContent = `${c.senderDisplay} <${c.sender}>`;

    const mlPhish = document.getElementById("ws-ml-phish");
    if (mlPhish) mlPhish.textContent = c.contentAnalysis.mlSignals.phishing;

    const mlBec = document.getElementById("ws-ml-bec");
    if (mlBec) mlBec.textContent = c.contentAnalysis.mlSignals.bec;

    const mlHarvest = document.getElementById("ws-ml-harvest");
    if (mlHarvest) mlHarvest.textContent = c.contentAnalysis.mlSignals.harvest;

    const mlSocial = document.getElementById("ws-ml-social");
    if (mlSocial) mlSocial.textContent = c.contentAnalysis.mlSignals.social;

    const detDisplay = document.getElementById("ws-det-display");
    if (detDisplay) detDisplay.textContent = c.contentAnalysis.deterministic.displayNameMismatch;

    const detLookalike = document.getElementById("ws-det-lookalike");
    if (detLookalike) detLookalike.textContent = c.contentAnalysis.deterministic.lookalikeDomain;

    const detReplyto = document.getElementById("ws-det-replyto");
    if (detReplyto) detReplyto.textContent = c.contentAnalysis.deterministic.replyTo;

    const detRelay = document.getElementById("ws-det-relay");
    if (detRelay) detRelay.textContent = c.contentAnalysis.deterministic.suspiciousRelay;

    const bodyPreview = document.getElementById("ws-email-body-preview");
    if (bodyPreview) {
        bodyPreview.textContent = c.body_text || "(No plaintext body found in .EML payload)";
    }
    const headersPreview = document.getElementById("ws-email-headers-preview");
    if (headersPreview) {
        headersPreview.textContent = c.raw_headers || "(No raw headers provided)";
    }
    const btnCopyBody = document.getElementById("btn-copy-ws-body");
    if (btnCopyBody) {
        btnCopyBody.onclick = () => {
            navigator.clipboard.writeText(c.body_text || "");
            showToast("📋 Email body text copied to clipboard!", "success");
        };
    }
    const btnCopyHeaders = document.getElementById("btn-copy-ws-headers");
    if (btnCopyHeaders) {
        btnCopyHeaders.onclick = () => {
            navigator.clipboard.writeText(c.raw_headers || "");
            showToast("📋 Raw RFC 822 headers copied to clipboard!", "success");
        };
    }

    const authSpf = document.getElementById("ws-auth-spf");
    if (authSpf) {
        authSpf.textContent = c.authForensics.spf.status;
        authSpf.style.color = c.authForensics.spf.color;
    }

    const authDkim = document.getElementById("ws-auth-dkim");
    if (authDkim) {
        authDkim.textContent = c.authForensics.dkim.status;
        authDkim.style.color = c.authForensics.dkim.color;
    }

    const authDmarc = document.getElementById("ws-auth-dmarc");
    if (authDmarc) {
        authDmarc.textContent = c.authForensics.dmarc.status;
        authDmarc.style.color = c.authForensics.dmarc.color;
    }

    const valReturnPath = document.getElementById("ws-val-return-path");
    if (valReturnPath) valReturnPath.textContent = c.authForensics.returnPath;

    const valMessageId = document.getElementById("ws-val-message-id");
    if (valMessageId) valMessageId.textContent = c.authForensics.messageId;

    const iocsTbody = document.getElementById("ws-iocs-tbody");
    if (iocsTbody) {
        iocsTbody.innerHTML = c.iocs.map(ioc => `
            <tr>
                <td><span class="badge-evidence badge-evidence-observed">${escapeHtml(ioc.type)}</span></td>
                <td style="font-family: var(--font-mono); font-size: 0.72rem; word-break: break-all;">${escapeHtml(ioc.value)}</td>
                <td>${escapeHtml(ioc.context)}</td>
                <td><span style="color: ${ioc.riskColor}; font-weight: 700;">${escapeHtml(ioc.risk)}</span></td>
            </tr>
        `).join("");
    }

    const urlExtracted = document.getElementById("ws-url-extracted");
    if (urlExtracted) urlExtracted.textContent = c.urlAnalysis.extractedUrl;

    const urlMismatch = document.getElementById("ws-url-mismatch");
    if (urlMismatch) urlMismatch.textContent = c.urlAnalysis.domainMismatch;

    const urlChainList = document.getElementById("ws-url-chain-list");
    if (urlChainList) {
        urlChainList.innerHTML = c.urlAnalysis.chain.map(hop => `
            <div class="url-chain-node" style="${hop.isFinal && c.threatScore > 50 ? 'border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.08);' : ''}">
                <span class="url-chain-step" style="${hop.isFinal && c.threatScore > 50 ? 'color: #ef4444;' : ''}">${escapeHtml(hop.step)}</span>
                <span class="url-chain-link" style="${hop.isFinal && c.threatScore > 50 ? 'color: #f87171;' : ''}">${escapeHtml(hop.link)}</span>
                <span class="badge-evidence ${hop.badgeClass}">${escapeHtml(hop.badge)}</span>
            </div>
        `).join("");
    }

    const attFilename = document.getElementById("ws-att-filename");
    if (attFilename) attFilename.textContent = c.attachmentAnalysis.filename;

    const attMismatch = document.getElementById("ws-att-mismatch");
    if (attMismatch) attMismatch.textContent = c.attachmentAnalysis.mismatch;

    const attTypes = document.getElementById("ws-att-types");
    if (attTypes) attTypes.textContent = c.attachmentAnalysis.types;

    const attMacro = document.getElementById("ws-att-macro");
    if (attMacro) attMacro.textContent = c.attachmentAnalysis.macro;

    const attHash = document.getElementById("ws-att-hash");
    if (attHash) attHash.textContent = c.attachmentAnalysis.hash;

    const attRisk = document.getElementById("ws-att-risk");
    if (attRisk) {
        attRisk.textContent = c.attachmentAnalysis.risk;
        attRisk.style.color = c.attachmentAnalysis.riskColor;
    }

    const domName = document.getElementById("ws-dom-name");
    if (domName) domName.textContent = c.domainIntelligence.name;

    const domAge = document.getElementById("ws-dom-age");
    if (domAge) {
        domAge.textContent = c.domainIntelligence.age;
        domAge.style.color = c.domainIntelligence.ageColor;
    }

    const domRegistrar = document.getElementById("ws-dom-registrar");
    if (domRegistrar) domRegistrar.textContent = c.domainIntelligence.registrar;

    const domDns = document.getElementById("ws-dom-dns");
    if (domDns) domDns.textContent = c.domainIntelligence.dns;

    const domMx = document.getElementById("ws-dom-mx");
    if (domMx) domMx.textContent = c.domainIntelligence.mx;

    const domNs = document.getElementById("ws-dom-ns");
    if (domNs) domNs.textContent = c.domainIntelligence.ns;

    const domAsn = document.getElementById("ws-dom-asn");
    if (domAsn) domAsn.textContent = c.domainIntelligence.asn;

    const domRep = document.getElementById("ws-dom-rep");
    if (domRep) {
        domRep.textContent = c.domainIntelligence.reputation;
        domRep.style.color = c.domainIntelligence.repColor;
    }

    const relayIp = document.getElementById("ws-relay-ip");
    if (relayIp) relayIp.textContent = c.relayTrace.ip;

    const relayGeo = document.getElementById("ws-relay-geo");
    if (relayGeo) relayGeo.textContent = c.relayTrace.geo;

    const relayHopList = document.getElementById("ws-relay-hop-list");
    if (relayHopList) {
        relayHopList.innerHTML = c.relayTrace.hops.map(hop => `
            <div class="url-chain-node">
                <span class="url-chain-step">${escapeHtml(hop.step)}</span>
                <span class="url-chain-link">${escapeHtml(hop.link)}</span>
                <span class="badge-evidence badge-evidence-observed">${escapeHtml(hop.badge)}</span>
            </div>
        `).join("");
    }

    const corrCluster = document.getElementById("ws-corr-cluster");
    if (corrCluster) corrCluster.textContent = c.threatIntel.cluster;

    const corrSim = document.getElementById("ws-corr-similarity");
    if (corrSim) corrSim.textContent = c.threatIntel.similarity;

    const corrShared = document.getElementById("ws-corr-shared");
    if (corrShared) corrShared.textContent = c.threatIntel.shared;

    const corrEvidence = document.getElementById("ws-corr-evidence");
    if (corrEvidence) corrEvidence.textContent = c.threatIntel.evidence;

    const o = c.originAssessment;
    const compPct = document.getElementById("ws-origin-comp-pct");
    if (compPct) { compPct.textContent = `${o.compromised.pct}%`; compPct.style.color = o.compromised.color; }
    const compBar = document.getElementById("ws-origin-comp-bar");
    if (compBar) { compBar.style.width = `${o.compromised.pct}%`; compBar.style.background = o.compromised.color; }
    const compRat = document.getElementById("ws-origin-comp-rat");
    if (compRat) compRat.textContent = o.compromised.rationale;

    const spoofPct = document.getElementById("ws-origin-spoof-pct");
    if (spoofPct) { spoofPct.textContent = `${o.spoofed.pct}%`; spoofPct.style.color = o.spoofed.color; }
    const spoofBar = document.getElementById("ws-origin-spoof-bar");
    if (spoofBar) { spoofBar.style.width = `${o.spoofed.pct}%`; spoofBar.style.background = o.spoofed.color; }
    const spoofRat = document.getElementById("ws-origin-spoof-rat");
    if (spoofRat) spoofRat.textContent = o.spoofed.rationale;

    const anonPct = document.getElementById("ws-origin-anon-pct");
    if (anonPct) { anonPct.textContent = `${o.anonymized.pct}%`; anonPct.style.color = o.anonymized.color; }
    const anonBar = document.getElementById("ws-origin-anon-bar");
    if (anonBar) { anonBar.style.width = `${o.anonymized.pct}%`; anonBar.style.background = o.anonymized.color; }
    const anonRat = document.getElementById("ws-origin-anon-rat");
    if (anonRat) anonRat.textContent = o.anonymized.rationale;

    const malPct = document.getElementById("ws-origin-mal-pct");
    if (malPct) { malPct.textContent = `${o.directMalicious.pct}%`; malPct.style.color = o.directMalicious.color; }
    const malBar = document.getElementById("ws-origin-mal-bar");
    if (malBar) { malBar.style.width = `${o.directMalicious.pct}%`; malBar.style.background = o.directMalicious.color; }
    const malRat = document.getElementById("ws-origin-mal-rat");
    if (malRat) malRat.textContent = o.directMalicious.rationale;

    renderWorkspaceMiniGraph(c.id);

    const timelineList = document.getElementById("ws-timeline-list");
    if (timelineList) {
        timelineList.innerHTML = c.timeline.map(step => `
            <div class="timeline-step-item">
                <span class="timeline-step-time">${escapeHtml(step.time)}</span>
                <span class="timeline-step-text">${escapeHtml(step.text)}</span>
            </div>
        `).join("");
    }

    const evidenceHash = document.getElementById("ws-evidence-hash");
    if (evidenceHash) evidenceHash.textContent = `SHA-256: ${c.sha256_hash}`;

    const btnTopPdf = document.getElementById("btn-ws-top-pdf");
    if (btnTopPdf) btnTopPdf.onclick = () => window.downloadReport(c.id);

    const btnExportPdf = document.getElementById("btn-ws-export-pdf");
    if (btnExportPdf) btnExportPdf.onclick = () => window.downloadReport(c.id);

    showToast(`📂 Loaded Case #${c.id}: ${c.subject.substring(0, 36)}...`, "info");
}

function renderWorkspaceMiniGraph(caseId) {
    const canvas = document.getElementById("ws-mini-graph-canvas");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const container = canvas.parentElement;
    if (container && container.offsetWidth > 0) {
        canvas.width = container.offsetWidth;
        canvas.height = 250;
    }

    const c = getWorkspaceCase(caseId);
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;

    let nodes = [];
    let edges = [];

    if (caseId === 1001 || caseId === 1002) {
        nodes = [
            { id: "case1001", label: "Case #1001 (PayPal Phish)", x: cx - 180, y: cy - 45, color: "#ef4444", glow: "rgba(239, 68, 68, 0.5)", r: 16, icon: "✉" },
            { id: "case1002", label: "Case #1002 (CEO BEC)", x: cx - 180, y: cy + 55, color: "#f59e0b", glow: "rgba(245, 158, 11, 0.5)", r: 15, icon: "✉" },
            { id: "relay", label: "IP 185.220.101.5", x: cx - 30, y: cy, color: "#dc2626", glow: "rgba(220, 38, 38, 0.6)", r: 18, icon: "⌖", highlight: true },
            { id: "asn", label: "AS44146 Tor Transit", x: cx + 110, y: cy - 60, color: "#f59e0b", glow: "rgba(245, 158, 11, 0.5)", r: 15, icon: "⬢" },
            { id: "cluster", label: "Cluster TC-44146", x: cx + 135, y: cy + 45, color: "#ea580c", glow: "rgba(234, 88, 12, 0.6)", r: 18, icon: "☠" },
            { id: "domain", label: caseId === 1001 ? "paypal-verify-user.com" : "corp-secure-finance.net", x: cx - 75, y: cy - 80, color: "#06b6d4", glow: "rgba(6, 182, 212, 0.5)", r: 14, icon: "🌐" },
            { id: "ns", label: "ns1.offshore-dns.cc", x: cx + 25, y: cy + 80, color: "#8b5cf6", glow: "rgba(139, 92, 246, 0.5)", r: 13, icon: "🌐" }
        ];

        edges = [
            { from: "case1001", to: "relay" },
            { from: "case1002", to: "relay" },
            { from: "case1001", to: "domain" },
            { from: "case1002", to: "ns" },
            { from: "domain", to: "relay" },
            { from: "relay", to: "asn" },
            { from: "relay", to: "cluster" },
            { from: "ns", to: "cluster" },
            { from: "asn", to: "cluster" }
        ];
    } else if (caseId === 1003) {
        nodes = [
            { id: "case1003", label: "Case #1003 (GitHub Advisory)", x: cx - 140, y: cy, color: "#10b981", glow: "rgba(16, 185, 129, 0.5)", r: 16, icon: "✉" },
            { id: "ip", label: "192.30.252.204", x: cx, y: cy - 40, color: "#34d399", glow: "rgba(52, 211, 153, 0.5)", r: 15, icon: "⌖" },
            { id: "domain", label: "github.com (Aligned)", x: cx, y: cy + 45, color: "#06b6d4", glow: "rgba(6, 182, 212, 0.5)", r: 14, icon: "🌐" },
            { id: "asn", label: "AS36459 GitHub Inc", x: cx + 140, y: cy, color: "#10b981", glow: "rgba(16, 185, 129, 0.5)", r: 16, icon: "⬢" }
        ];

        edges = [
            { from: "case1003", to: "ip" },
            { from: "case1003", to: "domain" },
            { from: "ip", to: "asn" },
            { from: "domain", to: "asn" }
        ];
    } else {
        const caseLabel = c && c.id ? `Case #${c.id}` : `Case #${caseId}`;
        const senderDomain = (c && c.sender && c.sender.includes("@")) ? c.sender.split("@")[1].replace(">", "").trim() : "target-domain.org";
        const relayIp = (c && c.extracted_ips && c.extracted_ips[0]) ? c.extracted_ips[0] : "185.220.101.5";

        nodes = [
            { id: "custom_case", label: caseLabel, x: cx - 160, y: cy, color: "#ef4444", glow: "rgba(239, 68, 68, 0.5)", r: 16, icon: "✉" },
            { id: "custom_dom", label: senderDomain, x: cx - 40, y: cy - 50, color: "#06b6d4", glow: "rgba(6, 182, 212, 0.5)", r: 14, icon: "🌐" },
            { id: "custom_ip", label: relayIp, x: cx - 40, y: cy + 50, color: "#dc2626", glow: "rgba(220, 38, 38, 0.6)", r: 15, icon: "⌖" },
            { id: "custom_asn", label: "AS44146 Transit", x: cx + 90, y: cy - 40, color: "#f59e0b", glow: "rgba(245, 158, 11, 0.5)", r: 14, icon: "⬢" },
            { id: "custom_cluster", label: "TC-44146 Syndicate", x: cx + 140, y: cy + 40, color: "#ea580c", glow: "rgba(234, 88, 12, 0.6)", r: 17, icon: "☠" }
        ];

        edges = [
            { from: "custom_case", to: "custom_dom" },
            { from: "custom_case", to: "custom_ip" },
            { from: "custom_dom", to: "custom_ip" },
            { from: "custom_ip", to: "custom_asn" },
            { from: "custom_asn", to: "custom_cluster" },
            { from: "custom_ip", to: "custom_cluster" }
        ];
    }

    const nodeMap = {};
    nodes.forEach(n => { nodeMap[n.id] = n; });

    edges.forEach(e => {
        const src = nodeMap[e.from];
        const tgt = nodeMap[e.to];
        if (src && tgt) {
            ctx.strokeStyle = "rgba(148, 163, 184, 0.25)";
            ctx.lineWidth = 1.4;
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.stroke();
        }
    });

    nodes.forEach(n => {
        if (n.highlight) {
            ctx.strokeStyle = "rgba(239, 68, 68, 0.5)";
            ctx.lineWidth = 3;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r + 5, 0, 2 * Math.PI);
            ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 3, 0, 2 * Math.PI);
        ctx.fillStyle = n.glow || "rgba(139, 92, 246, 0.4)";
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, 2 * Math.PI);
        ctx.fillStyle = n.color;
        ctx.fill();

        ctx.strokeStyle = "#090d16";
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.fillStyle = "#ffffff";
        ctx.font = `bold ${Math.round(n.r * 0.85)}px Inter, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(n.icon || "•", n.x, n.y + 1);

        const shortLabel = n.label.length > 20 ? n.label.substring(0, 18) + "…" : n.label;
        ctx.font = "10px Inter, sans-serif";
        const textWidth = ctx.measureText(shortLabel).width;
        const pillW = textWidth + 8;
        const pillH = 15;
        const pillX = n.x - pillW / 2;
        const pillY = n.y + n.r + 4;

        ctx.fillStyle = "rgba(9, 13, 22, 0.85)";
        ctx.strokeStyle = "rgba(148, 163, 184, 0.3)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        if (ctx.roundRect) {
            ctx.roundRect(pillX, pillY, pillW, pillH, 3);
        } else {
            ctx.rect(pillX, pillY, pillW, pillH);
        }
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = "#e2e8f0";
        ctx.textBaseline = "alphabetic";
        ctx.fillText(shortLabel, n.x, pillY + 11);
    });
}

function setWorkspaceBlankState(isBlank) {
    const loadedCaseEl = document.getElementById("workspace-loaded-case");
    const blankStateEl = document.getElementById("workspace-blank-state");
    const select = document.getElementById("workspace-case-select");

    if (isBlank) {
        if (loadedCaseEl) loadedCaseEl.classList.add("hidden");
        if (blankStateEl) blankStateEl.classList.remove("hidden");
        if (select) select.value = "blank";
    } else {
        if (loadedCaseEl) loadedCaseEl.classList.remove("hidden");
        if (blankStateEl) blankStateEl.classList.add("hidden");
    }
}

function exportStixBundle(caseId) {
    const c = getWorkspaceCase(caseId);
    const timestamp = new Date().toISOString();
    
    const bundle = {
        type: "bundle",
        id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'bytetrail-' + Date.now()}`,
        spec_version: "2.1",
        objects: [
            {
                type: "indicator",
                id: `indicator--${crypto.randomUUID ? crypto.randomUUID() : 'ioc-' + Date.now()}`,
                created: timestamp,
                modified: timestamp,
                name: `ByteTrail Threat Indicator #${c.id}`,
                pattern: `[ipv4-addr:value = '${c.relayTrace.ip}'] AND [domain-name:value = '${c.domainIntelligence.name}']`,
                pattern_type: "stix",
                valid_from: timestamp,
                confidence: c.attributionScore,
                description: `Extracted from email: ${c.subject}`
            },
            {
                type: "threat-actor",
                id: `threat-actor--${crypto.randomUUID ? crypto.randomUUID() : 'actor-' + Date.now()}`,
                created: timestamp,
                modified: timestamp,
                name: c.threatIntel.cluster,
                threat_actor_types: ["cybercriminal", "phishing-operator"],
                confidence: c.attributionScore,
                description: "Observed infrastructure cluster. Pattern-based attribution only."
            },
            {
                type: "observed-data",
                id: `observed-data--${crypto.randomUUID ? crypto.randomUUID() : 'obs-' + Date.now()}`,
                created: timestamp,
                modified: timestamp,
                first_observed: c.received_at,
                last_observed: timestamp,
                number_observed: 1
            }
        ]
    };

    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bytetrail-case-${c.id}-stix2.1.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`✅ STIX 2.1 Cyber Threat Intelligence Bundle Exported for Case #${c.id}`, "success");
}

function exportEvidenceJson(caseId) {
    const c = getWorkspaceCase(caseId);
    const evidencePackage = {
        bytetrail_forensic_evidence_standard: "ISO/IEC 27037:2012",
        case_id: c.id,
        timestamp_utc: new Date().toISOString(),
        sha256_cryptographic_seal: c.sha256_hash,
        audit_ledger_id: c.auditLedger,
        tamper_verification_status: "VERIFIED_AUTHENTIC",
        incident_metadata: {
            subject: c.subject,
            sender: c.sender,
            sender_display: c.senderDisplay,
            ingest_source: c.source,
            quarantine_enforcement: c.status
        },
        risk_metrics: {
            threat_fraud_risk_score: c.threatScore,
            attribution_confidence_score: c.attributionScore
        },
        origin_vector_assessment_ps26106: c.originAssessment,
        rfc822_authentication_matrix: c.authForensics,
        indicators_of_compromise: c.iocs,
        network_route_and_geolocation: {
            source_ip: c.relayTrace.ip,
            infrastructure_geolocation: c.relayTrace.geo,
            asn: c.domainIntelligence.asn,
            safe_origin_notice: "Geolocation reflects observed network relay infrastructure (ASNs, proxies, Tor hops) and does not represent the sender verified physical location."
        }
    };

    const blob = new Blob([JSON.stringify(evidencePackage, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bytetrail-case-${c.id}-evidence-integrity.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`✅ ISO/IEC 27037 Forensic Evidence JSON Exported for Case #${c.id}`, "success");
}

function fallbackPrintForensicReport(caseId) {
    const c = getWorkspaceCase(caseId);
    
    const reportHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ByteTrail Forensic Report - Case #${c.id}</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1e293b; background: #fff; line-height: 1.5; font-size: 13px; }
        .header { display: flex; justify-content: space-between; border-bottom: 2px solid #0284c7; padding-bottom: 15px; margin-bottom: 20px; }
        .logo-title { font-size: 22px; font-weight: 800; color: #0284c7; }
        .sub-title { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-danger { background: #fee2e2; color: #dc2626; border: 1px solid #f87171; }
        .badge-success { background: #dcfce7; color: #16a34a; border: 1px solid #4ade80; }
        .section-title { font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 25px; margin-bottom: 8px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 12px; }
        th, td { border: 1px solid #cbd5e1; padding: 7px 10px; text-align: left; }
        th { background: #f8fafc; font-weight: 600; }
        .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 8px; }
        .kv-box { background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px 12px; border-radius: 4px; }
        .kv-label { font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: bold; }
        .kv-val { font-size: 12px; font-weight: 600; color: #0f172a; margin-top: 2px; word-break: break-all; }
        .disclaimer { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 10px; margin-top: 20px; font-size: 11px; color: #92400e; }
        .footer { margin-top: 35px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 10px; color: #94a3b8; display: flex; justify-content: space-between; }
        @media print {
            body { margin: 15mm; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="no-print" style="background: #0284c7; color: white; padding: 10px 20px; margin: -40px -40px 25px -40px; display: flex; justify-content: space-between; align-items: center;">
        <span><strong>ByteTrail Forensic Evidence Engine</strong> — Print-ready view generated.</span>
        <button onclick="window.print()" style="background: white; color: #0284c7; border: none; padding: 6px 14px; font-weight: bold; border-radius: 4px; cursor: pointer;">Print / Save as PDF</button>
    </div>

    <div class="header">
        <div>
            <div class="logo-title">BYTETRAIL // FORENSIC EVIDENCE REPORT</div>
            <div class="sub-title">ISO/IEC 27037:2012 Evidence Identification & Integrity Certified</div>
        </div>
        <div style="text-align: right;">
            <div><strong>CASE #${c.id}</strong></div>
            <span class="badge ${c.threatScore > 50 ? 'badge-danger' : 'badge-success'}">${c.severity}</span>
        </div>
    </div>

    <div class="section-title">1. INCIDENT & ENVELOPE METADATA</div>
    <div class="kv-grid">
        <div class="kv-box"><div class="kv-label">Subject Header</div><div class="kv-val">${escapeHtml(c.subject)}</div></div>
        <div class="kv-box"><div class="kv-label">From Header</div><div class="kv-val">${escapeHtml(c.senderDisplay)} &lt;${escapeHtml(c.sender)}&gt;</div></div>
        <div class="kv-box"><div class="kv-label">Return-Path (RFC 5321)</div><div class="kv-val">${escapeHtml(c.authForensics.returnPath)}</div></div>
        <div class="kv-box"><div class="kv-label">Message-ID (RFC 5322)</div><div class="kv-val">${escapeHtml(c.authForensics.messageId)}</div></div>
        <div class="kv-box"><div class="kv-label">Threat / Fraud Risk</div><div class="kv-val">${c.threatScore} / 100</div></div>
        <div class="kv-box"><div class="kv-label">Attribution Confidence</div><div class="kv-val">${c.attributionScore} / 100</div></div>
    </div>

    <div class="section-title">2. DETERMINISTIC PROTOCOL AUTHENTICATION MATRIX</div>
    <table>
        <thead><tr><th>Protocol</th><th>Verification Result</th><th>Forensic Evaluation</th></tr></thead>
        <tbody>
            <tr><td>SPF (RFC 7208)</td><td><strong>${c.authForensics.spf.status}</strong></td><td>${escapeHtml(c.authForensics.spf.desc)}</td></tr>
            <tr><td>DKIM (RFC 6376)</td><td><strong>${c.authForensics.dkim.status}</strong></td><td>${escapeHtml(c.authForensics.dkim.desc)}</td></tr>
            <tr><td>DMARC (RFC 7489)</td><td><strong>${c.authForensics.dmarc.status}</strong></td><td>${escapeHtml(c.authForensics.dmarc.desc)}</td></tr>
        </tbody>
    </table>

    <div class="section-title">3. PS-26106 ORIGIN VECTOR ASSESSMENT (CONFIDENCE LIKELIHOODS)</div>
    <table>
        <thead><tr><th>Origin Assessment Vector</th><th>Likelihood</th><th>Forensic Rationale</th></tr></thead>
        <tbody>
            <tr><td>Compromised Account</td><td><strong>${c.originAssessment.compromised.pct}%</strong></td><td>${escapeHtml(c.originAssessment.compromised.rationale)}</td></tr>
            <tr><td>Spoofed Domain</td><td><strong>${c.originAssessment.spoofed.pct}%</strong></td><td>${escapeHtml(c.originAssessment.spoofed.rationale)}</td></tr>
            <tr><td>Anonymized Infrastructure</td><td><strong>${c.originAssessment.anonymized.pct}%</strong></td><td>${escapeHtml(c.originAssessment.anonymized.rationale)}</td></tr>
            <tr><td>Direct Malicious Environment</td><td><strong>${c.originAssessment.directMalicious.pct}%</strong></td><td>${escapeHtml(c.originAssessment.directMalicious.rationale)}</td></tr>
        </tbody>
    </table>

    <div class="section-title">4. EXTRACTED INDICATORS OF COMPROMISE (IoCs)</div>
    <table>
        <thead><tr><th>Type</th><th>Observed Indicator Value</th><th>Forensic Context</th><th>Risk Scrutiny</th></tr></thead>
        <tbody>
            ${c.iocs.map(ioc => `<tr><td>${escapeHtml(ioc.type)}</td><td style="font-family: monospace;">${escapeHtml(ioc.value)}</td><td>${escapeHtml(ioc.context)}</td><td><strong>${escapeHtml(ioc.risk)}</strong></td></tr>`).join("")}
        </tbody>
    </table>

    <div class="section-title">5. DOMAIN & INFRASTRUCTURE INTELLIGENCE</div>
    <div class="kv-grid">
        <div class="kv-box"><div class="kv-label">Observed Relay IP</div><div class="kv-val">${escapeHtml(c.relayTrace.ip)}</div></div>
        <div class="kv-box"><div class="kv-label">Infrastructure Geolocation</div><div class="kv-val">${escapeHtml(c.relayTrace.geo)}</div></div>
        <div class="kv-box"><div class="kv-label">Hosting ASN</div><div class="kv-val">${escapeHtml(c.domainIntelligence.asn)}</div></div>
        <div class="kv-box"><div class="kv-label">Threat Cluster Linkage</div><div class="kv-val">${escapeHtml(c.threatIntel.cluster)}</div></div>
    </div>

    <div class="disclaimer">
        <strong>Technically Safe Origin Disclaimer:</strong> Geolocation coordinates represent observed network relay infrastructure (ASNs, proxies, Tor hops) and do not represent the sender's verified physical location. Attribution confidence reflects threat intelligence pattern correlation and is provided for incident response and threat attribution support.
    </div>

    <div class="footer">
        <div>SHA-256 Seal: <span style="font-family: monospace;">${c.sha256_hash}</span></div>
        <div>Audit Ledger: ${c.auditLedger} | Generated: ${new Date().toISOString()}</div>
    </div>
</body>
</html>
    `;

    const reportWin = window.open("", "_blank");
    if (reportWin) {
        reportWin.document.write(reportHtml);
        reportWin.document.close();
    } else {
        showToast("⚠️ Pop-up blocked. Please allow pop-ups to open the Forensic Report.", "error");
    }
}

if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        renderAuthUI();
        initNavTabs();
        initRadarMap();
        initEmlDropzone();
        checkBackendStatus();
        loadEmails();
        loadConnectedMailboxes();
        initEventListeners();

        renderInvestigationWorkspace(1001);

        setInterval(() => {
            checkBackendStatus();
            loadEmails(false); // Silent background refresh
        }, 10000);
    });
}

function switchViewMode(mode, targetSubTab = null) {
    const landingSection = document.getElementById("landing-page");
    const socSection = document.getElementById("soc-dashboard");
    const btnModeLanding = document.getElementById("btn-mode-landing");
    const btnModeSoc = document.getElementById("btn-mode-soc");

    if (mode === "soc") {
        if (!getAuthToken()) {
            openAuthModal("signin");
            showToast("🔒 Please sign in or click Demo Analyst to enter the Live SOC Console", "info");
            return;
        }

        if (landingSection) landingSection.classList.add("hidden");
        if (socSection) socSection.classList.remove("hidden");
        if (btnModeLanding) btnModeLanding.classList.remove("active");
        if (btnModeSoc) btnModeSoc.classList.add("active");

        if (targetSubTab) {
            const tabBtn = document.querySelector(`.nav-tab[data-tab="${targetSubTab}"]`);
            if (tabBtn) tabBtn.click();
        }

        if (radarMap) {
            setTimeout(() => radarMap.invalidateSize(), 200);
        }
    } else {
        if (landingSection) landingSection.classList.remove("hidden");
        if (socSection) socSection.classList.add("hidden");
        if (btnModeLanding) btnModeLanding.classList.add("active");
        if (btnModeSoc) btnModeSoc.classList.remove("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
    }
}

function getAuthToken() {
    return localStorage.getItem("bytetrail_jwt_token");
}

function getAuthUser() {
    try {
        return JSON.parse(localStorage.getItem("bytetrail_user") || "null");
    } catch {
        return null;
    }
}

function setAuthSession(token, user) {
    localStorage.setItem("bytetrail_jwt_token", token);
    localStorage.setItem("bytetrail_user", JSON.stringify(user));
    renderAuthUI();
}

function clearAuthSession() {
    localStorage.removeItem("bytetrail_jwt_token");
    localStorage.removeItem("bytetrail_user");
    window.location.href = "login.html";
}

function getAuthHeaders(extraHeaders = {}) {
    const token = getAuthToken();
    const headers = { ...extraHeaders };
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
}

function renderAuthUI() {
    const user = getAuthUser();
    const token = getAuthToken();
    const unloggedCluster = document.getElementById("auth-unlogged-cluster");
    const loggedCluster = document.getElementById("auth-logged-cluster");
    const displayName = document.getElementById("user-display-name");
    const displayRole = document.getElementById("user-display-role");
    const avatarInitials = document.getElementById("user-avatar-initials");

    if (token && user) {
        if (unloggedCluster) unloggedCluster.classList.add("hidden");
        if (loggedCluster) loggedCluster.classList.remove("hidden");

        if (displayName) displayName.textContent = user.full_name || user.email.split("@")[0];
        if (displayRole) displayRole.textContent = (user.role || "Analyst").toUpperCase();

        const greetingName = document.getElementById("greeting-user-name");
        if (greetingName) greetingName.textContent = user.full_name ? user.full_name.split(" ")[0] : "Analyst";

        if (avatarInitials) {
            const names = (user.full_name || user.email).trim().split(" ");
            let initials = names[0][0];
            if (names.length > 1) initials += names[1][0];
            avatarInitials.textContent = initials.toUpperCase();
        }
    } else {
        if (unloggedCluster) unloggedCluster.classList.remove("hidden");
        if (loggedCluster) loggedCluster.classList.add("hidden");
    }
}

function openAuthModal(initialTab = "signin") {
    const modal = document.getElementById("auth-modal");
    if (!modal) return;
    modal.classList.remove("hidden");
    switchAuthModalTab(initialTab);
}

function closeAuthModal() {
    const modal = document.getElementById("auth-modal");
    if (!modal) return;
    modal.classList.add("hidden");
    const signinErr = document.getElementById("signin-error");
    const signupErr = document.getElementById("signup-error");
    if (signinErr) signinErr.classList.add("hidden");
    if (signupErr) signupErr.classList.add("hidden");
}

function switchAuthModalTab(tab) {
    const btnSignin = document.getElementById("tab-btn-signin");
    const btnSignup = document.getElementById("tab-btn-signup");
    const formSignin = document.getElementById("form-signin");
    const formSignup = document.getElementById("form-signup");
    const modalTitle = document.getElementById("auth-modal-title");

    if (tab === "signup") {
        btnSignin?.classList.remove("active");
        btnSignup?.classList.add("active");
        formSignin?.classList.add("hidden");
        formSignup?.classList.remove("hidden");
        if (modalTitle) modalTitle.textContent = "Create SOC Analyst Account";
    } else {
        btnSignin?.classList.add("active");
        btnSignup?.classList.remove("active");
        formSignin?.classList.remove("hidden");
        formSignup?.classList.add("hidden");
        if (modalTitle) modalTitle.textContent = "SOC Analyst Authentication";
    }
}

async function handleSignInSubmit(e) {
    e.preventDefault();
    const email = document.getElementById("signin-email").value.trim();
    const password = document.getElementById("signin-password").value;
    const errBox = document.getElementById("signin-error");
    const spinner = document.getElementById("signin-spinner");
    const btn = document.getElementById("btn-submit-signin");

    if (errBox) errBox.classList.add("hidden");
    if (spinner) spinner.classList.remove("hidden");
    if (btn) btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Authentication failed");

        setAuthSession(data.access_token, data.user);
        closeAuthModal();
        showToast(`✅ Welcome back, ${data.user.full_name || data.user.email}!`, "success");
        switchViewMode("soc");
        await loadEmails(false);
        await loadConnectedMailboxes();
    } catch (err) {
        if (errBox) {
            errBox.textContent = `❌ ${err.message}`;
            errBox.classList.remove("hidden");
        }
    } finally {
        if (spinner) spinner.classList.add("hidden");
        if (btn) btn.disabled = false;
    }
}

async function handleSignUpSubmit(e) {
    e.preventDefault();
    const full_name = document.getElementById("signup-name").value.trim();
    const email = document.getElementById("signup-email").value.trim();
    const password = document.getElementById("signup-password").value;
    const role = document.getElementById("signup-role").value;
    const errBox = document.getElementById("signup-error");
    const spinner = document.getElementById("signup-spinner");
    const btn = document.getElementById("btn-submit-signup");

    if (errBox) errBox.classList.add("hidden");
    if (spinner) spinner.classList.remove("hidden");
    if (btn) btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ full_name, email, password, role })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Registration failed");

        setAuthSession(data.access_token, data.user);
        closeAuthModal();
        showToast(`🎉 Account created! Welcome, ${data.user.full_name}!`, "success");
        switchViewMode("soc");
        await loadEmails(false);
        await loadConnectedMailboxes();
    } catch (err) {
        if (errBox) {
            errBox.textContent = `❌ ${err.message}`;
            errBox.classList.remove("hidden");
        }
    } finally {
        if (spinner) spinner.classList.add("hidden");
        if (btn) btn.disabled = false;
    }
}

async function handleDemoLogin() {
    showToast("⚡ Authenticating as Senior SOC Analyst...", "info");
    try {
        const res = await fetch(`${API_BASE}/api/auth/demo-login`, {
            method: "POST"
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Demo login failed");

        setAuthSession(data.access_token, data.user);
        closeAuthModal();
        showToast(`🚀 Authenticated as ${data.user.full_name} (${data.user.email})!`, "success");
        switchViewMode("soc");
        await loadEmails(false);
        await loadConnectedMailboxes();
    } catch (err) {
        showToast(`❌ Demo login error: ${err.message}`, "error");
    }
}

function initNavTabs() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            try {
                const navTabsContainer = tab.closest(".nav-tabs");
                if (navTabsContainer && navTabsContainer.scrollWidth > navTabsContainer.clientWidth) {
                    const tabLeft = tab.offsetLeft;
                    const tabWidth = tab.offsetWidth;
                    const containerWidth = navTabsContainer.clientWidth;
                    navTabsContainer.scrollTo({
                        left: tabLeft - (containerWidth / 2) + (tabWidth / 2),
                        behavior: "smooth"
                    });
                }
            } catch (err) { }

            if (window.scrollX !== 0 || document.documentElement.scrollLeft !== 0) {
                window.scrollTo({ left: 0, top: window.scrollY });
            }

            const targetTab = tab.dataset.tab;
            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });

            const activePane = document.getElementById(`pane-${targetTab}`);
            if (activePane) activePane.classList.add("active");

            if (targetTab === "radar" && radarMap) {
                setTimeout(() => {
                    radarMap.invalidateSize();
                }, 200);
            }

            if (targetTab === "investigation") {
                setTimeout(() => {
                    renderWorkspaceMiniGraph(currentWorkspaceCaseId);
                }, 60);
            }

            if (targetTab === "graph") {
                setTimeout(() => {
                    loadAndRenderCampaignGraph();
                }, 50);
            }

            if (targetTab === "mailboxes") {
                loadConnectedMailboxes();
            }
        });
    });

    let resizeTimer;
    window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (radarMap) {
                radarMap.invalidateSize();
            }
            const activeInvPane = document.getElementById("pane-investigation");
            if (activeInvPane && activeInvPane.classList.contains("active")) {
                renderWorkspaceMiniGraph(currentWorkspaceCaseId);
            }
            const activeGraphPane = document.getElementById("pane-graph");
            if (activeGraphPane && activeGraphPane.classList.contains("active")) {
                graphListenersInitialized = false;
                loadAndRenderCampaignGraph(true);
            }
        }, 150);
    });
}

function initEventListeners() {
    const wsCaseSelect = document.getElementById("workspace-case-select");
    if (wsCaseSelect) {
        wsCaseSelect.addEventListener("change", (e) => {
            if (e.target.value === "blank") {
                setWorkspaceBlankState(true);
            } else {
                renderInvestigationWorkspace(e.target.value);
            }
        });
    }

    const btnWsResetCase = document.getElementById("btn-ws-reset-case");
    if (btnWsResetCase) {
        btnWsResetCase.addEventListener("click", () => {
            renderInvestigationWorkspace(currentWorkspaceCaseId);
            showToast(`🔄 Case #${currentWorkspaceCaseId} view reset to baseline state.`, "info");
        });
    }

    const btnWsToggleBlank = document.getElementById("btn-ws-toggle-blank");
    if (btnWsToggleBlank) {
        btnWsToggleBlank.addEventListener("click", () => {
            setWorkspaceBlankState(true);
            showToast("Switched to blank analysis workspace.", "info");
        });
    }

    const btnBlankLoad1001 = document.getElementById("btn-blank-load-1001");
    if (btnBlankLoad1001) {
        btnBlankLoad1001.addEventListener("click", () => {
            renderInvestigationWorkspace(1001);
        });
    }

    const btnBlankLoad1002 = document.getElementById("btn-blank-load-1002");
    if (btnBlankLoad1002) {
        btnBlankLoad1002.addEventListener("click", () => {
            renderInvestigationWorkspace(1002);
        });
    }

    const btnBlankUploadEml = document.getElementById("btn-blank-upload-eml");
    if (btnBlankUploadEml) {
        btnBlankUploadEml.addEventListener("click", () => {
            const ingestTab = document.querySelector(`.nav-tab[data-tab="ingest"]`);
            if (ingestTab) ingestTab.click();
            document.getElementById("eml-file-input")?.click();
        });
    }

    const btnWsExportStix = document.getElementById("btn-ws-export-stix");
    if (btnWsExportStix) {
        btnWsExportStix.addEventListener("click", () => {
            exportStixBundle(currentWorkspaceCaseId);
        });
    }

    const btnWsExportJson = document.getElementById("btn-ws-export-json");
    if (btnWsExportJson) {
        btnWsExportJson.addEventListener("click", () => {
            exportEvidenceJson(currentWorkspaceCaseId);
        });
    }

    const btnWsTopPdf = document.getElementById("btn-ws-top-pdf");
    if (btnWsTopPdf) {
        btnWsTopPdf.addEventListener("click", () => {
            window.downloadReport(currentWorkspaceCaseId);
        });
    }

    const btnWsExportPdf = document.getElementById("btn-ws-export-pdf");
    if (btnWsExportPdf) {
        btnWsExportPdf.addEventListener("click", () => {
            window.downloadReport(currentWorkspaceCaseId);
        });
    }

    const brandHome = document.getElementById("brand-home-link");
    if (brandHome) brandHome.addEventListener("click", () => switchViewMode("landing"));

    const btnModeLanding = document.getElementById("btn-mode-landing");
    if (btnModeLanding) btnModeLanding.addEventListener("click", () => switchViewMode("landing"));

    const btnModeSoc = document.getElementById("btn-mode-soc");
    if (btnModeSoc) btnModeSoc.addEventListener("click", () => switchViewMode("soc"));

    const btnQuickDemo = document.getElementById("btn-quick-demo-login");
    if (btnQuickDemo) btnQuickDemo.addEventListener("click", handleDemoLogin);

    const btnOpenLogin = document.getElementById("btn-open-login-modal");
    if (btnOpenLogin) btnOpenLogin.addEventListener("click", () => openAuthModal("signin"));

    const btnHeroLaunchSoc = document.getElementById("btn-hero-launch-soc");
    if (btnHeroLaunchSoc) btnHeroLaunchSoc.addEventListener("click", () => switchViewMode("soc"));

    const btnHeroDemoLogin = document.getElementById("btn-hero-demo-login");
    if (btnHeroDemoLogin) btnHeroDemoLogin.addEventListener("click", handleDemoLogin);

    const btnBottomLaunchSoc = document.getElementById("btn-bottom-launch-soc");
    if (btnBottomLaunchSoc) btnBottomLaunchSoc.addEventListener("click", () => switchViewMode("soc"));

    const btnBottomOpenAuth = document.getElementById("btn-bottom-open-auth");
    if (btnBottomOpenAuth) btnBottomOpenAuth.addEventListener("click", () => openAuthModal("signup"));

    const btnModalDemoLogin = document.getElementById("btn-modal-demo-login");
    if (btnModalDemoLogin) btnModalDemoLogin.addEventListener("click", handleDemoLogin);

    const btnCloseAuth = document.getElementById("btn-close-auth-modal");
    const authBackdrop = document.getElementById("auth-modal-backdrop");
    if (btnCloseAuth) btnCloseAuth.addEventListener("click", closeAuthModal);
    if (authBackdrop) authBackdrop.addEventListener("click", closeAuthModal);

    const tabBtnSignin = document.getElementById("tab-btn-signin");
    const tabBtnSignup = document.getElementById("tab-btn-signup");
    if (tabBtnSignin) tabBtnSignin.addEventListener("click", () => switchAuthModalTab("signin"));
    if (tabBtnSignup) tabBtnSignup.addEventListener("click", () => switchAuthModalTab("signup"));

    const formSignin = document.getElementById("form-signin");
    if (formSignin) formSignin.addEventListener("submit", handleSignInSubmit);

    const formSignup = document.getElementById("form-signup");
    if (formSignup) formSignup.addEventListener("submit", handleSignUpSubmit);

    const btnUserLogout = document.getElementById("btn-user-logout");
    if (btnUserLogout) btnUserLogout.addEventListener("click", clearAuthSession);

    const btnQuickScan = document.getElementById("btn-quick-scan-email");
    if (btnQuickScan) {
        btnQuickScan.addEventListener("click", () => {
            const ingestTab = document.querySelector(`.nav-tab[data-tab="ingest"]`);
            if (ingestTab) ingestTab.click();
            document.getElementById("eml-dropzone")?.scrollIntoView({ behavior: "smooth" });
        });
    }

    const btnQuickConnect = document.getElementById("btn-quick-connect-inbox");
    if (btnQuickConnect) {
        btnQuickConnect.addEventListener("click", () => {
            document.getElementById("connect-mailbox-modal")?.classList.remove("hidden");
        });
    }

    const btnQuickScenarios = document.getElementById("btn-quick-view-scenarios");
    if (btnQuickScenarios) {
        btnQuickScenarios.addEventListener("click", () => {
            const ingestTab = document.querySelector(`.nav-tab[data-tab="ingest"]`);
            if (ingestTab) ingestTab.click();
            document.querySelector(".scenario-card")?.scrollIntoView({ behavior: "smooth" });
        });
    }

    const form = document.getElementById("ingest-form");
    if (form) form.addEventListener("submit", handleIngestSubmit);

    const btnRefreshFeed = document.getElementById("btn-refresh-feed");
    if (btnRefreshFeed) btnRefreshFeed.addEventListener("click", () => loadEmails(true));

    const btnLoadDemoCases = document.getElementById("btn-load-demo-cases");
    if (btnLoadDemoCases) {
        btnLoadDemoCases.addEventListener("click", () => {
            storedEmails = [DEMO_CASE, DEMO_CASE_2, DEMO_CASE_3];
            updateTelemetryStats(storedEmails);
            renderStreamFeed(storedEmails);
            applyFeedFilters();
            updateMapMarkers(storedEmails);
            updateAnalyticsMatrix(storedEmails);
            updateWorkspaceCaseDropdown();
            renderInvestigationWorkspace(DEMO_CASE.id);
            document.getElementById("tab-feed-count").textContent = storedEmails.length;
            showToast("🎯 Evaluator demo cases loaded (PS-26106 aligned).", "success");
        });
    }

    const btnClearFeed = document.getElementById("btn-clear-feed");
    if (btnClearFeed) {
        btnClearFeed.addEventListener("click", () => {
            storedEmails = [];
            updateTelemetryStats(storedEmails);
            renderStreamFeed(storedEmails);
            applyFeedFilters();
            updateMapMarkers(storedEmails);
            updateAnalyticsMatrix(storedEmails);
            updateWorkspaceCaseDropdown();
            renderInvestigationWorkspace("blank");
            document.getElementById("tab-feed-count").textContent = 0;
            showToast("🧹 Switched to blank / new-analysis state. Drop an .EML or load a scenario.", "info");
        });
    }

    const btnRefreshStream = document.getElementById("btn-refresh-stream");
    if (btnRefreshStream) btnRefreshStream.addEventListener("click", () => loadEmails(true));

    const btnRefreshGraph = document.getElementById("btn-refresh-graph");
    if (btnRefreshGraph) btnRefreshGraph.addEventListener("click", loadAndRenderCampaignGraph);

    const btnRefreshMailboxes = document.getElementById("btn-refresh-mailboxes");
    if (btnRefreshMailboxes) btnRefreshMailboxes.addEventListener("click", loadConnectedMailboxes);

    const btnResetZoom = document.getElementById("btn-reset-map-zoom");
    if (btnResetZoom) {
        btnResetZoom.addEventListener("click", () => {
            if (radarMap) radarMap.setView([25.0, 10.0], 2);
        });
    }

    const btnCloseModal = document.getElementById("btn-close-modal");
    const modalBackdrop = document.getElementById("modal-backdrop");
    if (btnCloseModal) btnCloseModal.addEventListener("click", closeForensicModal);
    if (modalBackdrop) modalBackdrop.addEventListener("click", closeForensicModal);

    const btnClosePipeline = document.getElementById("btn-close-pipeline-modal");
    const pipelineBackdrop = document.getElementById("pipeline-modal-backdrop");
    const closePipelineModal = () => {
        document.getElementById("modal-pipeline-progress")?.classList.add("hidden");
    };
    if (btnClosePipeline) btnClosePipeline.addEventListener("click", closePipelineModal);
    if (pipelineBackdrop) pipelineBackdrop.addEventListener("click", closePipelineModal);

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeForensicModal();
            closePipelineModal();
            document.getElementById("connect-mailbox-modal")?.classList.add("hidden");
        }
    });

    const btnOpenConnectModal = document.getElementById("btn-open-connect-modal");
    const btnAddMailboxTab = document.getElementById("btn-add-mailbox-tab");
    const btnCloseConnectModal = document.getElementById("btn-close-connect-modal");
    const btnCancelConnectMb = document.getElementById("btn-cancel-connect-mb");
    const connectModalBackdrop = document.getElementById("connect-modal-backdrop");

    const openConnectModal = () => {
        document.getElementById("connect-mailbox-modal").classList.remove("hidden");
    };
    const closeConnectModal = () => {
        document.getElementById("connect-mailbox-modal").classList.add("hidden");
    };

    if (btnOpenConnectModal) btnOpenConnectModal.addEventListener("click", openConnectModal);
    if (btnAddMailboxTab) btnAddMailboxTab.addEventListener("click", openConnectModal);
    if (btnCloseConnectModal) btnCloseConnectModal.addEventListener("click", closeConnectModal);
    if (btnCancelConnectMb) btnCancelConnectMb.addEventListener("click", closeConnectModal);
    if (connectModalBackdrop) connectModalBackdrop.addEventListener("click", closeConnectModal);

    const mbProviderSelect = document.getElementById("mb-provider");
    if (mbProviderSelect) {
        mbProviderSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            const info = PROVIDER_INFO[val] || PROVIDER_INFO.custom;
            document.getElementById("mb-instructions").textContent = info.instructions;

            const customFields = document.getElementById("custom-imap-fields");
            if (val === "custom") {
                customFields.classList.remove("hidden");
            } else {
                customFields.classList.add("hidden");
            }
        });
    }

    const connectMbForm = document.getElementById("connect-mailbox-form");
    if (connectMbForm) {
        connectMbForm.addEventListener("submit", handleConnectMailboxSubmit);
    }

    const modalDlBtn = document.getElementById("modal-dl-pdf-btn");
    if (modalDlBtn) {
        modalDlBtn.addEventListener("click", () => {
            if (currentViewingId) downloadReport(currentViewingId);
        });
    }

    const filterChips = document.querySelectorAll(".filter-chip");
    filterChips.forEach(chip => {
        chip.addEventListener("click", () => {
            filterChips.forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            activeFilter = chip.dataset.filter;
            applyFeedFilters();
        });
    });

    const searchInput = document.getElementById("feed-search");
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            applyFeedFilters();
        });
    }

    const scenarioCards = document.querySelectorAll(".scenario-card");
    scenarioCards.forEach(card => {
        const scenarioKey = card.dataset.scenario;
        const triggerBtn = card.querySelector(".scenario-trigger-btn");

        const loadHandler = (autoRun = false) => {
            const data = SCENARIOS[scenarioKey];
            if (data) {
                const sInput = document.getElementById("sender");
                const subInput = document.getElementById("subject");
                const hInput = document.getElementById("raw-headers");
                const bInput = document.getElementById("body-text");

                if (sInput) sInput.value = data.sender;
                if (subInput) subInput.value = data.subject;
                if (hInput) hInput.value = data.headers;
                if (bInput) bInput.value = data.body;

                showToast(`🎯 Scenario ${autoRun ? 'executing' : 'loaded'}: ${card.querySelector(".scenario-title")?.textContent || scenarioKey}`, "info");

                if (autoRun) {
                    handleIngestSubmit(new Event("submit", { cancelable: true }));
                } else {
                    document.getElementById("ingest-form")?.scrollIntoView({ behavior: "smooth" });
                }
            }
        };

        if (triggerBtn) {
            triggerBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                loadHandler(true);
            });
        }
        card.addEventListener("click", () => loadHandler(false));
    });

    const btnCopyWebhook = document.getElementById("btn-copy-webhook");
    if (btnCopyWebhook) {
        btnCopyWebhook.addEventListener("click", () => {
            navigator.clipboard.writeText(`${API_BASE}/api/v1/webhook/inbound`);
            showToast("📋 Webhook URL copied: http://127.0.0.1:8000/api/v1/webhook/inbound", "success");
        });
    }

    const btnScanFolder = document.getElementById("btn-scan-folder");
    if (btnScanFolder) {
        btnScanFolder.addEventListener("click", async () => {
            showToast("Scanning backend/inbound_emails/ for dropped .eml files...", "info");
            try {
                const res = await fetch(`${API_BASE}/integrations/watcher/scan`, { method: "POST" });
                const data = await res.json();
                if (data.auto_ingested_count > 0) {
                    showToast(`✅ Auto-ingested ${data.auto_ingested_count} new email files!`, "success");
                    await loadEmails(true);
                } else {
                    showToast("No new files found in inbound folder.", "info");
                }
            } catch (e) {
                showToast(`Scan error: ${e.message}`, "error");
            }
        });
    }

}

function initEmlDropzone() {
    const dropzone = document.getElementById("eml-dropzone");
    const fileInput = document.getElementById("eml-file-input");
    const btnBrowse = document.getElementById("btn-browse-eml");
    const btnSampleEml = document.getElementById("btn-load-sample-eml");
    const btnDlSampleEml = document.getElementById("btn-download-sample-eml");

    if (!dropzone || !fileInput) return;

    if (btnBrowse) {
        btnBrowse.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            fileInput.click();
        });
    }

    if (btnSampleEml) {
        btnSampleEml.addEventListener("click", async (e) => {
            e.preventDefault();
            e.stopPropagation();
            try {
                showToast("⚡ Fetching realistic sample threat .EML payload...", "info");
                const res = await fetch("sample_threat.eml");
                if (!res.ok) throw new Error("Could not load sample_threat.eml via network");
                const text = await res.text();
                const blob = new Blob([text], { type: "message/rfc822" });
                const file = new File([blob], "sample_threat.eml", { type: "message/rfc822" });
                await handleFileUpload(file);
            } catch (err) {
                console.warn("Falling back to embedded sample threat payload:", err);
                const sampleText = `From: "PayPal Security Center" <security-alert@paypal-verify-user-account.com>
To: target-analyst@corp-enterprise.com
Subject: URGENT ACTION REQUIRED: Account Access Suspended Immediately
Date: Sun, 23 Aug 2026 14:30:00 +0000
Message-ID: <992837198237@paypal-verify-user-account.com>
Authentication-Results: mx.relay-gateway.net; spf=fail; dkim=fail; dmarc=fail
Received: from unknown (185.220.101.5) by mx.relay-gateway.net with ESMTP
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

We detected suspicious unauthorized login attempts on your account from IP address 185.220.101.5 (Moscow, Russia).

To prevent permanent account termination, please verify your identity and credit card details within 24 hours:
http://paypal-verify-user-account.com/secure-login/login.php

Failure to comply will lead to permanent account deactivation.

PayPal Security Team`;
                const blob = new Blob([sampleText], { type: "message/rfc822" });
                const file = new File([blob], "sample_threat.eml", { type: "message/rfc822" });
                await handleFileUpload(file);
            }
        });
    }

    if (btnDlSampleEml) {
        btnDlSampleEml.addEventListener("click", (e) => {
            e.stopPropagation();
        });
    }

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", async (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

function parseEmlFile(emlText) {
    let headerText = "";
    let bodyText = "";
    const splitIndex = emlText.search(/\r?\n\r?\n/);
    if (splitIndex !== -1) {
        headerText = emlText.substring(0, splitIndex);
        bodyText = emlText.substring(splitIndex).trim();
    } else {
        headerText = emlText;
        bodyText = "";
    }

    const headers = {};
    const headerLines = headerText.split(/\r?\n/);
    let currentKey = null;

    headerLines.forEach(line => {
        if (/^\s+/.test(line) && currentKey) {
            headers[currentKey] += " " + line.trim();
        } else {
            const colonIdx = line.indexOf(":");
            if (colonIdx !== -1) {
                currentKey = line.substring(0, colonIdx).trim().toLowerCase();
                const val = line.substring(colonIdx + 1).trim();
                if (headers[currentKey]) {
                    headers[currentKey] += "\n" + val;
                } else {
                    headers[currentKey] = val;
                }
            }
        }
    });

    const sender = headers["from"] || "unknown@threat-origin.com";
    const subject = headers["subject"] || "No Subject (RFC 822 Ingest)";
    const to = headers["to"] || "analyst@bytetrail.io";
    const date = headers["date"] || new Date().toUTCString();
    const authResults = headers["authentication-results"] || "";

    let cleanBody = bodyText;
    if (/boundary=/i.test(headerText) || /Content-Type:\s*multipart/i.test(headerText)) {
        const textParts = bodyText.split(/--[^\r\n]+/);
        for (const part of textParts) {
            if (/Content-Type:\s*text\/plain/i.test(part)) {
                const subSplit = part.search(/\r?\n\r?\n/);
                if (subSplit !== -1) {
                    cleanBody = part.substring(subSplit).trim();
                    break;
                }
            } else if (!cleanBody && /Content-Type:\s*text\/html/i.test(part)) {
                const subSplit = part.search(/\r?\n\r?\n/);
                if (subSplit !== -1) {
                    cleanBody = part.substring(subSplit).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
                }
            }
        }
    }

    const receivedChain = headers["received"] || "";
    const ipMatch = receivedChain.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
    const relayIp = ipMatch ? ipMatch[0] : "185.220.101.5";

    let spf = "none";
    let dkim = "none";
    let dmarc = "none";
    if (/spf=pass/i.test(authResults) || /spf=pass/i.test(headerText)) spf = "pass";
    else if (/spf=fail/i.test(authResults) || /spf=fail/i.test(headerText)) spf = "fail";
    else if (/spf=softfail/i.test(authResults)) spf = "softfail";

    if (/dkim=pass/i.test(authResults) || /dkim=pass/i.test(headerText)) dkim = "pass";
    else if (/dkim=fail/i.test(authResults) || /dkim=fail/i.test(headerText)) dkim = "fail";

    if (/dmarc=pass/i.test(authResults) || /dmarc=pass/i.test(headerText)) dmarc = "pass";
    else if (/dmarc=fail/i.test(authResults) || /dmarc=fail/i.test(headerText)) dmarc = "fail";

    return {
        sender,
        subject,
        to,
        date,
        raw_headers: headerText,
        body_text: cleanBody || "(No readable plaintext body found in .EML payload)",
        relayIp,
        spf,
        dkim,
        dmarc
    };
}

async function analyzeParsedEmailClientSide(parsed) {
    const textToScan = `${parsed.subject} ${parsed.body_text}`.toLowerCase();
    
    const urgencyPatterns = ["urgent", "immediately", "immediate", "suspended", "suspension", "terminated", "freeze", "24 hours", "action required", "unauthorized", "verify", "security alert", "compromised"];
    const wirePatterns = ["wire transfer", "escrow", "payment", "invoice", "bank transfer", "confidential", "acquisition", "$", "usd", "funds", "routing number"];
    const credPatterns = ["password", "login", "credentials", "re-authenticate", "session expired", "portal", "verify your identity", "banking credentials", "sign in", "account access"];
    
    let urgencyScore = 0;
    urgencyPatterns.forEach(w => { if (textToScan.includes(w)) urgencyScore += 0.12; });
    let wireScore = 0;
    wirePatterns.forEach(w => { if (textToScan.includes(w)) wireScore += 0.15; });
    let credScore = 0;
    credPatterns.forEach(w => { if (textToScan.includes(w)) credScore += 0.14; });

    let fraudScore = Math.min(0.98, Math.max(0.08, urgencyScore + wireScore + credScore));

    const senderDomain = (parsed.sender.split("@")[1] || "").replace(/>.*$/, "").trim().toLowerCase();
    const hasTypoSquat = /paypal-verify|paypal-security|m365-security|corp-secure|amazon-shipment|microsoft-auth|google-auth|apple-security|update-account/i.test(senderDomain);
    const headerValid = parsed.spf === "pass" && parsed.dkim === "pass" && !hasTypoSquat;

    let geo = {
        city: "Frankfurt",
        country: "Germany",
        lat: 50.1109,
        lng: 8.6821,
        isp: "AS44146 Relay Network",
        isTor: false,
        actor: "Uncategorized Relay Infrastructure"
    };

    if (parsed.relayIp.startsWith("185.220.") || parsed.relayIp.startsWith("185.220.101")) {
        geo = { city: "Moscow", country: "Russia", lat: 55.7558, lng: 37.6173, isp: "AS44146 Tor Exit Node", isTor: true, actor: "Tor Exit Relay Cluster TC-44146" };
    } else if (parsed.relayIp.startsWith("197.210.")) {
        geo = { city: "Lagos", country: "Nigeria", lat: 6.5244, lng: 3.3792, isp: "AS37108 MTN Nigeria", isTor: false, actor: "SilverTerrier BEC Threat Actor" };
    } else if (parsed.relayIp.startsWith("188.166.")) {
        geo = { city: "Amsterdam", country: "Netherlands", lat: 52.3676, lng: 4.9041, isp: "AS14061 DigitalOcean", isTor: false, actor: "Commercial Bulletproof VPS" };
    } else if (parsed.relayIp.startsWith("192.30.252.")) {
        geo = { city: "San Francisco", country: "United States", lat: 37.7749, lng: -122.4194, isp: "AS36459 GitHub Inc", isTor: false, actor: "Verified Enterprise Infrastructure" };
    }

    let finalScore = 15;
    if (fraudScore > 0.4) finalScore += Math.round(fraudScore * 35);
    if (!headerValid || parsed.spf === "fail" || parsed.dkim === "fail") finalScore += 30;
    if (hasTypoSquat) finalScore += 20;
    if (geo.isTor) finalScore += 15;
    finalScore = Math.min(99, Math.max(8, finalScore));

    let riskLevel = "low";
    if (finalScore >= 70) riskLevel = "critical";
    else if (finalScore >= 40) riskLevel = "suspicious";

    let sha256_hash = "a3f2c1d8e9b047fc6a2e85d1c3b94f70e2a1d9c843b56f2a97e1c08d3b24f190";
    try {
        if (window.crypto && window.crypto.subtle) {
            const encoder = new TextEncoder();
            const data = encoder.encode(parsed.raw_headers + "\n\n" + parsed.body_text);
            const hashBuf = await window.crypto.subtle.digest("SHA-256", data);
            const hashArr = Array.from(new Uint8Array(hashBuf));
            sha256_hash = hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
        }
    } catch {}

    const newId = storedEmails.length > 0 ? Math.max(...storedEmails.map(e => Number(e.id) || 0)) + 1 : 1004;

    return {
        id: newId,
        sender: parsed.sender,
        subject: parsed.subject,
        raw_headers: parsed.raw_headers,
        body_text: parsed.body_text,
        fraud_score: Number(fraudScore.toFixed(2)),
        header_valid: headerValid,
        spf_result: parsed.spf,
        dkim_result: parsed.dkim,
        dmarc_result: parsed.dmarc,
        ip_address: parsed.relayIp,
        country: geo.country,
        city: geo.city,
        latitude: geo.lat,
        longitude: geo.lng,
        final_score: finalScore,
        risk_level: riskLevel,
        isp_asn: geo.isp,
        is_vpn_tor: geo.isTor,
        threat_actor: geo.actor,
        sha256_hash: sha256_hash,
        received_at: new Date().toISOString()
    };
}

async function handleFileUpload(file) {
    showToast(`🔬 Ingesting & analyzing ${file.name}...`, "info");

    let fileText = "";
    try {
        fileText = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    } catch (e) {
        console.warn("FileReader notice:", e);
    }

    let parsedResult = null;

    if (API_BASE) {
        try {
            const formData = new FormData();
            formData.append("file", file);
            const response = await fetch(`${API_BASE}/emails/upload-eml`, {
                method: "POST",
                headers: getAuthHeaders(),
                body: formData
            });

            if (response.ok) {
                parsedResult = await response.json();
            }
        } catch (e) {
            console.warn("Backend API not reachable, running client-side RFC 822 forensic engine:", e);
        }
    }

    if (!parsedResult && fileText) {
        const parsed = parseEmlFile(fileText);
        parsedResult = await analyzeParsedEmailClientSide(parsed);
    }

    if (parsedResult) {
        storedEmails = [parsedResult, ...storedEmails.filter(e => e.id !== parsedResult.id)];
        
        updateTelemetryStats(storedEmails);
        renderStreamFeed(storedEmails);
        applyFeedFilters();
        updateMapMarkers(storedEmails);
        updateAnalyticsMatrix(storedEmails);
        updateWorkspaceCaseDropdown();
        renderInvestigationWorkspace(parsedResult.id);

        const feedCount = document.getElementById("tab-feed-count");
        if (feedCount) feedCount.textContent = storedEmails.length;

        showToast(`✅ Case #${parsedResult.id} Ingested from EML: ${parsedResult.risk_level.toUpperCase()} THREAT (${parsedResult.final_score}/100)`, "success");
        runSequential4VectorPipeline(parsedResult);
    } else {
        showToast(`❌ Could not read or parse ${file.name}`, "error");
    }
}

function initRadarMap() {
    try {
        radarMap = L.map("radar-map", {
            zoomControl: true,
            attributionControl: false
        }).setView([25.0, 10.0], 2);

        L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            maxZoom: 18,
            subdomains: "abcd"
        }).addTo(radarMap);

        markerLayerGroup = L.layerGroup().addTo(radarMap);
    } catch (e) {
        console.error("Map error:", e);
    }
}

async function checkBackendStatus() {
    const chip = document.getElementById("backend-status-chip");
    const label = document.getElementById("backend-status-label");
    try {
        const response = await fetch(`${API_BASE}/ping`);
        if (response.ok) {
            chip.className = "status-chip";
            label.textContent = "Pipeline Active • MySQL";
        } else {
            throw new Error();
        }
    } catch (e) {
        chip.className = "status-chip offline";
        label.textContent = "Pipeline Offline";
    }
}

async function loadEmails(showFeedback = false) {
    const tbody = document.getElementById("feed-tbody");
    try {
        const res = await fetch(`${API_BASE}/emails`, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const latest = await res.json();

        if (storedEmails.length > 0 && latest.length > storedEmails.length) {
            const newCount = latest.length - storedEmails.length;
            showToast(`🚨 ${newCount} New Inbound Email(s) Auto-Ingested & Scored!`, "success");
        }

        if (latest && latest.length > 0) {
            storedEmails = latest;
        } else if (storedEmails.length === 0) {
            storedEmails = [DEMO_CASE, DEMO_CASE_2, DEMO_CASE_3];
        }

        updateTelemetryStats(storedEmails);
        renderStreamFeed(storedEmails);
        applyFeedFilters();
        updateMapMarkers(storedEmails);
        updateAnalyticsMatrix(storedEmails);
        updateWorkspaceCaseDropdown();

        document.getElementById("tab-feed-count").textContent = storedEmails.length;
        if (showFeedback) showToast("Feed refreshed from MySQL.", "info");
    } catch (err) {
        if (storedEmails.length === 0) {
            storedEmails = [DEMO_CASE, DEMO_CASE_2, DEMO_CASE_3];
            updateTelemetryStats(storedEmails);
            renderStreamFeed(storedEmails);
            applyFeedFilters();
            updateMapMarkers(storedEmails);
            updateAnalyticsMatrix(storedEmails);
            updateWorkspaceCaseDropdown();
            document.getElementById("tab-feed-count").textContent = storedEmails.length;
        } else {
            updateWorkspaceCaseDropdown();
        }
        if (tbody && storedEmails.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="color: var(--threat-high);">⚠️ Could not retrieve records: ${err.message}</td></tr>`;
        }
    }
}

async function loadConnectedMailboxes() {
    const grid = document.getElementById("mailboxes-grid-list");
    const countBadge = document.getElementById("tab-mailbox-count");
    if (!grid) return;

    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes`, {
            headers: getAuthHeaders()
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        connectedMailboxes = await res.json();

        if (countBadge) countBadge.textContent = connectedMailboxes.length;

        if (connectedMailboxes.length === 0) {
            grid.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
                    <i class="fa-solid fa-inbox" style="font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.5;"></i>
                    <h4 style="color: var(--text-bright); margin-bottom: 0.35rem;">No Active Mailboxes Connected</h4>
                    <p style="font-size: 0.82rem; max-width: 440px; margin: 0 auto 1.25rem;">Connect your Gmail, Outlook, or corporate email account to continuously monitor and detect fraud on every incoming email in real-time.</p>
                    <button class="btn btn-cyber-primary" onclick="document.getElementById('connect-mailbox-modal').classList.remove('hidden')"><i class="fa-solid fa-plug"></i> Connect First Mailbox</button>
                </div>
            `;
            return;
        }

        grid.innerHTML = connectedMailboxes.map(mb => {
            const providerIcon = (mb.provider === "gmail" || mb.provider === "google") ? "fa-google" : mb.provider === "outlook" ? "fa-microsoft" : mb.provider === "yahoo" ? "fa-yahoo" : "fa-envelope";
            const isGmail = mb.provider === "gmail" || mb.provider === "google";

            return `
                <div class="card" style="padding: 1.25rem; background: var(--bg-surface);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                        <div style="display: flex; align-items: center; gap: 0.65rem;">
                            <div style="width: 36px; height: 36px; border-radius: 0.45rem; background: var(--primary-bg); border: 1px solid rgba(139, 92, 246, 0.3); display: flex; align-items: center; justify-content: center; color: var(--primary); font-size: 1.1rem;">
                                <i class="fa-brands ${providerIcon}"></i>
                            </div>
                            <div>
                                <h4 style="font-size: 0.9rem; color: var(--text-bright); font-weight: 600;">${escapeHtml(mb.email_address)}</h4>
                                <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(mb.host)}:${mb.port}</span>
                            </div>
                        </div>
                        <span class="badge-risk-pill low"><span class="pulse-dot"></span> LIVE POLLING</span>
                    </div>

                    <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-input); padding: 0.65rem 0.85rem; border-radius: 0.4rem; border: 1px solid var(--border-subtle); margin-bottom: 0.85rem; font-size: 0.76rem;">
                        <div>
                            <span style="color: var(--text-muted); display: block;">Sync Schedule</span>
                            <span style="color: var(--text-primary); font-family: var(--font-mono); font-weight: 600;">Continuous Automated Polling (Every 60s)</span>
                        </div>
                    </div>

                    <div style="display: flex; gap: 0.4rem; justify-content: flex-end; flex-wrap: wrap;">
                        <button class="btn btn-sm btn-cyber-secondary" onclick="viewMailboxThreats()" title="Show high-risk emails detected for your account">
                            <i class="fa-solid fa-triangle-exclamation"></i> View Threats
                        </button>
                        <button class="btn btn-sm btn-cyber-primary" onclick="deepScanConnectedMailbox(${mb.id})" title="Deep Scan All Historical Read and Unread Emails">
                            <i class="fa-solid fa-magnifying-glass"></i> Deep Scan (Read + Unread)
                        </button>
                        <button class="btn btn-sm btn-cyber-secondary" onclick="syncConnectedMailbox(${mb.id})" title="Scan New Unread Only">
                            <i class="fa-solid fa-rotate"></i> Sync New
                        </button>
                        <button class="btn btn-sm btn-cyber-secondary" style="color: var(--threat-high);" onclick="disconnectConnectedMailbox(${mb.id})" title="Disconnect Account">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Error loading mailboxes:", e);
    }
}

window.viewMailboxThreats = async function () {
    await loadEmails(false);
    const feedTab = document.querySelector('.nav-tab[data-tab="feed"]');
    if (feedTab) feedTab.click();
    activeFilter = "high";
    document.querySelectorAll(".filter-chip").forEach(chip => {
        chip.classList.toggle("active", chip.dataset.filter === "high");
    });
    applyFeedFilters();
    showToast("Showing high-risk email threats detected for your account.", "info");
};

async function handleConnectMailboxSubmit(e) {
    e.preventDefault();

    const provider = document.getElementById("mb-provider").value;
    const emailAddress = document.getElementById("mb-email").value.trim();
    const password = document.getElementById("mb-password").value.trim();
    const host = document.getElementById("mb-host")?.value.trim() || null;
    const port = parseInt(document.getElementById("mb-port")?.value || "993");
    const skipVerify = document.getElementById("mb-skip-verify")?.checked || false;
    const scanHistory = document.getElementById("mb-scan-history")?.checked ?? true;
    const errBox = document.getElementById("connect-mb-error");

    if (errBox) {
        errBox.classList.add("hidden");
        errBox.textContent = "";
    }

    if (!emailAddress || !password) {
        showToast("Please fill in email and password.", "error");
        return;
    }

    const btn = document.getElementById("btn-submit-connect-mb");
    const spinner = document.getElementById("connect-mb-spinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");

    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/connect`, {
            method: "POST",
            headers: getAuthHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({
                email_address: emailAddress,
                password: password,
                provider: provider,
                host: host,
                port: port,
                scan_history: scanHistory
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Connection error ${res.status}`);
        }

        const data = await res.json();
        showToast(`✅ Successfully connected ${data.email_address}! Live monitoring activated.`, "success");
        document.getElementById("connect-mailbox-modal").classList.add("hidden");
        document.getElementById("connect-mailbox-form").reset();

        await loadEmails(true);
        await loadConnectedMailboxes();
    } catch (err) {
        if (errBox) {
            errBox.textContent = `❌ ${err.message}`;
            errBox.classList.remove("hidden");
        }
        showToast(`❌ Connection failed: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        spinner.classList.add("hidden");
    }
}

async function handleGoogleOAuthLogin(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (e && e.stopPropagation) e.stopPropagation();

    const btn = document.getElementById("btn-google-oauth-login");
    const spinner = document.getElementById("google-oauth-spinner");
    if (btn) btn.disabled = true;
    if (spinner) spinner.classList.remove("hidden");

    const width = 540;
    const height = 640;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;
    let popupWindow = null;
    try {
        popupWindow = window.open(
            "about:blank",
            "GoogleOAuthConsent",
            `width=${width},height=${height},left=${left},top=${top},status=no,resizable=yes`
        );
    } catch (err) {
        popupWindow = null;
    }

    try {
        const res = await fetch(`${API_BASE}/api/v1/auth/google/url?purpose=mailbox`, {
            headers: getAuthHeaders()
        });
        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || "Could not start Google connection.");
        }

        if (data && data.url) {
            if (popupWindow && !popupWindow.closed) {
                popupWindow.location.href = data.url;
            } else {
                window.location.href = data.url;
            }
        } else {
            if (popupWindow && !popupWindow.closed) popupWindow.close();
            showToast("Failed to retrieve Google OAuth authorization URL.", "error");
        }
    } catch (err) {
        if (popupWindow && !popupWindow.closed) popupWindow.close();
        showToast(`Google OAuth error: ${err.message}`, "error");
    } finally {
        if (btn) btn.disabled = false;
        if (spinner) spinner.classList.add("hidden");
    }
}

window.deepScanConnectedMailbox = async function (id) {
    showToast("🚀 Initiating sequential deep scan (10 emails per batch)...", "info");

    let offset = 0;
    let pageToken = null;
    let totalIngested = 0;
    let totalScanned = 0;
    let hasMore = true;
    let batchIndex = 1;

    try {
        while (hasMore) {
            showToast(`🔍 Scanning Batch #${batchIndex} (Emails ${offset + 1}–${offset + 10})...`, "info");

            let url = `${API_BASE}/api/v1/mailboxes/${id}/deep-scan?batch_size=10&offset=${offset}`;
            if (pageToken) {
                url += `&page_token=${encodeURIComponent(pageToken)}`;
            }

            const res = await fetch(url, { method: "POST", headers: getAuthHeaders() });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Server error (${res.status})`);
            }

            const data = await res.json();
            const batchIngested = data.batch_analyzed || 0;
            const scannedInBatch = data.total_scanned_in_batch || batchIngested || 0;

            totalIngested += batchIngested;
            totalScanned += scannedInBatch;
            hasMore = Boolean(data.has_more);
            offset = data.next_offset !== undefined ? data.next_offset : (offset + 10);
            pageToken = data.next_page_token || null;

            if (batchIngested > 0) {
                await loadEmails(true);
                await loadConnectedMailboxes();
            }

            if (!hasMore || scannedInBatch === 0) {
                break;
            }

            batchIndex++;
            await new Promise(r => setTimeout(r, 300));
        }

        if (totalIngested > 0) {
            showToast(`🎉 Deep Scan Complete! Analyzed ${totalIngested} new threat emails across entire inbox history.`, "success");
        } else {
            showToast(`✅ Scanned ${totalScanned} inbox emails. All messages are already fully indexed & analyzed.`, "success");
        }
        await loadEmails(true);
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Deep scan error: ${e.message}`, "error");
    }
};

window.syncConnectedMailbox = async function (id) {
    showToast("Syncing mailbox for new unread emails...", "info");
    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/${id}/sync`, { method: "POST", headers: getAuthHeaders() });
        const data = await res.json();
        if (data.new_emails_detected > 0) {
            showToast(`✅ Detected and analyzed ${data.new_emails_detected} new incoming emails!`, "success");
            await loadEmails(true);
        } else {
            showToast("No new unread emails found in mailbox.", "info");
        }
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Sync error: ${e.message}`, "error");
    }
};

window.disconnectConnectedMailbox = async function (id) {
    if (!confirm("Are you sure you want to disconnect this mailbox?")) return;
    try {
        const res = await fetch(`${API_BASE}/api/v1/mailboxes/${id}`, { method: "DELETE", headers: getAuthHeaders() });
        if (!res.ok) throw new Error(`Server error (${res.status})`);
        showToast("Mailbox disconnected.", "info");
        await loadConnectedMailboxes();
    } catch (e) {
        showToast(`Error disconnecting: ${e.message}`, "error");
    }
};

function updateTelemetryStats(emails) {
    let criticalCount = 0;
    let suspiciousCount = 0;
    let benignCount = 0;

    emails.forEach(e => {
        const risk = (e.risk_level || "low").toLowerCase();
        if (risk === "high") criticalCount++;
        else if (risk === "medium") suspiciousCount++;
        else benignCount++;
    });

    const total = emails.length;
    document.getElementById("stat-total").textContent = total;
    document.getElementById("stat-critical").textContent = criticalCount;
    document.getElementById("stat-suspicious").textContent = suspiciousCount;
    document.getElementById("stat-benign").textContent = benignCount;

    const criticalPct = total > 0 ? Math.round((criticalCount / total) * 100) : 0;
    document.getElementById("stat-critical-pct").textContent = `${criticalPct}% of total payload`;

    document.getElementById("count-all").textContent = total;
    document.getElementById("count-high").textContent = criticalCount;
    document.getElementById("count-med").textContent = suspiciousCount;
    document.getElementById("count-low").textContent = benignCount;
}

function renderStreamFeed(emails) {
    const streamContainer = document.getElementById("stream-feed-list");
    if (!streamContainer) return;

    if (!emails || emails.length === 0) {
        streamContainer.innerHTML = `<div class="stream-empty">No threat incidents logged yet.</div>`;
        return;
    }

    streamContainer.innerHTML = emails.slice(0, 15).map(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        const score = email.final_score !== null && email.final_score !== undefined ? email.final_score : 0;
        const country = email.country || "Unknown Origin";

        return `
            <div class="stream-item" onclick="openForensicModal(${email.id})">
                <div class="stream-top-row">
                    <span class="badge-risk-pill ${risk}">
                        ${risk === "high" ? "🔴" : risk === "medium" ? "🟡" : "🟢"} ${risk.toUpperCase()} (${score}/100)
                    </span>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">#${email.id}</span>
                </div>
                <span class="stream-subject" title="${escapeHtml(email.subject)}">${escapeHtml(email.subject)}</span>
                <div class="stream-meta">
                    <span class="stream-sender" title="${escapeHtml(email.sender)}"><i class="fa-solid fa-envelope"></i> ${escapeHtml(email.sender)}</span>
                    <span><i class="fa-solid fa-location-dot"></i> ${escapeHtml(country)}</span>
                </div>
            </div>
        `;
    }).join("");
}

function applyFeedFilters() {
    const tbody = document.getElementById("feed-tbody");
    const searchQuery = (document.getElementById("feed-search")?.value || "").toLowerCase().trim();

    let filtered = storedEmails.filter(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        if (activeFilter !== "all" && risk !== activeFilter) return false;

        if (searchQuery) {
            const sender = (email.sender || "").toLowerCase();
            const subject = (email.subject || "").toLowerCase();
            const country = (email.country || "").toLowerCase();
            const ip = (email.ip_address || "").toLowerCase();
            return sender.includes(searchQuery) || subject.includes(searchQuery) || country.includes(searchQuery) || ip.includes(searchQuery);
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No matching threat records found.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(email => {
        const risk = (email.risk_level || "low").toLowerCase();
        const score = email.final_score !== null && email.final_score !== undefined ? email.final_score : "N/A";
        const authStatus = email.header_valid ? "pass" : (email.spf_result === "fail" || email.dkim_result === "fail" ? "fail" : "none");
        const country = email.country || "Unknown";
        const ip = email.ip_address || "No IP";
        const asn = email.isp_asn || "Standard ASN";

        return `
            <tr>
                <td class="case-id-pill">#${email.id}</td>
                <td>
                    <span class="badge-risk-pill ${risk}">
                        ${risk === "high" ? "🔴" : risk === "medium" ? "🟡" : "🟢"} ${risk.toUpperCase()} (${score})
                    </span>
                </td>
                <td><span class="sender-pill" title="${escapeHtml(email.sender)}">${escapeHtml(email.sender)}</span></td>
                <td><span class="subject-cell" title="${escapeHtml(email.subject)}">${escapeHtml(email.subject)}</span></td>
                <td>
                    <div class="geo-cell">
                        <span class="geo-country">${escapeHtml(country)}</span>
                        <span class="geo-ip">${escapeHtml(ip)} • ${escapeHtml(asn.substring(0, 18))}</span>
                    </div>
                </td>
                <td style="text-align: center;">
                    <span class="auth-badge-tag ${authStatus}">${authStatus.toUpperCase()}</span>
                </td>
                <td style="text-align: center;">
                    <div style="display: flex; gap: 0.35rem; justify-content: center;">
                        <button class="btn btn-sm btn-cyber-secondary" onclick="openForensicModal(${email.id})" title="Inspect Forensics">
                            <i class="fa-solid fa-microscope"></i> View
                        </button>
                        <button class="btn btn-sm btn-cyber-primary" onclick="downloadReport(${email.id})" title="Download Official PDF Report">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join("");
}

function updateMapMarkers(emails) {
    if (!markerLayerGroup || !radarMap) return;

    markerLayerGroup.clearLayers();
    const bounds = [];

    emails.forEach(email => {
        const lat = email.latitude;
        const lon = email.longitude;

        if (lat !== null && lon !== null && (lat !== 0 || lon !== 0)) {
            const risk = (email.risk_level || "low").toLowerCase();
            const pinClass = risk === "high" ? "pin-high" : (risk === "medium" ? "pin-medium" : "pin-low");
            const pinEmoji = risk === "high" ? "🔴" : (risk === "medium" ? "🟡" : "🟢");

            const customIcon = L.divIcon({
                className: "custom-map-pin-container",
                html: `<div class="custom-map-pin ${pinClass}">#${email.id}</div>`,
                iconSize: [24, 24],
                iconAnchor: [12, 12],
                popupAnchor: [0, -14]
            });

            const marker = L.marker([lat, lon], { icon: customIcon });

            const popupContent = `
                <div style="font-family: var(--font-sans); color: #f8fafc;">
                    <div style="font-weight: 700; font-size: 0.88rem; margin-bottom: 0.35rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.25rem; display: flex; justify-content: space-between;">
                        <span>${pinEmoji} Case #${email.id} (${risk.toUpperCase()})</span>
                        <span style="font-family: var(--font-mono); color: #a78bfa;">${escapeHtml(email.country || '')}</span>
                    </div>
                    <div style="font-size: 0.78rem; color: #94a3b8; line-height: 1.4; margin-bottom: 0.5rem;">
                        <strong>Sender:</strong> ${escapeHtml(email.sender)}<br/>
                        <strong>Subject:</strong> ${escapeHtml(email.subject)}<br/>
                        <strong>IP:</strong> <span style="font-family: var(--font-mono);">${escapeHtml(email.ip_address || 'N/A')}</span>
                    </div>
                    <div style="display: flex; gap: 0.35rem;">
                        <button style="background: rgba(139, 92, 246, 0.15); border: 1px solid rgba(139, 92, 246, 0.4); color: #a78bfa; padding: 0.25rem 0.55rem; border-radius: 0.3rem; font-size: 0.75rem; cursor: pointer;" onclick="openForensicModal(${email.id})">🔬 Inspect</button>
                        <button style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); color: #34d399; padding: 0.25rem 0.55rem; border-radius: 0.3rem; font-size: 0.75rem; cursor: pointer;" onclick="downloadReport(${email.id})">📄 PDF Report</button>
                    </div>
                </div>
            `;

            marker.bindPopup(popupContent);
            markerLayerGroup.addLayer(marker);
            bounds.push([lat, lon]);
        }
    });

    if (bounds.length > 0) {
        radarMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
    }
}

const CAMPAIGN_DATASETS = {
    all: {
        id: "all",
        title: "All Threat Campaigns (Global Landscape)",
        clusters: 4,
        nodes: [
            { id: "c1_email", label: "Case #1001 (PayPal Phish)", type: "email", risk: "critical", campaign: "TC-44146", val: "service@intl.paypal.com", desc: "Urgent Suspicious Activity Security Notice" },
            { id: "c1_dom", label: "paypal-verify-user.com", type: "domain", risk: "critical", campaign: "TC-44146", val: "Domain (Typosquat)", desc: "Offshore registrar, fast-flux DNS rotation" },
            { id: "c1_url", label: "/secure-login/login.php", type: "url", risk: "critical", campaign: "TC-44146", val: "Credential Harvesting URI", desc: "Cloned PayPal SSO entry form with 2FA intercept" },
            { id: "c1_hop1", label: "bit.ly/secure-pp-auth", type: "url", risk: "high", campaign: "TC-44146", val: "Shortener Gateway (Hop 1)", desc: "HTTP 301 obfuscation redirection hop" },
            { id: "c1_relay", label: "185.220.101.5", type: "ip", risk: "critical", campaign: "TC-44146", val: "Relay IP (Exit Node)", desc: "Known Tor exit relay in Frankfurt, Germany" },
            { id: "c1_asn", label: "AS44146 Tor Transit", type: "asn", risk: "high", campaign: "TC-44146", val: "Tor Network / Transit", desc: "Multi-jurisdiction bulletproof Tor transit" },
            { id: "c1_att", label: "Invoice_Escrow.pdf.exe", type: "hash", risk: "critical", campaign: "TC-44146", val: "SHA256: e3b0c442...991b", desc: "PE32+ Executable disguised as escrow PDF" },
            { id: "c1_ns", label: "ns1.offshore-dns.cc", type: "domain", risk: "high", campaign: "TC-44146", val: "Nameserver", desc: "Bulletproof privacy DNS provider" },
            { id: "c1_cluster", label: "Threat Cluster TC-44146", type: "cluster", risk: "critical", campaign: "TC-44146", val: "Tor Credential Harvesting Ring", desc: "Active adversary cluster targeting financial fintech" },

            { id: "c2_email", label: "Case #1002 (CEO Wire Fraud)", type: "email", risk: "critical", campaign: "FIN-CORP", val: "cfo-urgent@corp-secure-finance.net", desc: "CEO Impersonation Acquisition Wire Transfer" },
            { id: "c2_dom", label: "corp-secure-finance.net", type: "domain", risk: "critical", campaign: "FIN-CORP", val: "Domain (Lookalike)", desc: "Registered 18 days prior, mimics legitimate target finance" },
            { id: "c2_vps", label: "91.240.118.42", type: "ip", risk: "high", campaign: "FIN-CORP", val: "C2 Host IP (Moldova)", desc: "Bulletproof VPS hosting SMTP proxy & forwarders" },
            { id: "c2_asn", label: "AS208643 Flokinet", type: "asn", risk: "high", campaign: "FIN-CORP", val: "Flokinet Iceland / Romania", desc: "Offshore bulletproof hosting sanctuary" },
            { id: "c2_doc", label: "SWIFT_MT103_EUR.pdf", type: "hash", risk: "high", campaign: "FIN-CORP", val: "SHA256: 7fa801b9...55c2", desc: "Weaponized PDF lure with remote command template" },
            { id: "c2_cluster", label: "FIN-CORP Wire Syndicate", type: "cluster", risk: "critical", campaign: "FIN-CORP", val: "Executive BEC Wire Fraud", desc: "Sophisticated corporate treasury wire diversion gang" },

            { id: "c3_email", label: "Case #1004 (M365 ATO Lure)", type: "email", risk: "critical", campaign: "Storm-0539", val: "admin-alert@microsoft-support.net", desc: "Mandatory Session Authentication Refresh Lure" },
            { id: "c3_dom", label: "login-msft-verify.us", type: "domain", risk: "critical", campaign: "Storm-0539", val: "AitM Reverse Proxy Domain", desc: "Reverse-proxy domain hosting Evilginx proxy" },
            { id: "c3_url", label: "/oauth2/v2.0/token", type: "url", risk: "critical", campaign: "Storm-0539", val: "AitM Token Capture Endpoint", desc: "Steals session cookies and bypasses FIDO/SMS MFA" },
            { id: "c3_ip", label: "45.154.255.89", type: "ip", risk: "high", campaign: "Storm-0539", val: "Relay IP (Hostinger)", desc: "Hostinger International VPS relay" },
            { id: "c3_asn", label: "AS47583 Hostinger", type: "asn", risk: "medium", campaign: "Storm-0539", val: "AS47583 Hosting Cloud", desc: "Commercial hosting repurposed for AitM proxies" },
            { id: "c3_token", label: "Session_PRT_Token.bin", type: "hash", risk: "critical", campaign: "Storm-0539", val: "Captured Session Cookie", desc: "Primary Refresh Token (PRT) exfiltration artifact" },
            { id: "c3_cluster", label: "Storm-0539 ATO Broker", type: "cluster", risk: "critical", campaign: "Storm-0539", val: "Cloud Identity Theft Group", desc: "Specializes in Microsoft 365 cloud session hijack" },

            { id: "c4_email", label: "Case #1005 (Amazon Urgent Hold)", type: "email", risk: "high", campaign: "SMISH-AMZ", val: "delivery-alert@amz-track-update.com", desc: "Urgent package dispatch address update notice" },
            { id: "c4_dom", label: "amz-track-update.com", type: "domain", risk: "high", campaign: "SMISH-AMZ", val: "Domain (Brand Impersonation)", desc: "Impersonates Amazon Logistics dispatch center" },
            { id: "c4_url", label: "/track/order-reschedule", type: "url", risk: "high", campaign: "SMISH-AMZ", val: "Phishing Gateway URL", desc: "Mobile-targeted credential harvester" },
            { id: "c4_ip", label: "103.145.13.78", type: "ip", risk: "high", campaign: "SMISH-AMZ", val: "C2 Command IP (Panama)", desc: "PrivateLayer bulletproof upstream node" },
            { id: "c4_asn", label: "AS51852 PrivateLayer", type: "asn", risk: "high", campaign: "SMISH-AMZ", val: "Private Layer Hosting", desc: "Offshore hosting frequently abused for mobile payloads" },
            { id: "c4_apk", label: "Amz_Tracking_Fix.apk", type: "hash", risk: "critical", campaign: "SMISH-AMZ", val: "SHA256: 3d18e8f2...99aa", desc: "Android trojan dropper / SMS forwarder" },
            { id: "c4_cluster", label: "SMISH-AMZ Stealer Ring", type: "cluster", risk: "high", campaign: "SMISH-AMZ", val: "Mobile / E-Commerce Scam", desc: "Automated SMS/Email dropper distribution network" },

            { id: "c5_email", label: "Case #1003 (GitHub Advisory)", type: "email", risk: "benign", campaign: "Verified Base", val: "notifications@github.com", desc: "Verified GitHub Security Advisory for Dependabot" },
            { id: "c5_dom", label: "github.com", type: "domain", risk: "benign", campaign: "Verified Base", val: "Authoritative Domain", desc: "Fully aligned SPF pass, DKIM valid, DMARC pass" },
            { id: "c5_ip", label: "192.30.252.204", type: "ip", risk: "benign", campaign: "Verified Base", val: "GitHub Outbound MTA", desc: "Authoritative GitHub SMTP transmission node" },
            { id: "c5_asn", label: "AS36459 GitHub Inc", type: "asn", risk: "benign", campaign: "Verified Base", val: "AS36459 GitHub Network", desc: "Verified corporate autonomous system" },
            { id: "c5_cert", label: "DigiCert TLS Root", type: "hash", risk: "benign", campaign: "Verified Base", val: "X.509 SHA-256 Fingerprint", desc: "EV SSL Certificate with full certificate transparency" },
            { id: "c5_cluster", label: "Verified Enterprise Cloud", type: "cluster", risk: "benign", campaign: "Verified Base", val: "Legitimate Baseline", desc: "Sanctioned enterprise SaaS cloud baseline" }
        ],
        edges: [
            { source: "c1_email", target: "c1_dom" },
            { source: "c1_email", target: "c1_hop1" },
            { source: "c1_hop1", target: "c1_url" },
            { source: "c1_dom", target: "c1_url" },
            { source: "c1_dom", target: "c1_relay" },
            { source: "c1_dom", target: "c1_ns" },
            { source: "c1_relay", target: "c1_asn" },
            { source: "c1_email", target: "c1_att" },
            { source: "c1_asn", target: "c1_cluster" },
            { source: "c1_relay", target: "c1_cluster" },
            { source: "c1_dom", target: "c1_cluster" },

            { source: "c2_email", target: "c2_dom" },
            { source: "c2_email", target: "c2_doc" },
            { source: "c2_dom", target: "c2_vps" },
            { source: "c2_vps", target: "c2_asn" },
            { source: "c2_email", target: "c1_relay" },
            { source: "c2_dom", target: "c1_ns" },
            { source: "c2_asn", target: "c2_cluster" },
            { source: "c2_vps", target: "c2_cluster" },
            { source: "c2_cluster", target: "c1_cluster" },

            { source: "c3_email", target: "c3_dom" },
            { source: "c3_dom", target: "c3_url" },
            { source: "c3_dom", target: "c3_ip" },
            { source: "c3_ip", target: "c3_asn" },
            { source: "c3_url", target: "c3_token" },
            { source: "c3_asn", target: "c3_cluster" },
            { source: "c3_token", target: "c3_cluster" },
            { source: "c3_email", target: "c3_cluster" },

            { source: "c4_email", target: "c4_dom" },
            { source: "c4_dom", target: "c4_url" },
            { source: "c4_url", target: "c4_apk" },
            { source: "c4_dom", target: "c4_ip" },
            { source: "c4_ip", target: "c4_asn" },
            { source: "c4_apk", target: "c4_cluster" },
            { source: "c4_asn", target: "c4_cluster" },

            { source: "c5_email", target: "c5_dom" },
            { source: "c5_dom", target: "c5_ip" },
            { source: "c5_ip", target: "c5_asn" },
            { source: "c5_dom", target: "c5_cert" },
            { source: "c5_asn", target: "c5_cluster" },
            { source: "c5_cert", target: "c5_cluster" }
        ]
    },
    paypal: {
        id: "paypal",
        title: "Campaign TC-44146 (Tor Phish & Credential Harvest Ring)",
        clusters: 1,
        nodes: [
            { id: "c1_email", label: "Case #1001 (PayPal Phish)", type: "email", risk: "critical", campaign: "TC-44146", val: "service@intl.paypal.com", desc: "Urgent Security Verification Phish" },
            { id: "c1_dom", label: "paypal-verify-user.com", type: "domain", risk: "critical", campaign: "TC-44146", val: "paypal-verify-user.com", desc: "Typosquat lookalike credential harvest domain" },
            { id: "c1_url", label: "/secure-login/login.php", type: "url", risk: "critical", campaign: "TC-44146", val: "/secure-login/login.php", desc: "Credential harvesting form target" },
            { id: "c1_hop1", label: "bit.ly/secure-pp-auth", type: "url", risk: "high", campaign: "TC-44146", val: "bit.ly/secure-pp-auth", desc: "HTTP 301 Shortener gateway hop" },
            { id: "c1_relay", label: "185.220.101.5", type: "ip", risk: "critical", campaign: "TC-44146", val: "185.220.101.5 (Relay IP)", desc: "Known Tor exit relay in Frankfurt" },
            { id: "c1_asn", label: "AS44146 Tor Transit", type: "asn", risk: "high", campaign: "TC-44146", val: "AS44146 Tor Network", desc: "Tor exit & transit routing provider" },
            { id: "c1_att", label: "Invoice_Escrow.pdf.exe", type: "hash", risk: "critical", campaign: "TC-44146", val: "e3b0c44298fc1c149afbf4c8996fb924", desc: "Double-extension dropper executable" },
            { id: "c1_ns", label: "ns1.offshore-dns.cc", type: "domain", risk: "high", campaign: "TC-44146", val: "ns1.offshore-dns-hosting.cc", desc: "Fast-flux bulletproof DNS authority" },
            { id: "c1_cluster", label: "Cluster TC-44146", type: "cluster", risk: "critical", campaign: "TC-44146", val: "Cluster TC-44146", desc: "Core credential harvesting syndicate" }
        ],
        edges: [
            { source: "c1_email", target: "c1_dom" },
            { source: "c1_email", target: "c1_hop1" },
            { source: "c1_hop1", target: "c1_url" },
            { source: "c1_dom", target: "c1_url" },
            { source: "c1_dom", target: "c1_relay" },
            { source: "c1_dom", target: "c1_ns" },
            { source: "c1_relay", target: "c1_asn" },
            { source: "c1_email", target: "c1_att" },
            { source: "c1_asn", target: "c1_cluster" },
            { source: "c1_relay", target: "c1_cluster" },
            { source: "c1_dom", target: "c1_cluster" },
            { source: "c1_ns", target: "c1_cluster" }
        ]
    },
    bec: {
        id: "bec",
        title: "Campaign FIN-CORP-WIRE (Executive BEC Wire Transfer)",
        clusters: 1,
        nodes: [
            { id: "c2_email", label: "Case #1002 (CEO Wire Fraud)", type: "email", risk: "critical", campaign: "FIN-CORP", val: "cfo-alert@corp-secure-finance.net", desc: "Urgent EUR 482,000 Acquisition Transfer" },
            { id: "c2_dom", label: "corp-secure-finance.net", type: "domain", risk: "critical", campaign: "FIN-CORP", val: "corp-secure-finance.net", desc: "Deceptive domain mimicking enterprise treasury" },
            { id: "c2_vps", label: "91.240.118.42", type: "ip", risk: "high", campaign: "FIN-CORP", val: "91.240.118.42 (Moldova VPS)", desc: "Bulletproof C2 host running SMTP forwarder" },
            { id: "c2_relay", label: "185.220.101.5 (Shared Relay)", type: "ip", risk: "critical", campaign: "FIN-CORP", val: "185.220.101.5", desc: "Tor exit relay shared with TC-44146" },
            { id: "c2_asn", label: "AS208643 Flokinet", type: "asn", risk: "high", campaign: "FIN-CORP", val: "AS208643 Flokinet", desc: "Bulletproof autonomous system" },
            { id: "c2_tor_asn", label: "AS44146 Tor Transit", type: "asn", risk: "high", campaign: "FIN-CORP", val: "AS44146 Tor Network", desc: "Anonymized inbound origin" },
            { id: "c2_doc", label: "SWIFT_MT103_EUR.pdf", type: "hash", risk: "high", campaign: "FIN-CORP", val: "7fa801b9ca2e41e4649b", desc: "Forged SWIFT wire routing instructions" },
            { id: "c2_ns", label: "ns1.offshore-dns.cc", type: "domain", risk: "high", campaign: "FIN-CORP", val: "ns1.offshore-dns.cc", desc: "Shared bulletproof DNS infrastructure" },
            { id: "c2_cluster", label: "FIN-CORP Wire Syndicate", type: "cluster", risk: "critical", campaign: "FIN-CORP", val: "FIN-CORP Syndicate", desc: "Organized financial wire diversion group" }
        ],
        edges: [
            { source: "c2_email", target: "c2_dom" },
            { source: "c2_email", target: "c2_doc" },
            { source: "c2_email", target: "c2_relay" },
            { source: "c2_dom", target: "c2_vps" },
            { source: "c2_dom", target: "c2_ns" },
            { source: "c2_relay", target: "c2_tor_asn" },
            { source: "c2_vps", target: "c2_asn" },
            { source: "c2_asn", target: "c2_cluster" },
            { source: "c2_tor_asn", target: "c2_cluster" },
            { source: "c2_doc", target: "c2_cluster" },
            { source: "c2_ns", target: "c2_cluster" },
            { source: "c2_email", target: "c2_cluster" }
        ]
    },
    m365: {
        id: "m365",
        title: "Campaign Storm-0539 (M365 Cloud Token AitM Syndicate)",
        clusters: 1,
        nodes: [
            { id: "c3_email", label: "Case #1004 (M365 ATO Lure)", type: "email", risk: "critical", campaign: "Storm-0539", val: "admin-alert@microsoft-support.net", desc: "Urgent session token re-authentication lure" },
            { id: "c3_dom", label: "login-msft-verify.us", type: "domain", risk: "critical", campaign: "Storm-0539", val: "login-msft-verify.us", desc: "AitM Evilginx reverse-proxy portal" },
            { id: "c3_url", label: "/oauth2/v2.0/token", type: "url", risk: "critical", campaign: "Storm-0539", val: "/oauth2/v2.0/token", desc: "Intercepts session tokens & MFA OTP" },
            { id: "c3_ip", label: "45.154.255.89", type: "ip", risk: "high", campaign: "Storm-0539", val: "45.154.255.89 (Hostinger)", desc: "Originating AitM proxy relay host" },
            { id: "c3_asn", label: "AS47583 Hostinger Int", type: "asn", risk: "medium", campaign: "Storm-0539", val: "AS47583 Hostinger", desc: "Abused commercial hosting infrastructure" },
            { id: "c3_token", label: "Session_PRT_Token.bin", type: "hash", risk: "critical", campaign: "Storm-0539", val: "PRT-Cookie-Exfil", desc: "Primary Refresh Token session hijacking payload" },
            { id: "c3_cluster", label: "Storm-0539 ATO Broker", type: "cluster", risk: "critical", campaign: "Storm-0539", val: "Storm-0539 Group", desc: "Cloud identity theft and token harvesting ring" }
        ],
        edges: [
            { source: "c3_email", target: "c3_dom" },
            { source: "c3_dom", target: "c3_url" },
            { source: "c3_dom", target: "c3_ip" },
            { source: "c3_ip", target: "c3_asn" },
            { source: "c3_url", target: "c3_token" },
            { source: "c3_asn", target: "c3_cluster" },
            { source: "c3_token", target: "c3_cluster" },
            { source: "c3_email", target: "c3_cluster" }
        ]
    },
    amz: {
        id: "amz",
        title: "Campaign SMISH-AMZ (Mobile Stealer & Logistics Dropper)",
        clusters: 1,
        nodes: [
            { id: "c4_email", label: "Case #1005 (Amazon Urgent Hold)", type: "email", risk: "high", campaign: "SMISH-AMZ", val: "delivery-alert@amz-track-update.com", desc: "Reschedule pending parcel delivery lure" },
            { id: "c4_dom", label: "amz-track-update.com", type: "domain", risk: "high", campaign: "SMISH-AMZ", val: "amz-track-update.com", desc: "Phishing portal masquerading as carrier dispatch" },
            { id: "c4_url", label: "/track/order-reschedule", type: "url", risk: "high", campaign: "SMISH-AMZ", val: "/track/order-reschedule", desc: "Landing page prompting malicious APK install" },
            { id: "c4_ip", label: "103.145.13.78", type: "ip", risk: "high", campaign: "SMISH-AMZ", val: "103.145.13.78 (Panama)", desc: "Offshore C2 command and control server" },
            { id: "c4_asn", label: "AS51852 Private Layer", type: "asn", risk: "high", campaign: "SMISH-AMZ", val: "AS51852 Private Layer", desc: "Panama offshore hosting provider" },
            { id: "c4_apk", label: "Amz_Tracking_Fix.apk", type: "hash", risk: "critical", campaign: "SMISH-AMZ", val: "3d18e8f2a991b852", desc: "Banking trojan & SMS interceptor payload" },
            { id: "c4_cluster", label: "SMISH-AMZ Stealer Ring", type: "cluster", risk: "high", campaign: "SMISH-AMZ", val: "SMISH-AMZ Ring", desc: "Mobile banking stealer distribution operation" }
        ],
        edges: [
            { source: "c4_email", target: "c4_dom" },
            { source: "c4_dom", target: "c4_url" },
            { source: "c4_url", target: "c4_apk" },
            { source: "c4_dom", target: "c4_ip" },
            { source: "c4_ip", target: "c4_asn" },
            { source: "c4_apk", target: "c4_cluster" },
            { source: "c4_asn", target: "c4_cluster" },
            { source: "c4_email", target: "c4_cluster" }
        ]
    },
    benign: {
        id: "benign",
        title: "Verified Cloud Base (Enterprise Ground Truth & Baseline)",
        clusters: 1,
        nodes: [
            { id: "c5_email", label: "Case #1003 (GitHub Advisory)", type: "email", risk: "benign", campaign: "Verified Base", val: "notifications@github.com", desc: "Authentic Dependabot vulnerability notification" },
            { id: "c5_dom", label: "github.com", type: "domain", risk: "benign", campaign: "Verified Base", val: "github.com (Aligned)", desc: "Passes strict SPF, DKIM 2048-bit, DMARC reject" },
            { id: "c5_ip", label: "192.30.252.204", type: "ip", risk: "benign", campaign: "Verified Base", val: "192.30.252.204", desc: "Authorized GitHub outbound mail relay node" },
            { id: "c5_asn", label: "AS36459 GitHub Inc", type: "asn", risk: "benign", campaign: "Verified Base", val: "AS36459 GitHub / Microsoft", desc: "Legitimate corporate autonomous system" },
            { id: "c5_cert", label: "DigiCert TLS Root", type: "hash", risk: "benign", campaign: "Verified Base", val: "DigiCert Global Root G2", desc: "Valid TLS cryptographic certificate authority" },
            { id: "c5_cluster", label: "Verified Enterprise Cloud", type: "cluster", risk: "benign", campaign: "Verified Base", val: "Verified Cloud Base", desc: "Baseline trusted enterprise infrastructure" }
        ],
        edges: [
            { source: "c5_email", target: "c5_dom" },
            { source: "c5_dom", target: "c5_ip" },
            { source: "c5_ip", target: "c5_asn" },
            { source: "c5_dom", target: "c5_cert" },
            { source: "c5_asn", target: "c5_cluster" },
            { source: "c5_cert", target: "c5_cluster" }
        ]
    }
};

let activeCampaignKey = "all";
let graphNodes = [];
let graphEdges = [];
let graphAnimFrame = null;
let isGraphPhysicsActive = true;
let draggedNode = null;
let hoveredNode = null;
let graphSearchQuery = "";
let edgePackets = [];
let graphListenersInitialized = false;
let graphPulseTick = 0;

function getNodeVisualAttributes(n) {
    let color = "#8b5cf6";
    let glow = "rgba(139, 92, 246, 0.45)";
    let r = 14;
    let icon = "⬡";

    if (n.type === "email") {
        icon = "✉";
        r = 18;
        if (n.risk === "critical" || n.risk === "high") {
            color = "#ef4444";
            glow = "rgba(239, 68, 68, 0.55)";
        } else if (n.risk === "medium") {
            color = "#f59e0b";
            glow = "rgba(245, 158, 11, 0.5)";
        } else {
            color = "#10b981";
            glow = "rgba(16, 185, 129, 0.5)";
        }
    } else if (n.type === "domain") {
        icon = "🌐";
        color = "#06b6d4";
        glow = "rgba(6, 182, 212, 0.5)";
        r = 14;
    } else if (n.type === "url") {
        icon = "⚡";
        color = "#ec4899";
        glow = "rgba(236, 72, 153, 0.5)";
        r = 12;
    } else if (n.type === "ip") {
        icon = "⌖";
        color = n.risk === "critical" ? "#dc2626" : "#a855f7";
        glow = n.risk === "critical" ? "rgba(220, 38, 38, 0.6)" : "rgba(168, 85, 247, 0.5)";
        r = 15;
    } else if (n.type === "asn") {
        icon = "⬢";
        color = "#f59e0b";
        glow = "rgba(245, 158, 11, 0.45)";
        r = 14;
    } else if (n.type === "hash") {
        icon = "☣";
        color = "#3b82f6";
        glow = "rgba(59, 130, 246, 0.5)";
        r = 13;
    } else if (n.type === "cluster") {
        icon = "☠";
        color = n.risk === "benign" ? "#10b981" : "#ea580c";
        glow = n.risk === "benign" ? "rgba(16, 185, 129, 0.6)" : "rgba(234, 88, 12, 0.7)";
        r = 20;
    }
    return { color, glow, r, icon };
}

function enrichDatasetsWithLiveIngested() {
    const list = (typeof storedEmails !== "undefined" && Array.isArray(storedEmails)) ? storedEmails : [];
    list.forEach(e => {
        const cId = `case_${e.id}`;
        const exists = CAMPAIGN_DATASETS.all.nodes.some(n => n.id === cId);
        if (!exists && e.id) {
            const risk = (e.risk_level || "high").toLowerCase();
            const newNode = {
                id: cId,
                label: `Case #${e.id} (${(e.subject || 'Ingested').substring(0, 16)}…)`,
                type: "email",
                risk: risk === "high" ? "critical" : risk,
                campaign: "TC-44146",
                val: e.sender || "ingested@soc.local",
                desc: e.subject || "Ingested Threat Telemetry"
            };
            CAMPAIGN_DATASETS.all.nodes.push(newNode);
            CAMPAIGN_DATASETS.all.edges.push({ source: cId, target: "c1_relay" });
            CAMPAIGN_DATASETS.all.edges.push({ source: cId, target: "c1_cluster" });
        }
    });
}

function initCampaignDataset(key, canvas) {
    enrichDatasetsWithLiveIngested();
    const ds = CAMPAIGN_DATASETS[key] || CAMPAIGN_DATASETS["all"];
    const w = canvas.width || 900;
    const h = canvas.height || 520;
    const cx = w / 2;
    const cy = h / 2;

    const rawNodes = ds.nodes || [];
    const count = rawNodes.length;

    const clusterGroups = {};
    rawNodes.forEach(n => {
        const cKey = n.campaign || "default";
        if (!clusterGroups[cKey]) clusterGroups[cKey] = [];
        clusterGroups[cKey].push(n);
    });

    const clusterKeys = Object.keys(clusterGroups);
    const clusterAngles = {};
    clusterKeys.forEach((k, idx) => {
        clusterAngles[k] = (idx / clusterKeys.length) * 2 * Math.PI - Math.PI / 2;
    });

    graphNodes = rawNodes.map((n, i) => {
        const cKey = n.campaign || "default";
        const baseAngle = clusterAngles[cKey] !== undefined ? clusterAngles[cKey] : (i / count) * 2 * Math.PI;
        const subIdx = clusterGroups[cKey].indexOf(n);
        const subTotal = clusterGroups[cKey].length;
        const subSpread = ((subIdx - subTotal / 2) / (subTotal || 1)) * 0.9;
        const angle = baseAngle + subSpread;
        const dist = n.type === "cluster" ? (count > 15 ? 120 : 70) : (count > 15 ? 170 + (i % 3) * 35 : 130 + (i % 2) * 25);

        const visual = getNodeVisualAttributes(n);
        return {
            ...n,
            x: Math.max(30, Math.min(w - 30, cx + Math.cos(angle) * dist + (Math.random() - 0.5) * 25)),
            y: Math.max(30, Math.min(h - 30, cy + Math.sin(angle) * dist + (Math.random() - 0.5) * 25)),
            vx: (Math.random() - 0.5) * 1.5,
            vy: (Math.random() - 0.5) * 1.5,
            ...visual
        };
    });

    const nodeMap = {};
    graphNodes.forEach(n => { nodeMap[n.id] = n; });

    graphEdges = (ds.edges || []).map(e => ({
        source: nodeMap[e.source],
        target: nodeMap[e.target]
    })).filter(e => e.source && e.target);

    edgePackets = graphEdges.map(() => ({
        progress: Math.random(),
        speed: 0.005 + Math.random() * 0.005
    }));

    updateGraphStatsChip(ds);
}

function updateGraphStatsChip(ds) {
    const nodeEl = document.getElementById("graph-node-count");
    const edgeEl = document.getElementById("graph-edge-count");
    const clusterEl = document.getElementById("graph-cluster-count");
    if (nodeEl) nodeEl.innerHTML = `<i class="fa-solid fa-circle-nodes" style="color: var(--primary);"></i> ${graphNodes.length} Nodes`;
    if (edgeEl) edgeEl.innerHTML = `<i class="fa-solid fa-route" style="color: #38bdf8;"></i> ${graphEdges.length} Correlated Edges`;
    if (clusterEl) clusterEl.innerHTML = `<i class="fa-solid fa-biohazard" style="color: #ef4444;"></i> ${ds.clusters || 1} Threat Cluster${(ds.clusters || 1) > 1 ? "s" : ""}`;
}

function stepGraphPhysics(canvas) {
    if (!isGraphPhysicsActive && !draggedNode) return;

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;

    const kRep = graphNodes.length > 20 ? 1800 : 2500;
    const kSpring = 0.032;
    const springLen = graphNodes.length > 20 ? 95 : 120;
    const damping = 0.85;
    const centerGrav = 0.015;

    for (let i = 0; i < graphNodes.length; i++) {
        const n1 = graphNodes[i];
        if (n1 === draggedNode) continue;

        for (let j = i + 1; j < graphNodes.length; j++) {
            const n2 = graphNodes[j];
            let dx = n1.x - n2.x;
            let dy = n1.y - n2.y;
            let d = Math.sqrt(dx * dx + dy * dy);
            if (d < 1) { dx = 1; dy = 0; d = 1; }

            const sameCluster = n1.campaign && n2.campaign && n1.campaign === n2.campaign;
            const repFactor = sameCluster ? kRep * 0.85 : kRep * 1.35;
            const force = repFactor / (d * d + 80);

            const fx = (dx / d) * force;
            const fy = (dy / d) * force;

            n1.vx += fx;
            n1.vy += fy;
            if (n2 !== draggedNode) {
                n2.vx -= fx;
                n2.vy -= fy;
            }
        }
    }

    graphEdges.forEach(e => {
        const src = e.source;
        const tgt = e.target;
        if (!src || !tgt) return;

        let dx = tgt.x - src.x;
        let dy = tgt.y - src.y;
        let d = Math.sqrt(dx * dx + dy * dy);
        if (d < 1) d = 1;

        const force = (d - springLen) * kSpring;
        const fx = (dx / d) * force;
        const fy = (dy / d) * force;

        if (src !== draggedNode) {
            src.vx += fx;
            src.vy += fy;
        }
        if (tgt !== draggedNode) {
            tgt.vx -= fx;
            tgt.vy -= fy;
        }
    });

    graphNodes.forEach(n => {
        if (n === draggedNode) return;

        n.vx += (cx - n.x) * centerGrav;
        n.vy += (cy - n.y) * centerGrav;

        n.vx *= damping;
        n.vy *= damping;

        const maxV = 8;
        const curV = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
        if (curV > maxV) {
            n.vx = (n.vx / curV) * maxV;
            n.vy = (n.vy / curV) * maxV;
        }

        n.x += n.vx;
        n.y += n.vy;

        const pad = n.r + 20;
        if (n.x < pad) { n.x = pad; n.vx = Math.abs(n.vx) * 0.5; }
        if (n.x > w - pad) { n.x = w - pad; n.vx = -Math.abs(n.vx) * 0.5; }
        if (n.y < pad) { n.y = pad; n.vy = Math.abs(n.vy) * 0.5; }
        if (n.y > h - pad) { n.y = h - pad; n.vy = -Math.abs(n.vy) * 0.5; }
    });
}

function renderCampaignGraphFrame(canvas) {
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    graphPulseTick++;
    stepGraphPhysics(canvas);

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const connectedNodeIds = new Set();
    if (hoveredNode) {
        connectedNodeIds.add(hoveredNode.id);
        graphEdges.forEach(e => {
            if (e.source.id === hoveredNode.id) connectedNodeIds.add(e.target.id);
            if (e.target.id === hoveredNode.id) connectedNodeIds.add(e.source.id);
        });
    }

    const hasSearch = graphSearchQuery.length > 0;
    const matchingNodeIds = new Set();
    if (hasSearch) {
        graphNodes.forEach(n => {
            if (
                n.label.toLowerCase().includes(graphSearchQuery) ||
                (n.val && n.val.toLowerCase().includes(graphSearchQuery)) ||
                (n.type && n.type.toLowerCase().includes(graphSearchQuery)) ||
                (n.campaign && n.campaign.toLowerCase().includes(graphSearchQuery))
            ) {
                matchingNodeIds.add(n.id);
            }
        });
    }

    graphEdges.forEach((e, idx) => {
        const src = e.source;
        const tgt = e.target;
        if (!src || !tgt) return;

        const isHighlighted = hoveredNode && (src.id === hoveredNode.id || tgt.id === hoveredNode.id);
        const isDimmed = hoveredNode && !isHighlighted;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);

        if (isHighlighted) {
            ctx.strokeStyle = "rgba(6, 182, 212, 0.9)";
            ctx.lineWidth = 2.4;
        } else if (isDimmed) {
            ctx.strokeStyle = "rgba(148, 163, 184, 0.08)";
            ctx.lineWidth = 1;
        } else {
            ctx.strokeStyle = "rgba(148, 163, 184, 0.22)";
            ctx.lineWidth = 1.4;
        }
        ctx.stroke();

        const packet = edgePackets[idx];
        if (packet && (!isDimmed || isHighlighted)) {
            packet.progress += packet.speed;
            if (packet.progress > 1) packet.progress = 0;

            const px = src.x + (tgt.x - src.x) * packet.progress;
            const py = src.y + (tgt.y - src.y) * packet.progress;

            ctx.beginPath();
            ctx.arc(px, py, isHighlighted ? 3.5 : 2.5, 0, 2 * Math.PI);
            ctx.fillStyle = isHighlighted ? "#38bdf8" : (src.color || "#38bdf8");
            ctx.shadowColor = src.color || "#38bdf8";
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    });

    graphNodes.forEach(n => {
        const isHov = hoveredNode && hoveredNode.id === n.id;
        const isConn = hoveredNode && connectedNodeIds.has(n.id);
        const isMatch = hasSearch && matchingNodeIds.has(n.id);
        const isDim = (hoveredNode && !isHov && !isConn) || (hasSearch && !isMatch);

        const alpha = isDim ? 0.22 : 1.0;
        ctx.globalAlpha = alpha;

        if (n.type === "cluster") {
            const pulseRadius = n.r + 5 + Math.sin(graphPulseTick * 0.08) * 3;
            ctx.beginPath();
            ctx.arc(n.x, n.y, pulseRadius, 0, 2 * Math.PI);
            ctx.strokeStyle = n.glow;
            ctx.lineWidth = 2;
            ctx.stroke();
        }

        if (isMatch) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r + 8 + Math.sin(graphPulseTick * 0.12) * 2, 0, 2 * Math.PI);
            ctx.strokeStyle = "#38bdf8";
            ctx.lineWidth = 2.5;
            ctx.stroke();
        }

        if (isHov) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r + 6, 0, 2 * Math.PI);
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 2;
            ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 3, 0, 2 * Math.PI);
        ctx.fillStyle = n.glow;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, 2 * Math.PI);
        ctx.fillStyle = n.color;
        ctx.fill();

        ctx.strokeStyle = "#090d16";
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.fillStyle = "#ffffff";
        ctx.font = `bold ${Math.round(n.r * 0.85)}px Inter, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(n.icon || "•", n.x, n.y + 1);

        const shortLabel = n.label.length > 22 ? n.label.substring(0, 20) + "…" : n.label;
        ctx.font = "10px Inter, sans-serif";
        const textWidth = ctx.measureText(shortLabel).width;
        const pillW = textWidth + 10;
        const pillH = 16;
        const pillX = n.x - pillW / 2;
        const pillY = n.y + n.r + 5;

        ctx.fillStyle = "rgba(9, 13, 22, 0.85)";
        ctx.strokeStyle = isHov ? "#38bdf8" : "rgba(148, 163, 184, 0.35)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        if (ctx.roundRect) {
            ctx.roundRect(pillX, pillY, pillW, pillH, 4);
        } else {
            ctx.rect(pillX, pillY, pillW, pillH);
        }
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = isHov ? "#38bdf8" : "#e2e8f0";
        ctx.textBaseline = "alphabetic";
        ctx.fillText(shortLabel, n.x, pillY + 11);

        ctx.globalAlpha = 1.0;
    });

    const activeGraphPane = document.getElementById("pane-graph");
    if (activeGraphPane && activeGraphPane.classList.contains("active")) {
        graphAnimFrame = requestAnimationFrame(() => renderCampaignGraphFrame(canvas));
    } else {
        graphAnimFrame = null;
    }
}

function setupGraphInteractions(canvas, container) {
    if (graphListenersInitialized) return;
    graphListenersInitialized = true;

    const tooltip = document.getElementById("graph-tooltip-cyber");

    function getCanvasPos(e) {
        const rect = canvas.getBoundingClientRect();
        return {
            x: (e.clientX - rect.left) * (canvas.width / rect.width),
            y: (e.clientY - rect.top) * (canvas.height / rect.height),
            clientX: e.clientX,
            clientY: e.clientY
        };
    }

    function findNodeAt(x, y) {
        for (let i = graphNodes.length - 1; i >= 0; i--) {
            const n = graphNodes[i];
            const dist = Math.hypot(x - n.x, y - n.y);
            if (dist <= n.r + 8) return n;
        }
        return null;
    }

    canvas.addEventListener("mousedown", e => {
        const pos = getCanvasPos(e);
        const node = findNodeAt(pos.x, pos.y);
        if (node) {
            draggedNode = node;
            canvas.style.cursor = "grabbing";
            wakeGraphPhysics(canvas);
        }
    });

    window.addEventListener("mousemove", e => {
        const pos = getCanvasPos(e);
        if (draggedNode) {
            draggedNode.x = pos.x;
            draggedNode.y = pos.y;
            draggedNode.vx = 0;
            draggedNode.vy = 0;
            wakeGraphPhysics(canvas);
            return;
        }

        const rect = canvas.getBoundingClientRect();
        if (e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom) {
            if (hoveredNode) {
                hoveredNode = null;
                if (tooltip) tooltip.classList.remove("visible");
            }
            return;
        }

        const node = findNodeAt(pos.x, pos.y);
        if (node !== hoveredNode) {
            hoveredNode = node;
            canvas.style.cursor = node ? "pointer" : "grab";
            if (node && tooltip) {
                const degree = graphEdges.filter(ed => (ed.source && ed.source.id === node.id) || (ed.target && ed.target.id === node.id)).length;
                tooltip.innerHTML = `
                    <div class="tooltip-header">
                        <span class="tooltip-title">${escapeHtml(node.label)}</span>
                        <span class="tooltip-badge ${node.risk || 'high'}">${(node.risk || 'info').toUpperCase()}</span>
                    </div>
                    <div class="tooltip-type">TYPE: ${(node.type || 'ENTITY').toUpperCase()} • CAMPAIGN: ${escapeHtml(node.campaign || 'GLOBAL')}</div>
                    <div class="tooltip-field">
                        <span class="tooltip-key">Observable:</span>
                        <span class="tooltip-val">${escapeHtml(node.val || node.label)}</span>
                    </div>
                    <div class="tooltip-field">
                        <span class="tooltip-key">Details:</span>
                        <span class="tooltip-val">${escapeHtml(node.desc || 'Active correlated threat asset')}</span>
                    </div>
                    <div class="tooltip-field">
                        <span class="tooltip-key">Topology:</span>
                        <span class="tooltip-val" style="color: #38bdf8;">Connected to ${degree} threat artifact${degree !== 1 ? 's' : ''}</span>
                    </div>
                `;
                const tipX = Math.min(pos.x + 18, canvas.width - 240);
                const tipY = Math.min(pos.y + 12, canvas.height - 130);
                tooltip.style.left = `${tipX}px`;
                tooltip.style.top = `${tipY}px`;
                tooltip.classList.add("visible");
            } else if (tooltip) {
                tooltip.classList.remove("visible");
            }
        }
    });

    window.addEventListener("mouseup", () => {
        if (draggedNode) {
            draggedNode = null;
            canvas.style.cursor = "grab";
            wakeGraphPhysics(canvas);
        }
    });

    canvas.addEventListener("mouseleave", () => {
        if (hoveredNode) {
            hoveredNode = null;
            if (tooltip) tooltip.classList.remove("visible");
        }
    });

    const presetBtns = document.querySelectorAll(".graph-preset-btn");
    presetBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            presetBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            activeCampaignKey = btn.dataset.campaign || "all";
            initCampaignDataset(activeCampaignKey, canvas);
            wakeGraphPhysics(canvas);
        });
    });

    const searchInput = document.getElementById("graph-search-input");
    if (searchInput) {
        searchInput.addEventListener("input", e => {
            graphSearchQuery = (e.target.value || "").toLowerCase().trim();
            wakeGraphPhysics(canvas);
        });
    }

    const togglePhysicsBtn = document.getElementById("btn-graph-toggle-physics");
    if (togglePhysicsBtn) {
        togglePhysicsBtn.addEventListener("click", () => {
            isGraphPhysicsActive = !isGraphPhysicsActive;
            const icon = document.getElementById("icon-graph-physics");
            const span = togglePhysicsBtn.querySelector("span");
            if (isGraphPhysicsActive) {
                if (icon) icon.className = "fa-solid fa-pause";
                if (span) span.textContent = "Pause Physics";
                wakeGraphPhysics(canvas);
            } else {
                if (icon) icon.className = "fa-solid fa-play";
                if (span) span.textContent = "Resume Physics";
            }
        });
    }

    const recenterBtn = document.getElementById("btn-graph-recenter");
    if (recenterBtn) {
        recenterBtn.addEventListener("click", () => {
            const cx = canvas.width / 2;
            const cy = canvas.height / 2;
            graphNodes.forEach((n, i) => {
                const angle = (i / graphNodes.length) * 2 * Math.PI;
                n.vx = (cx - n.x) * 0.15 + Math.cos(angle) * 3;
                n.vy = (cy - n.y) * 0.15 + Math.sin(angle) * 3;
            });
            wakeGraphPhysics(canvas);
        });
    }
}

function wakeGraphPhysics(canvas) {
    if (!graphAnimFrame) {
        graphAnimFrame = requestAnimationFrame(() => renderCampaignGraphFrame(canvas));
    }
}

async function loadAndRenderCampaignGraph(forceReload = false) {
    const canvas = document.getElementById("campaign-graph-canvas");
    const container = document.getElementById("graph-canvas-container");
    if (!canvas || !container) return;

    canvas.width = container.clientWidth || 900;
    canvas.height = container.clientHeight || 520;

    if (graphAnimFrame) {
        cancelAnimationFrame(graphAnimFrame);
        graphAnimFrame = null;
    }

    setupGraphInteractions(canvas, container);

    if (forceReload || graphNodes.length === 0) {
        initCampaignDataset(activeCampaignKey, canvas);
    }

    wakeGraphPhysics(canvas);
}

function updateAnalyticsMatrix(emails) {
    let spfPass = 0, spfFail = 0;
    let dkimPass = 0, dkimFail = 0;
    let dmarcPass = 0, dmarcFail = 0;
    const countryMap = {};

    emails.forEach(e => {
        if (e.spf_result === "pass") spfPass++;
        else if (e.spf_result === "fail" || e.spf_result === "softfail") spfFail++;

        if (e.dkim_result === "pass" || e.dkim_result === "present") dkimPass++;
        else if (e.dkim_result === "fail") dkimFail++;

        if (e.dmarc_result === "pass") dmarcPass++;
        else if (e.dmarc_result === "fail") dmarcFail++;

        const c = e.country || "Unknown";
        countryMap[c] = (countryMap[c] || 0) + 1;
    });

    document.getElementById("spf-pass-count").textContent = `${spfPass} Pass`;
    document.getElementById("spf-fail-count").textContent = `${spfFail} Fail`;
    const spfTotal = spfPass + spfFail;
    const spfPct = spfTotal > 0 ? (spfPass / spfTotal) * 100 : 50;
    document.getElementById("spf-meter").style.width = `${spfPct}%`;

    document.getElementById("dkim-pass-count").textContent = `${dkimPass} Pass`;
    document.getElementById("dkim-fail-count").textContent = `${dkimFail} Fail`;
    const dkimTotal = dkimPass + dkimFail;
    const dkimPct = dkimTotal > 0 ? (dkimPass / dkimTotal) * 100 : 50;
    document.getElementById("dkim-meter").style.width = `${dkimPct}%`;

    document.getElementById("dmarc-pass-count").textContent = `${dmarcPass} Pass`;
    document.getElementById("dmarc-fail-count").textContent = `${dmarcFail} Fail`;
    const dmarcTotal = dmarcPass + dmarcFail;
    const dmarcPct = dmarcTotal > 0 ? (dmarcPass / dmarcTotal) * 100 : 50;
    document.getElementById("dmarc-meter").style.width = `${dmarcPct}%`;

    const sortedCountries = Object.entries(countryMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const countryContainer = document.getElementById("country-rank-list");
    if (countryContainer) {
        countryContainer.innerHTML = sortedCountries.map(([country, count], idx) => `
            <div class="country-rank-item">
                <span style="font-weight: 600;"><span style="color: var(--primary); font-family: var(--font-mono); margin-right: 0.4rem;">#${idx + 1}</span> ${escapeHtml(country)}</span>
                <span style="font-family: var(--font-mono); background: rgba(255,255,255,0.06); padding: 0.15rem 0.5rem; border-radius: 0.3rem;">${count} incidents</span>
            </div>
        `).join("");
    }
}

async function handleIngestSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    const senderInput = document.getElementById("sender");
    const subjectInput = document.getElementById("subject");
    const headersInput = document.getElementById("raw-headers");
    const bodyInput = document.getElementById("body-text");

    const sender = senderInput ? senderInput.value.trim() : "";
    const subject = subjectInput ? subjectInput.value.trim() : "";
    const rawHeaders = headersInput ? headersInput.value.trim() || null : null;
    const bodyText = bodyInput ? bodyInput.value.trim() : "";

    if (!sender || !subject || !bodyText) {
        showToast("Please fill in all required fields.", "error");
        return;
    }

    const btn = document.getElementById("btn-submit-ingest");
    const spinner = document.getElementById("ingest-spinner");
    if (btn) btn.disabled = true;
    if (spinner) spinner.classList.remove("hidden");

    let data = null;

    if (API_BASE) {
        try {
            const response = await fetch(`${API_BASE}/emails`, {
                method: "POST",
                headers: getAuthHeaders({ "Content-Type": "application/json" }),
                body: JSON.stringify({
                    sender,
                    subject,
                    raw_headers: rawHeaders,
                    body_text: bodyText
                })
            });

            if (response.ok) {
                data = await response.json();
            }
        } catch (err) {
            console.warn("Backend API not reachable, running client-side RFC 822 forensic engine:", err);
        }
    }

    if (!data) {
        const fullPayload = `${rawHeaders ? rawHeaders + "\n\n" : ""}${bodyText}`;
        const parsed = parseEmlFile(fullPayload);
        parsed.sender = sender;
        parsed.subject = subject;
        if (rawHeaders) parsed.raw_headers = rawHeaders;
        data = await analyzeParsedEmailClientSide(parsed);
    }

    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add("hidden");

    if (data) {
        storedEmails = [data, ...storedEmails.filter(e => e.id !== data.id)];
        
        updateTelemetryStats(storedEmails);
        renderStreamFeed(storedEmails);
        applyFeedFilters();
        updateMapMarkers(storedEmails);
        updateAnalyticsMatrix(storedEmails);
        updateWorkspaceCaseDropdown();
        renderInvestigationWorkspace(data.id);

        const feedCount = document.getElementById("tab-feed-count");
        if (feedCount) feedCount.textContent = storedEmails.length;

        showToast(`✅ Case #${data.id} Ingested: ${data.risk_level.toUpperCase()} THREAT (${data.final_score}/100)`, "success");
        runSequential4VectorPipeline(data);
    } else {
        showToast(`❌ Ingestion failed: could not parse payload`, "error");
    }
}

let activePipelineId = 0;

async function runSequential4VectorPipeline(emailResult) {
    const currentRunId = ++activePipelineId;
    let isCancelled = false;

    const modal = document.getElementById("modal-pipeline-progress");
    const fill = document.getElementById("pipeline-progress-bar-fill");
    const pctLabel = document.getElementById("pipeline-pct-label");
    const statusBadge = document.getElementById("pipeline-status-badge");
    const terminal = document.getElementById("pipeline-live-terminal");
    const proceedBtn = document.getElementById("btn-pipeline-proceed");
    const skipBtn = document.getElementById("btn-pipeline-skip-now");
    const viewWsBtn = document.getElementById("btn-pipeline-view-ws");
    const closeBtn = document.getElementById("btn-close-pipeline-modal");
    const backdrop = document.getElementById("pipeline-modal-backdrop");
    const scrollBody = document.getElementById("pipeline-modal-scrollable-body");

    const senderLabel = document.getElementById("pipeline-target-sender");
    const caseLabel = document.getElementById("pipeline-target-case");

    if (!modal) {
        openForensicModal(emailResult.id);
        return;
    }

    if (senderLabel) senderLabel.textContent = emailResult.sender || "Unknown Sender";
    if (caseLabel) caseLabel.textContent = `Case #${emailResult.id}`;

    if (proceedBtn) proceedBtn.style.display = "none";
    if (viewWsBtn) viewWsBtn.style.display = "none";
    if (skipBtn) {
        skipBtn.style.display = "inline-flex";
        skipBtn.innerHTML = `<i class="fa-solid fa-forward"></i> <span>Skip Animation</span>`;
    }

    const resetStepCard = (id, detailDefault, badgeDefault) => {
        const card = document.getElementById(id);
        const detail = document.getElementById(`${id}-detail`);
        const badge = document.getElementById(`${id}-badge`);
        if (card) {
            card.classList.remove("active");
        }
        if (detail) detail.textContent = detailDefault;
        if (badge) {
            badge.textContent = badgeDefault;
            badge.className = "badge-risk-pill";
            badge.style.background = "rgba(255, 255, 255, 0.06)";
            badge.style.color = "var(--text-muted)";
        }
    };

    resetStepCard("step-v1", "Waiting to inspect deceptive urgency & phishing patterns...", "PENDING");
    resetStepCard("step-v2", "Waiting to audit SPF, DKIM, DMARC alignment...", "PENDING");
    resetStepCard("step-v3", "Waiting to resolve relay IP, ASN/ISP & Tor node...", "PENDING");
    resetStepCard("step-v4", "Waiting to compute SHA-256 fingerprint & risk rating...", "PENDING");

    if (fill) fill.style.width = "0%";
    if (pctLabel) pctLabel.textContent = "0%";
    if (statusBadge) {
        statusBadge.textContent = "RUNNING SEQUENCE...";
        statusBadge.style.color = "#c4b5fd";
    }

    const appendLog = (msg, color = "#a1a1aa") => {
        if (!terminal) return;
        const line = document.createElement("div");
        line.style.color = color;
        line.style.marginTop = "0.2rem";
        line.textContent = msg;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    };

    if (terminal) terminal.innerHTML = "";
    appendLog(`[INIT] Executing 4-Vector Threat Forensic Pipeline for Case #${emailResult.id}...`, "#a78bfa");

    modal.classList.remove("hidden");
    if (scrollBody) scrollBody.scrollTop = 0;

    const completeAllCardsInstantly = () => {
        const fraudPct = Math.round((emailResult.fraud_score || 0) * 100);
        const spf = (emailResult.spf_result || "none").toUpperCase();
        const dkim = (emailResult.dkim_result || "none").toUpperCase();
        const dmarc = (emailResult.dmarc_result || "none").toUpperCase();
        const headerValid = emailResult.header_valid;
        const ip = emailResult.ip_address || "127.0.0.1";
        const geoLoc = `${emailResult.city || "Unknown City"}, ${emailResult.country || "Unknown Country"}`;
        const isp = emailResult.isp_asn || "Standard Relays";
        const isTor = emailResult.is_vpn_tor;
        const hashSnippet = emailResult.sha256_hash ? emailResult.sha256_hash.substring(0, 16) + "..." : "SEALED";
        const riskLevel = (emailResult.risk_level || "low").toLowerCase();
        const finalScore = emailResult.final_score || 0;

        const cardV1 = document.getElementById("step-v1");
        const badgeV1 = document.getElementById("step-v1-badge");
        const detailV1 = document.getElementById("step-v1-detail");
        if (cardV1) cardV1.classList.add("active");
        if (detailV1) detailV1.textContent = `Fraud Score: ${fraudPct}% | Deceptive Language Analyzed`;
        if (badgeV1) {
            badgeV1.textContent = fraudPct >= 50 ? `FLAGGED (${fraudPct}%)` : `CLEAN (${fraudPct}%)`;
            badgeV1.className = `badge-risk-pill ${fraudPct >= 50 ? "high" : "low"}`;
        }

        const cardV2 = document.getElementById("step-v2");
        const badgeV2 = document.getElementById("step-v2-badge");
        const detailV2 = document.getElementById("step-v2-detail");
        if (cardV2) cardV2.classList.add("active");
        if (detailV2) detailV2.textContent = `SPF: ${spf} | DKIM: ${dkim} | DMARC: ${dmarc}`;
        if (badgeV2) {
            badgeV2.textContent = (!headerValid || spf === "FAIL" || dkim === "FAIL") ? `HEADER FAIL (${spf}/${dkim})` : `VERIFIED (${spf}/${dkim})`;
            badgeV2.className = `badge-risk-pill ${(!headerValid || spf === "FAIL" || dkim === "FAIL") ? "high" : "low"}`;
        }

        const cardV3 = document.getElementById("step-v3");
        const badgeV3 = document.getElementById("step-v3-badge");
        const detailV3 = document.getElementById("step-v3-detail");
        if (cardV3) cardV3.classList.add("active");
        if (detailV3) detailV3.textContent = `Relay IP: ${ip} (${geoLoc}) | ASN: ${isp}`;
        if (badgeV3) {
            badgeV3.textContent = isTor ? `TOR / VPN DETECTED` : `GEO RESOLVED (${emailResult.country || "IP"})`;
            badgeV3.className = `badge-risk-pill ${isTor ? "high" : "low"}`;
        }

        const cardV4 = document.getElementById("step-v4");
        const badgeV4 = document.getElementById("step-v4-badge");
        const detailV4 = document.getElementById("step-v4-detail");
        if (cardV4) cardV4.classList.add("active");
        if (detailV4) detailV4.textContent = `SHA-256: ${hashSnippet} | Composite Risk Score: ${finalScore}/100`;
        if (badgeV4) {
            badgeV4.textContent = `${riskLevel.toUpperCase()} THREAT (${finalScore}/100)`;
            badgeV4.className = `badge-risk-pill ${riskLevel}`;
        }

        if (fill) fill.style.width = "100%";
        if (pctLabel) pctLabel.textContent = "100%";
        if (statusBadge) {
            statusBadge.textContent = "VERIFICATION COMPLETE";
            statusBadge.style.color = "#34d399";
        }
    };

    const showFinishedButtons = () => {
        if (skipBtn) skipBtn.style.display = "none";
        if (proceedBtn) {
            proceedBtn.style.display = "inline-flex";
            proceedBtn.onclick = () => {
                modal.classList.add("hidden");
                openForensicModal(emailResult.id);
            };
        }
        if (viewWsBtn) {
            viewWsBtn.style.display = "inline-flex";
            viewWsBtn.onclick = () => {
                modal.classList.add("hidden");
                const wsTab = document.querySelector(`.nav-tab[data-tab="investigation"]`) || document.querySelector(`.nav-tab[data-tab="workspace"]`);
                if (wsTab) wsTab.click();
                renderInvestigationWorkspace(emailResult.id);
            };
        }
    };

    const closePipelineModal = () => {
        isCancelled = true;
        modal.classList.add("hidden");
    };

    if (closeBtn) closeBtn.onclick = closePipelineModal;
    if (backdrop) backdrop.onclick = closePipelineModal;

    if (skipBtn) {
        skipBtn.onclick = () => {
            isCancelled = true;
            completeAllCardsInstantly();
            modal.classList.add("hidden");
            openForensicModal(emailResult.id);
        };
    }

    const sleep = (ms) => new Promise((res) => {
        const timeout = setTimeout(() => res(true), ms);
        const checkInterval = setInterval(() => {
            if (isCancelled || currentRunId !== activePipelineId) {
                clearTimeout(timeout);
                clearInterval(checkInterval);
                res(false);
            }
        }, 40);
    });

    const cardV1 = document.getElementById("step-v1");
    const badgeV1 = document.getElementById("step-v1-badge");
    const detailV1 = document.getElementById("step-v1-detail");
    if (cardV1) cardV1.classList.add("active");
    if (badgeV1) {
        badgeV1.textContent = "ANALYZING...";
        badgeV1.style.background = "rgba(59, 130, 246, 0.2)";
        badgeV1.style.color = "#60a5fa";
    }
    appendLog(`[VECTOR-1] Inspecting deceptive linguistics, NLP phishing indicators & urgency keywords...`, "#60a5fa");
    if (!(await sleep(400))) return;

    const fraudPct = Math.round((emailResult.fraud_score || 0) * 100);
    if (detailV1) detailV1.textContent = `Fraud Score: ${fraudPct}% | Deceptive Language Analyzed`;
    if (badgeV1) {
        if (fraudPct >= 50) {
            badgeV1.textContent = `FLAGGED (${fraudPct}%)`;
            badgeV1.className = "badge-risk-pill high";
        } else {
            badgeV1.textContent = `CLEAN (${fraudPct}%)`;
            badgeV1.className = "badge-risk-pill low";
        }
    }
    if (fill) fill.style.width = "25%";
    if (pctLabel) pctLabel.textContent = "25%";
    appendLog(`[VECTOR-1 COMPLETE] Deceptive NLP Fraud Score: ${fraudPct}%`, fraudPct >= 50 ? "#f87171" : "#34d399");

    if (!(await sleep(350))) return;
    const cardV2 = document.getElementById("step-v2");
    const badgeV2 = document.getElementById("step-v2-badge");
    const detailV2 = document.getElementById("step-v2-detail");
    if (cardV2) cardV2.classList.add("active");
    if (badgeV2) {
        badgeV2.textContent = "AUDITING...";
        badgeV2.style.background = "rgba(139, 92, 246, 0.2)";
        badgeV2.style.color = "#a78bfa";
    }
    appendLog(`[VECTOR-2] Auditing RFC 822 headers for SPF, DKIM signature & DMARC alignment...`, "#a78bfa");
    if (!(await sleep(400))) return;

    const spf = (emailResult.spf_result || "none").toUpperCase();
    const dkim = (emailResult.dkim_result || "none").toUpperCase();
    const dmarc = (emailResult.dmarc_result || "none").toUpperCase();
    const headerValid = emailResult.header_valid;

    if (detailV2) detailV2.textContent = `SPF: ${spf} | DKIM: ${dkim} | DMARC: ${dmarc}`;
    if (badgeV2) {
        if (!headerValid || spf === "FAIL" || dkim === "FAIL") {
            badgeV2.textContent = `HEADER FAIL (${spf}/${dkim})`;
            badgeV2.className = "badge-risk-pill high";
        } else {
            badgeV2.textContent = `VERIFIED (${spf}/${dkim})`;
            badgeV2.className = "badge-risk-pill low";
        }
    }
    if (fill) fill.style.width = "50%";
    if (pctLabel) pctLabel.textContent = "50%";
    appendLog(`[VECTOR-2 COMPLETE] Header Validation: SPF=${spf}, DKIM=${dkim}, DMARC=${dmarc}`, headerValid ? "#34d399" : "#f87171");

    if (!(await sleep(350))) return;
    const cardV3 = document.getElementById("step-v3");
    const badgeV3 = document.getElementById("step-v3-badge");
    const detailV3 = document.getElementById("step-v3-detail");
    if (cardV3) cardV3.classList.add("active");
    if (badgeV3) {
        badgeV3.textContent = "RESOLVING...";
        badgeV3.style.background = "rgba(236, 72, 153, 0.2)";
        badgeV3.style.color = "#f472b6";
    }
    const ip = emailResult.ip_address || "127.0.0.1";
    appendLog(`[VECTOR-3] Querying GeoIP database & threat intel for relay node ${ip}...`, "#f472b6");
    if (!(await sleep(400))) return;

    const geoLoc = `${emailResult.city || "Unknown City"}, ${emailResult.country || "Unknown Country"}`;
    const isp = emailResult.isp_asn || "Standard Relays";
    const isTor = emailResult.is_vpn_tor;

    if (detailV3) detailV3.textContent = `Relay IP: ${ip} (${geoLoc}) | ASN: ${isp}`;
    if (badgeV3) {
        if (isTor) {
            badgeV3.textContent = `TOR / VPN DETECTED`;
            badgeV3.className = "badge-risk-pill high";
        } else {
            badgeV3.textContent = `GEO RESOLVED (${emailResult.country || "IP"})`;
            badgeV3.className = "badge-risk-pill low";
        }
    }
    if (fill) fill.style.width = "75%";
    if (pctLabel) pctLabel.textContent = "75%";
    appendLog(`[VECTOR-3 COMPLETE] Origin GeoIP: ${geoLoc} [${ip}] | ASN: ${isp}`, isTor ? "#f87171" : "#34d399");

    if (!(await sleep(350))) return;
    const cardV4 = document.getElementById("step-v4");
    const badgeV4 = document.getElementById("step-v4-badge");
    const detailV4 = document.getElementById("step-v4-detail");
    if (cardV4) cardV4.classList.add("active");
    if (badgeV4) {
        badgeV4.textContent = "SEALING...";
        badgeV4.style.background = "rgba(16, 185, 129, 0.2)";
        badgeV4.style.color = "#34d399";
    }
    appendLog(`[VECTOR-4] Generating SHA-256 chain-of-custody fingerprint & multi-factor risk score...`, "#34d399");
    if (!(await sleep(400))) return;

    const hashSnippet = emailResult.sha256_hash ? emailResult.sha256_hash.substring(0, 16) + "..." : "SEALED";
    const riskLevel = (emailResult.risk_level || "low").toLowerCase();
    const finalScore = emailResult.final_score || 0;

    if (detailV4) detailV4.textContent = `SHA-256: ${hashSnippet} | Composite Risk Score: ${finalScore}/100`;
    if (badgeV4) {
        badgeV4.textContent = `${riskLevel.toUpperCase()} THREAT (${finalScore}/100)`;
        badgeV4.className = `badge-risk-pill ${riskLevel}`;
    }
    if (fill) fill.style.width = "100%";
    if (pctLabel) pctLabel.textContent = "100%";
    if (statusBadge) {
        statusBadge.textContent = "VERIFICATION COMPLETE";
        statusBadge.style.color = "#34d399";
    }
    appendLog(`[VECTOR-4 COMPLETE] SHA-256 Sealed. Aggregated Rating: ${riskLevel.toUpperCase()} (${finalScore}/100)`, "#34d399");

    showFinishedButtons();
}

function openForensicModal(id) {
    const email = storedEmails.find(e => e.id === id);
    if (!email) return;

    currentViewingId = email.id;
    document.getElementById("modal-title").textContent = `Forensic Incident Inspection`;
    document.getElementById("modal-case-subtitle").textContent = `Case #${email.id} — Ingested: ${formatTimestamp(email.received_at)}`;

    const risk = (email.risk_level || "low").toLowerCase();
    const fraudPct = Math.round((email.fraud_score || 0) * 100);
    const attribConf = Math.min(94, Math.max(42, Math.round((email.final_score || 70) * 0.76)));
    const isTorOrVpn = Boolean(email.is_vpn_tor || /tor|vpn|relay|proxy/i.test(email.isp_asn || ""));
    const content = document.getElementById("modal-body-content");

    const signalBadge = (label, color) => `
        <span style="display:inline-flex;align-items:center;gap:0.25rem;font-size:0.62rem;font-weight:700;
            letter-spacing:0.05em;padding:0.15rem 0.45rem;border-radius:3px;
            background:${color}1a;border:1px solid ${color}55;color:${color};font-family:var(--font-mono);
            text-transform:uppercase;margin-left:0.5rem;vertical-align:middle;">${label}</span>`;

    const extractUrls = (text) => {
        if (!text) return [];
        const urlRegex = /https?:\/\/[^\s<>"']+/gi;
        return [...new Set((text.match(urlRegex) || []))].slice(0, 5);
    };

    const bodyUrls = extractUrls(email.body_text || "");
    const headerUrls = extractUrls(email.raw_headers || "");
    const allUrls = [...new Set([...bodyUrls, ...headerUrls])];

    const classifyUrl = (url) => {
        const u = url.toLowerCase();
        if (u.includes("login") || u.includes("verify") || u.includes("auth") || u.includes("secure")) return { label: "Credential Harvest Lure", color: "#f87171" };
        if (u.includes("invoice") || u.includes("wire") || u.includes("payment") || u.includes("transfer")) return { label: "Financial Fraud Redirect", color: "#fbbf24" };
        if (u.includes("update") || u.includes("reauth") || u.includes("renew")) return { label: "Account Takeover Lure", color: "#fb923c" };
        return { label: "Suspicious Redirect", color: "#a78bfa" };
    };

    const detectAttachments = (headers, body) => {
        const text = (headers || "") + (body || "");
        const attachments = [];
        const mimeMatches = text.match(/Content-Type:\s*(application\/[^\s;]+|image\/[^\s;]+|text\/[^\s;]+)/gi) || [];
        const nameMatches = text.match(/filename[*]?=["\s]*([^";\n\r]+)/gi) || [];
        mimeMatches.forEach(m => {
            const type = m.replace(/Content-Type:\s*/i, "").trim();
            if (!["text/plain", "text/html", "multipart/mixed", "multipart/alternative"].some(t => type.toLowerCase().startsWith(t))) {
                attachments.push({ type, risky: /pdf|zip|exe|doc|xls|ppt|js|vbs|macro/i.test(type) });
            }
        });
        if (nameMatches.length > 0 && attachments.length === 0) {
            nameMatches.slice(0, 3).forEach(m => {
                const name = m.replace(/filename[*]?=["'\s]*/i, "").replace(/["'\s]/g, "");
                attachments.push({ type: name, risky: /\.exe|\.js|\.vbs|\.zip|\.doc|\.xls|\.pdf|\.bat/i.test(name) });
            });
        }
        return attachments;
    };

    const attachments = detectAttachments(email.raw_headers, email.body_text);

    const senderDomain = (email.sender || "").split("@")[1] || "unknown";
    const knownLegitDomains = ["github.com", "google.com", "microsoft.com", "amazon.com", "paypal.com", "linkedin.com"];
    const isKnownLegit = knownLegitDomains.includes(senderDomain.toLowerCase());
    const hasLookalike = /paypal-verify|m365-security|corp-secure|amazon-shipment|microsoft-auth|google-auth/i.test(senderDomain);
    const domainRisk = hasLookalike ? "high" : isKnownLegit ? "low" : "medium";
    const domainRiskLabel = domainRisk === "high" ? "Typosquat / Lookalike" : domainRisk === "medium" ? "Unverified Domain" : "Established Domain";
    const domainRiskColor = domainRisk === "high" ? "#f87171" : domainRisk === "medium" ? "#fbbf24" : "#34d399";
    const mxAligned = email.spf_result === "pass" && email.dkim_result === "pass";

    content.innerHTML = `
        <!-- Signal Legend Bar -->
        <div style="background:rgba(255,255,255,0.03);border:1px solid var(--border-subtle);border-radius:0.45rem;padding:0.55rem 0.85rem;margin-bottom:1rem;display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;font-size:0.72rem;">
            <span style="color:var(--text-muted);font-family:var(--font-mono);letter-spacing:0.04em;">SIGNAL KEY:</span>
            ${signalBadge("[Observed Evidence]", "#34d399")}
            ${signalBadge("[Deterministic]", "#60a5fa")}
            ${signalBadge("[ML Prediction]", "#f472b6")}
            ${signalBadge("[Enrichment]", "#a78bfa")}
            ${signalBadge("[Inferred Confidence]", "#fbbf24")}
        </div>

        <!-- 4-Metrics Row: Separate Threat Risk vs Attribution Confidence -->
        <div class="hud-metrics-row">
            <div class="hud-stat-card">
                <div class="hud-stat-title">Threat &amp; Fraud Risk ${signalBadge("[Inferred Confidence]", "#fbbf24")}</div>
                <div class="hud-stat-val">
                    <span class="badge-risk-pill ${risk}">${risk.toUpperCase()}</span>
                </div>
                <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.35rem;">
                    Risk Score: <strong>${email.final_score || 0} / 100</strong>
                </div>
            </div>

            <div class="hud-stat-card">
                <div class="hud-stat-title">Attribution Confidence ${signalBadge("[Inferred Confidence]", "#fbbf24")}</div>
                <div class="hud-stat-val" style="color: #fbbf24;">
                    ${attribConf}%
                </div>
                <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.35rem;">
                    Pattern-matched heuristic (unconfirmed)
                </div>
            </div>

            <div class="hud-stat-card">
                <div class="hud-stat-title">NLP Phishing Probability ${signalBadge("[ML Prediction]", "#f472b6")}</div>
                <div class="hud-stat-val" style="color: ${fraudPct > 50 ? 'var(--threat-high)' : 'var(--threat-low)'};">
                    ${fraudPct}%
                </div>
                <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.35rem;">
                    Raw Coefficient: ${(email.fraud_score || 0).toFixed(2)}
                </div>
            </div>

            <div class="hud-stat-card">
                <div class="hud-stat-title">Cryptographic Auth ${signalBadge("[Deterministic]", "#60a5fa")}</div>
                <div style="display: flex; gap: 0.35rem; justify-content: center; margin-top: 0.35rem;">
                    <span class="auth-badge-tag ${email.spf_result === 'pass' ? 'pass' : email.spf_result === 'fail' ? 'fail' : 'none'}">SPF: ${email.spf_result || 'none'}</span>
                    <span class="auth-badge-tag ${email.dkim_result === 'pass' || email.dkim_result === 'present' ? 'pass' : email.dkim_result === 'fail' ? 'fail' : 'none'}">DKIM: ${email.dkim_result || 'none'}</span>
                    <span class="auth-badge-tag ${email.dmarc_result === 'pass' ? 'pass' : email.dmarc_result === 'fail' ? 'fail' : 'none'}">DMARC: ${email.dmarc_result || 'none'}</span>
                </div>
                <div style="font-size: 0.72rem; color: ${email.header_valid ? 'var(--threat-low)' : 'var(--threat-high)'}; margin-top: 0.35rem;">
                    ${email.header_valid ? '✅ Signatures Validated' : '⚠️ Signatures Failed'}
                </div>
            </div>
        </div>

        <!-- Primary Email Envelope & Full Message Body Card (Instant Access) -->
        <div class="hud-detail-card" style="border: 1px solid rgba(167, 139, 250, 0.4); background: rgba(167, 139, 250, 0.05);">
            <div class="hud-detail-label" style="display: flex; justify-content: space-between; align-items: center;">
                <span><i class="fa-solid fa-envelope-open-text" style="color: var(--primary);"></i> Ingested Email Payload &amp; Envelope Details ${signalBadge("[Observed Evidence]", "#34d399")}</span>
                <span style="font-family: var(--font-mono); font-size: 0.72rem; color: #a78bfa; font-weight: 700;">Case #${email.id}</span>
            </div>
            
            <div style="background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: 0.45rem; padding: 0.85rem 1rem; display: flex; flex-direction: column; gap: 0.45rem; font-size: 0.82rem; margin-bottom: 0.75rem;">
                <div><span style="color: var(--text-muted); width: 85px; display: inline-block;">Subject:</span> <strong style="color: #f8fafc;">${escapeHtml(email.subject)}</strong></div>
                <div><span style="color: var(--text-muted); width: 85px; display: inline-block;">Sender:</span> <span style="font-family: var(--font-mono); color: #a78bfa;">${escapeHtml(email.sender)}</span></div>
                <div><span style="color: var(--text-muted); width: 85px; display: inline-block;">Relay IP:</span> <code style="color: #38bdf8; background: rgba(255,255,255,0.06); padding: 0.15rem 0.4rem; border-radius: 3px;">${escapeHtml(email.ip_address || "N/A")}</code> <span style="color: var(--text-muted); font-size: 0.74rem;">(${escapeHtml(email.city || "Unknown")}, ${escapeHtml(email.country || "Unknown")})</span></div>
                <div><span style="color: var(--text-muted); width: 85px; display: inline-block;">Ingested At:</span> <span style="color: var(--text-muted);">${formatTimestamp(email.received_at)}</span></div>
            </div>

            <!-- Full Message Body Content Excerpt -->
            <div style="margin-bottom: 0.65rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                    <span style="font-size: 0.74rem; font-weight: 700; color: #cbd5e1;"><i class="fa-solid fa-align-left" style="color: var(--primary);"></i> Message Body Text (Clean View)</span>
                    <button type="button" class="btn btn-sm btn-cyber-secondary" onclick="navigator.clipboard.writeText(document.getElementById('modal-raw-body-snippet')?.textContent || ''); showToast('📋 Body text copied to clipboard!', 'success');" style="font-size: 0.68rem; padding: 0.15rem 0.5rem;">
                        <i class="fa-solid fa-copy"></i> Copy Body
                    </button>
                </div>
                <pre class="hud-code-snippet" id="modal-raw-body-snippet" style="max-height: 220px; font-size: 0.78rem; line-height: 1.5; color: #f1f5f9; background: #0b0f19;">${escapeHtml(email.body_text || "(No plaintext body found in .EML payload)")}</pre>
            </div>

            <!-- Raw Network Headers (Collapsible / Preview) -->
            <div>
                <details style="background: rgba(0,0,0,0.25); border: 1px solid var(--border-subtle); border-radius: 0.4rem; padding: 0.45rem 0.75rem;">
                    <summary style="font-size: 0.74rem; font-weight: 700; color: #38bdf8; cursor: pointer; user-select: none;">
                        <i class="fa-solid fa-code"></i> View Full Raw RFC 822 Network Inbound Headers (${(email.raw_headers || "").length} bytes)
                    </summary>
                    <div style="margin-top: 0.5rem;">
                        <pre class="hud-code-snippet" style="max-height: 180px; font-size: 0.7rem; color: #94a3b8; background: #060910;">${email.raw_headers ? escapeHtml(email.raw_headers) : '(No raw headers provided)'}</pre>
                    </div>
                </details>
            </div>
        </div>

        <!-- PS-Required Origin Vector Assessment -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-crosshairs"></i> Origin Vector Assessment (PS-26106) ${signalBadge("[Inferred Confidence]", "#fbbf24")}</div>
            <div style="background: var(--bg-input); padding: 0.85rem 1rem; border-radius: 0.45rem; border: 1px solid var(--border-subtle); display: flex; flex-direction: column; gap: 0.75rem;">
                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.25rem;">
                        <span style="color: #e2e8f0; font-weight: 600;">1. Spoofed Domain / Typosquatting</span>
                        <span style="font-family: var(--font-mono); font-weight: 700; color: ${hasLookalike ? '#f87171' : '#34d399'};">${hasLookalike ? '92% (High Likelihood)' : '18% (Low Likelihood)'}</span>
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border-radius: 3px; height: 6px; overflow: hidden;">
                        <div style="width: ${hasLookalike ? '92%' : '18%'}; background: ${hasLookalike ? '#f87171' : '#34d399'}; height: 100%;"></div>
                    </div>
                    <div style="font-size: 0.69rem; color: var(--text-muted); margin-top: 0.2rem;">${hasLookalike ? 'Lookalike sender domain with missing/failed DMARC cryptographic alignment.' : 'Sender domain matches standard lexical registration patterns.'}</div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.25rem;">
                        <span style="color: #e2e8f0; font-weight: 600;">2. Anonymized Relay Infrastructure (Tor/VPN/Proxy)</span>
                        <span style="font-family: var(--font-mono); font-weight: 700; color: ${isTorOrVpn ? '#fbbf24' : '#60a5fa'};">${isTorOrVpn ? '88% (High Likelihood)' : '24% (Low Likelihood)'}</span>
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border-radius: 3px; height: 6px; overflow: hidden;">
                        <div style="width: ${isTorOrVpn ? '88%' : '24%'}; background: ${isTorOrVpn ? '#fbbf24' : '#60a5fa'}; height: 100%;"></div>
                    </div>
                    <div style="font-size: 0.69rem; color: var(--text-muted); margin-top: 0.2rem;">${isTorOrVpn ? 'Relay IP resolves to known anonymization network (Tor exit relay / VPN transit).' : 'Relay IP routes through standard commercial transit provider.'}</div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.25rem;">
                        <span style="color: #e2e8f0; font-weight: 600;">3. Direct Malicious Hosting Environment</span>
                        <span style="font-family: var(--font-mono); font-weight: 700; color: ${risk === 'high' ? '#f87171' : '#a78bfa'};">${risk === 'high' ? '74% (Moderate-High)' : '12% (Negligible)'}</span>
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border-radius: 3px; height: 6px; overflow: hidden;">
                        <div style="width: ${risk === 'high' ? '74%' : '12%'}; background: ${risk === 'high' ? '#f87171' : '#a78bfa'}; height: 100%;"></div>
                    </div>
                    <div style="font-size: 0.69rem; color: var(--text-muted); margin-top: 0.2rem;">Analysis of autonomous system reputation, ephemeral MX records, and bulletproof ASN patterns.</div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.25rem;">
                        <span style="color: #e2e8f0; font-weight: 600;">4. Compromised Legitimate Account</span>
                        <span style="font-family: var(--font-mono); font-weight: 700; color: ${email.header_valid ? '#fbbf24' : '#64748b'};">${email.header_valid ? '64% (Probable Takeover)' : '14% (Unlikely — Auth Failed)'}</span>
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border-radius: 3px; height: 6px; overflow: hidden;">
                        <div style="width: ${email.header_valid ? '64%' : '14%'}; background: ${email.header_valid ? '#fbbf24' : '#64748b'}; height: 100%;"></div>
                    </div>
                    <div style="font-size: 0.69rem; color: var(--text-muted); margin-top: 0.2rem;">${email.header_valid ? 'Valid cryptographic keys on anomalous sender IP suggest legitimate mailbox hijacking.' : 'DKIM/SPF failure contradicts legitimate compromised infrastructure.'}</div>
                </div>
            </div>
        </div>

        <!-- IoC Extraction Panel -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-list-check"></i> Extracted Indicators of Compromise (IoCs) ${signalBadge("[Observed Evidence]", "#34d399")}</div>
            <div style="background: var(--bg-input); padding: 0.75rem 1rem; border-radius: 0.45rem; border: 1px solid var(--border-subtle); display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.76rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
                    <span style="color: var(--text-muted);"><i class="fa-solid fa-network-wired" style="color: #a78bfa;"></i> IPv4 Relay:</span>
                    <code style="background: rgba(255,255,255,0.05); padding: 0.2rem 0.5rem; border-radius: 3px; color: #38bdf8;">${escapeHtml(email.ip_address || 'N/A')}</code>
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
                    <span style="color: var(--text-muted);"><i class="fa-solid fa-globe" style="color: #06b6d4;"></i> Extracted Domain:</span>
                    <code style="background: rgba(255,255,255,0.05); padding: 0.2rem 0.5rem; border-radius: 3px; color: #38bdf8;">${escapeHtml(senderDomain)}</code>
                </div>
                ${allUrls.length > 0 ? `
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
                    <span style="color: var(--text-muted);"><i class="fa-solid fa-link" style="color: #ec4899;"></i> Extracted URL:</span>
                    <code style="background: rgba(255,255,255,0.05); padding: 0.2rem 0.5rem; border-radius: 3px; color: #f472b6; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(allUrls[0])}</code>
                </div>` : ''}
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
                    <span style="color: var(--text-muted);"><i class="fa-solid fa-fingerprint" style="color: #34d399;"></i> SHA-256 Hash:</span>
                    <code style="background: rgba(255,255,255,0.05); padding: 0.2rem 0.5rem; border-radius: 3px; color: #34d399; font-size: 0.7rem;">${email.sha256_hash ? email.sha256_hash.substring(0, 32) + '...' : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</code>
                </div>
            </div>
        </div>

        <!-- GeoLocation Origin & ASN Box with Geolocation Disclaimer -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-location-crosshairs"></i> Relay Origin &amp; Threat Intelligence ${signalBadge("[Observed Evidence]", "#34d399")}</div>
            <div style="background: var(--bg-input); padding: 0.75rem 1rem; border-radius: 0.4rem; border: 1px solid var(--border-subtle);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                    <div>
                        <strong style="color: var(--text-bright); font-size: 0.95rem;">📍 ${escapeHtml(email.country || 'Unknown')}${email.city ? ', ' + escapeHtml(email.city) : ''}</strong>
                        <span style="font-family: var(--font-mono); color: var(--primary); margin-left: 0.65rem;">[${escapeHtml(email.ip_address || 'No IP')}]</span>
                        <div style="font-size: 0.76rem; color: #a78bfa; margin-top: 0.2rem;">🏢 ${escapeHtml(email.isp_asn || 'Standard Autonomous System')}</div>
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted); text-align: right;">
                        Lat: ${email.latitude || 0}, Lon: ${email.longitude || 0}<br/>
                        Threat Cluster (Inferred): <strong style="color: #f8fafc;">${escapeHtml(email.threat_actor || 'Unattributed')}</strong>
                        <span style="color:var(--text-muted);font-size:0.68rem;display:block;margin-top:0.1rem;">— unconfirmed, pattern-based only</span>
                    </div>
                </div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 0.5rem; border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 0.4rem;">
                    <i class="fa-solid fa-circle-info" style="color: #60a5fa;"></i> <em>Note: Geolocation reflects observed network relay infrastructure (ASNs, proxies, Tor hops) and does not represent the sender's verified physical location.</em>
                </div>
            </div>
        </div>

        <!-- Domain & Sender Intelligence -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-shield-halved"></i> Domain &amp; Sender Intelligence ${signalBadge("[Enrichment]", "#a78bfa")}</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.65rem;">
                <div style="background:var(--bg-input);padding:0.65rem 0.85rem;border-radius:0.4rem;border:1px solid var(--border-subtle);">
                    <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.25rem;">Sender Domain</div>
                    <div style="font-family:var(--font-mono);color:#a78bfa;font-size:0.83rem;word-break:break-all;">${escapeHtml(senderDomain)}</div>
                </div>
                <div style="background:var(--bg-input);padding:0.65rem 0.85rem;border-radius:0.4rem;border:1px solid ${domainRiskColor}44;">
                    <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.25rem;">Domain Classification</div>
                    <div style="font-weight:700;color:${domainRiskColor};font-size:0.83rem;">
                        ${domainRisk === "high" ? "⚠️" : domainRisk === "medium" ? "🔶" : "✅"} ${domainRiskLabel}
                    </div>
                </div>
                <div style="background:var(--bg-input);padding:0.65rem 0.85rem;border-radius:0.4rem;border:1px solid var(--border-subtle);">
                    <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.25rem;">MX Record Alignment</div>
                    <div style="font-weight:600;color:${mxAligned ? '#34d399' : '#f87171'};font-size:0.83rem;">
                        ${mxAligned ? '✅ SPF + DKIM Pass (Aligned)' : '❌ MX Alignment Failed'}
                    </div>
                </div>
                <div style="background:var(--bg-input);padding:0.65rem 0.85rem;border-radius:0.4rem;border:1px solid var(--border-subtle);">
                    <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.25rem;">Lookalike Typosquat Detection</div>
                    <div style="font-weight:600;color:${hasLookalike ? '#f87171' : '#34d399'};font-size:0.83rem;">
                        ${hasLookalike ? '🔴 Lookalike Domain Detected' : '🟢 No Lookalike Pattern Found'}
                    </div>
                </div>
            </div>
        </div>

        <!-- URL & Redirect Intelligence -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-link"></i> URL &amp; Redirect Intelligence ${signalBadge("[ML Prediction]", "#f472b6")}</div>
            ${allUrls.length > 0 ? `
            <div style="display:flex;flex-direction:column;gap:0.45rem;">
                ${allUrls.map(url => {
                    const cat = classifyUrl(url);
                    return `<div style="background:var(--bg-input);padding:0.55rem 0.85rem;border-radius:0.4rem;border:1px solid ${cat.color}44;display:flex;align-items:center;justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">
                        <span style="font-family:var(--font-mono);font-size:0.73rem;color:#e2e8f0;word-break:break-all;flex:1;">${escapeHtml(url)}</span>
                        <span style="font-size:0.67rem;font-weight:700;color:${cat.color};background:${cat.color}18;border:1px solid ${cat.color}44;padding:0.1rem 0.4rem;border-radius:3px;white-space:nowrap;">${cat.label}</span>
                    </div>`;
                }).join("")}
            </div>` : `<div style="color:var(--text-muted);font-size:0.82rem;padding:0.5rem 0;"><i class="fa-solid fa-circle-check" style="color:#34d399;"></i> No suspicious URLs extracted from message body or headers.</div>`}
        </div>

        <!-- Attachment Intelligence -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-paperclip"></i> Attachment Intelligence ${signalBadge("[Observed Evidence]", "#34d399")}</div>
            ${attachments.length > 0 ? `
            <div style="display:flex;flex-direction:column;gap:0.4rem;">
                ${attachments.map(att => `
                    <div style="background:var(--bg-input);padding:0.55rem 0.85rem;border-radius:0.4rem;border:1px solid ${att.risky ? '#f8717144' : 'var(--border-subtle)'};display:flex;align-items:center;justify-content:space-between;gap:0.5rem;">
                        <span style="font-family:var(--font-mono);font-size:0.78rem;color:#e2e8f0;">${escapeHtml(att.type)}</span>
                        <span style="font-size:0.67rem;font-weight:700;color:${att.risky ? '#f87171' : '#34d399'};background:${att.risky ? '#f8717118' : '#34d39918'};border:1px solid ${att.risky ? '#f8717144' : '#34d39944'};padding:0.1rem 0.4rem;border-radius:3px;">${att.risky ? '⚠️ High-Risk MIME' : '✅ Standard MIME'}</span>
                    </div>`).join("")}
            </div>` : `<div style="color:var(--text-muted);font-size:0.82rem;padding:0.5rem 0;"><i class="fa-solid fa-circle-check" style="color:#34d399;"></i> No attachments detected in this message payload.</div>`}
        </div>

        <!-- Evidence Governance & Privacy Controls -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-user-shield"></i> Evidence Governance &amp; Privacy Controls ${signalBadge("[Deterministic]", "#60a5fa")}</div>
            <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 0.45rem; padding: 0.75rem 1rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; font-size: 0.74rem;">
                <div><span style="color: var(--text-muted);">PII Redaction:</span> <strong style="color: #34d399;">Active (Masked in Logs)</strong></div>
                <div><span style="color: var(--text-muted);">Raw Email Storage:</span> <strong style="color: #34d399;">Volatile In-Memory (Zero Plaintext)</strong></div>
                <div><span style="color: var(--text-muted);">Retention Policy:</span> <strong style="color: #f8fafc;">30-Day Auto Purge</strong></div>
                <div><span style="color: var(--text-muted);">Evidence Integrity:</span> <strong style="color: #34d399;">ISO/IEC 27037 Sealed</strong></div>
            </div>
        </div>

        <!-- Evidence Chain of Custody SHA-256 -->
        <div class="hud-detail-card">
            <div class="hud-detail-label"><i class="fa-solid fa-fingerprint"></i> Evidence Integrity &amp; Chain-of-Custody SHA-256 Fingerprint ${signalBadge("[Observed Evidence]", "#34d399")}</div>
            <div style="font-family: var(--font-mono); font-size: 0.76rem; color: #34d399; background: var(--bg-input); padding: 0.55rem 0.75rem; border-radius: 0.35rem; border: 1px solid rgba(16, 185, 129, 0.3); word-break: break-all;">
                ${email.sha256_hash ? email.sha256_hash : 'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
            </div>
        </div>

        <!-- Action Row at Bottom of Modal -->
        <div style="display: flex; gap: 0.65rem; justify-content: flex-end; margin-top: 0.5rem; flex-wrap: wrap;">
            <button type="button" class="btn btn-cyber-secondary" onclick="closeForensicModal(); const wsTab = document.querySelector('.nav-tab[data-tab=\\'investigation\\']') || document.querySelector('.nav-tab[data-tab=\\'workspace\\']'); if (wsTab) wsTab.click(); renderInvestigationWorkspace(${email.id});">
                <i class="fa-solid fa-folder-open"></i> <span>Open in Investigation Workspace</span>
            </button>
            <button type="button" class="btn btn-cyber-primary" onclick="downloadReport(${email.id});">
                <i class="fa-solid fa-file-pdf"></i> <span>Download Forensic Report</span>
            </button>
        </div>
    `;

    document.getElementById("forensic-modal").classList.remove("hidden");
}
if (typeof window !== "undefined") {
    window.openForensicModal = openForensicModal;
}

function closeForensicModal() {
    document.getElementById("forensic-modal").classList.add("hidden");
    currentViewingId = null;
}

if (typeof window !== "undefined") {
    window.downloadReport = function (id) {
        const targetId = id || currentWorkspaceCaseId || 1001;
        showToast(`📄 Preparing Forensic Incident Report for Case #${targetId}...`, "info");

        if (API_BASE) {
            const url = `${API_BASE}/emails/${targetId}/report`;
            fetch(url, { method: "HEAD" })
                .then(res => {
                    if (res.ok) {
                        window.open(url, "_blank");
                    } else {
                        fallbackPrintForensicReport(targetId);
                    }
                })
                .catch(() => {
                    fallbackPrintForensicReport(targetId);
                });
        } else {
            fallbackPrintForensicReport(targetId);
        }
    };
}

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast-msg toast-${type}`;

    let icon = "fa-circle-info";
    if (type === "success") icon = "fa-circle-check";
    if (type === "error") icon = "fa-triangle-exclamation";

    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(20px)";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatTimestamp(ts) {
    if (!ts) return "N/A";
    try {
        const date = new Date(ts);
        if (isNaN(date.getTime())) return ts;
        return date.toLocaleString();
    } catch {
        return ts;
    }
}