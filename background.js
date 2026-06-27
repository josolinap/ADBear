// ==================== STATE ====================
const QUERY_LOG = [];
const MAX_QUERY_LOG = 10000;
let blockedDomains = new Set();
let blockedIps = new Set();
let whitelistedDomains = new Set();
let filteringEnabled = false;
let blockedCount = 0;
let totalQueries = 0;
let uniqueDomains = new Set();
let dnsResolveCount = 0;
let dnsResolveErrors = 0;
let dnsResolveTimes = [];
let webRequestCount = 0;
let blockedByListCount = 0;
let allowedCount = 0;
let bwSent = 0;
let bwReceived = 0;

const DNS_CACHE = new Map();
const DNS_CACHE_TTL = 300000;
const DNS_QUEUE = [];
let dnsProcessing = false;
let currentDnsServers = ["1.1.1.1"];

// ==================== FIREFOX CONNECTION TRACKER ====================
const FIREFOX_CONNECTIONS = new Map();
const CONNECTION_TTL = 120000;
let connectionId = 0;

const WELL_KNOWN_PORTS = {
    80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP",
    53: "DNS", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 3389: "RDP", 5900: "VNC", 27017: "MongoDB"
};

const RISK_RULES = [
    { match: (d) => /track|analytics|pixel|beacon|telemetry/i.test(d), level: "medium", reason: "Tracker" },
    { match: (d) => /ad[sx]?|doubleclick|adservice|adnetwork|adserver/i.test(d), level: "low", reason: "Ad Server" },
    { match: (d) => /malware|phish|scam|exploit|hack/i.test(d), level: "critical", reason: "Suspicious Domain" },
    { match: (d) => /login|signin|auth|oauth|sso/i.test(d), level: "medium", reason: "Authentication" },
    { match: (d) => /payment|checkout|stripe|paypal|billing/i.test(d), level: "high", reason: "Financial" },
    { match: (d) => /cdn|cloudfront|akamai|fastly|cloudflare/i.test(d), level: "safe", reason: "CDN" },
    { match: (d) => /google|facebook|meta|twitter|x\.com|tiktok/i.test(d), level: "low", reason: "Big Tech" },
    { match: (d) => /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(d) && !d.includes("127.0.0.1"), level: "medium", reason: "Direct IP" },
];

function assessRisk(domain) {
    for (const rule of RISK_RULES) {
        if (rule.match(domain)) return { level: rule.level, reason: rule.reason };
    }
    return { level: "safe", reason: "Normal" };
}

function extractDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return null;
    }
}

function getProtocolFromUrl(url) {
    try {
        const proto = new URL(url).protocol;
        if (proto === "https:") return "TCP";
        if (proto === "http:") return "TCP";
        if (proto === "wss:" || proto === "ws:") return "TCP";
        if (proto === "ftp:") return "TCP";
        return "TCP";
    } catch {
        return "TCP";
    }
}

function getPortFromUrl(url) {
    try {
        const u = new URL(url);
        if (u.port) return parseInt(u.port);
        if (u.protocol === "https:" || u.protocol === "wss:") return 443;
        if (u.protocol === "http:" || u.protocol === "ws:") return 80;
        if (u.protocol === "ftp:") return 21;
        return 0;
    } catch {
        return 0;
    }
}

function addFirefoxConnection(details) {
    const domain = extractDomain(details.url);
    if (!domain) return;
    if (domain === "localhost" || domain === "127.0.0.1" || domain === "0.0.0.0") return;
    if (domain.endsWith(".mozilla.org") || domain.endsWith(".mozilla.net")) return;

    const port = getPortFromUrl(details.url);
    const protocol = getProtocolFromUrl(details.url);
    const risk = assessRisk(domain);
    const cid = `${domain}:${port}:${details.requestId || ++connectionId}`;

    if (FIREFOX_CONNECTIONS.has(cid)) {
        const existing = FIREFOX_CONNECTIONS.get(cid);
        existing.lastSeen = Date.now();
        existing.requestCount = (existing.requestCount || 1) + 1;
        return;
    }

    const conn = {
        id: cid,
        protocol,
        local_ip: "127.0.0.1",
        local_port: 0,
        remote_ip: domain,
        remote_port: port,
        state: "ESTABLISHED",
        pid: 0,
        process_name: details.tabId ? `Tab ${details.tabId}` : "Background",
        tab_id: details.tabId || 0,
        country: null,
        country_code: null,
        city: null,
        asn: null,
        risk_level: risk.level,
        risk_reason: risk.reason,
        domain: domain,
        service: WELL_KNOWN_PORTS[port] || "",
        url: details.url,
        type: details.type || "other",
        method: details.method || "GET",
        requestCount: 1,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        isNew: true,
        isClosed: false,
        blocked: false,
    };

    FIREFOX_CONNECTIONS.set(cid, conn);

    if (DNS_CACHE.has(domain)) {
        const cached = DNS_CACHE.get(domain);
        if (cached.result && cached.result.addresses && cached.result.addresses.length > 0) {
            conn.remote_ip = cached.result.addresses[0];
        }
    }

    scheduleConnectionCleanup();
}

function removeFirefoxConnection(details) {
    const domain = extractDomain(details.url);
    if (!domain) return;
    const port = getPortFromUrl(details.url);
    const cid = `${domain}:${port}:${details.requestId}`;
    const conn = FIREFOX_CONNECTIONS.get(cid);
    if (conn) {
        conn.state = "CLOSE_WAIT";
        conn.isClosed = true;
        conn.lastSeen = Date.now();
    }
}

function getActiveFirefoxConnections() {
    const now = Date.now();
    const active = [];
    for (const [cid, conn] of FIREFOX_CONNECTIONS) {
        if (now - conn.lastSeen < CONNECTION_TTL) {
            active.push(conn);
        }
    }
    active.sort((a, b) => b.lastSeen - a.lastSeen);
    return active;
}

function scheduleConnectionCleanup() {
    if (scheduleConnectionCleanup.timer) return;
    scheduleConnectionCleanup.timer = setTimeout(() => {
        scheduleConnectionCleanup.timer = null;
        const now = Date.now();
        for (const [cid, conn] of FIREFOX_CONNECTIONS) {
            if (now - conn.lastSeen > CONNECTION_TTL) {
                FIREFOX_CONNECTIONS.delete(cid);
            }
        }
        if (FIREFOX_CONNECTIONS.size > 0) {
            scheduleConnectionCleanup();
        }
    }, 30000);
}

// ==================== WEBREQUEST LISTENERS ====================
function isDomainBlocked(domain) {
    if (!filteringEnabled || !domain) return false;
    const d = domain.toLowerCase().replace(/\.$/, "");

    // Whitelist check (walk parent chain)
    let current = d;
    while (current) {
        if (whitelistedDomains.has(current)) return false;
        const firstDot = current.indexOf(".");
        if (firstDot === -1) break;
        current = current.substring(firstDot + 1);
        if (!current.includes(".")) break;
    }

    // Domain block check (walk parent chain)
    current = d;
    while (current) {
        if (blockedDomains.has(current)) return true;
        const firstDot = current.indexOf(".");
        if (firstDot === -1) break;
        current = current.substring(firstDot + 1);
        if (!current.includes(".")) break;
    }

    // IP-based block: only if domain is literally an IP
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(d) && blockedIps.has(d)) return true;

    return false;
}

browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        webRequestCount++;
        addFirefoxConnection(details);

        if (!details.url) return;
        const domain = extractDomain(details.url);
        if (!domain) return;
        if (domain === "localhost" || domain === "127.0.0.1") return;
        if (domain.endsWith(".mozilla.org") || domain.endsWith(".mozilla.net")) return;

        if (isDomainBlocked(domain)) {
            blockedCount++;
            blockedByListCount++;
            logQuery(domain, details.type, true, details.tabId);
            const cid = `${domain}:${getPortFromUrl(details.url)}:${details.requestId}`;
            const conn = FIREFOX_CONNECTIONS.get(cid);
            if (conn) { conn.blocked = true; conn.state = "BLOCKED"; }
            return { cancel: true };
        }

        allowedCount++;
        logQuery(domain, details.type, false, details.tabId);
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

browser.webRequest.onCompleted.addListener(
    (details) => {
        const conn = FIREFOX_CONNECTIONS.get(`${extractDomain(details.url)}:${getPortFromUrl(details.url)}:${details.requestId}`);
        if (conn) { conn.state = "ESTABLISHED"; conn.lastSeen = Date.now(); }
    },
    { urls: ["<all_urls>"] }
);

browser.webRequest.onErrorOccurred.addListener(
    (details) => {
        removeFirefoxConnection(details);
    },
    { urls: ["<all_urls>"] }
);

browser.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.fromCache) return;
        if (details.statusCode < 200 || details.statusCode >= 300) return;
        const cl = details.responseHeaders?.find(
            h => h.name.toLowerCase() === "content-length"
        );
        if (cl) {
            bwReceived += parseInt(cl.value, 10) || 0;
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

browser.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url && details.url.startsWith("http")) {
        addFirefoxConnection({ url: details.url, type: "main_frame", tabId: details.tabId, requestId: `nav-${details.timeStamp}` });
    }
});

// ==================== DNS RESOLVE ====================
async function resolveDomain(domain) {
    if (DNS_CACHE.has(domain)) {
        const cached = DNS_CACHE.get(domain);
        if (Date.now() - cached.ts < DNS_CACHE_TTL) return { result: cached.result, resolveTime: 0 };
    }

    const t0 = Date.now();
    try {
        const result = await browser.dns.resolve(domain, { dnsServers: currentDnsServers });
        const ms = Date.now() - t0;
        dnsResolveCount++;
        dnsResolveTimes.push(ms);
        if (dnsResolveTimes.length > 100) dnsResolveTimes.shift();
        DNS_CACHE.set(domain, { result, ts: Date.now() });
        return { result, resolveTime: ms };
    } catch (e) {
        dnsResolveErrors++;
        return null;
    }
}

async function processDnsQueue() {
    dnsProcessing = true;
    while (DNS_QUEUE.length > 0) {
        const { domain, entry } = DNS_QUEUE.shift();
        const resolved = await resolveDomain(domain);
        if (resolved) {
            entry.resolvedIps = resolved.result.addresses || [];
            entry.resolveTime = resolved.resolveTime;
        }
    }
    dnsProcessing = false;
}

// ==================== QUERY LOG ====================
function logQuery(domain, type, blocked, tabId) {
    totalQueries++;
    if (blocked) blockedCount++;
    uniqueDomains.add(domain);

    const cached = DNS_CACHE.get(domain);
    const entry = {
        time: Date.now(), domain, type, blocked, tabId,
        resolvedIps: (cached && cached.result && cached.result.addresses) ? cached.result.addresses : [],
        resolveTime: 0,
    };
    QUERY_LOG.push(entry);
    if (QUERY_LOG.length > MAX_QUERY_LOG) QUERY_LOG.splice(0, QUERY_LOG.length - MAX_QUERY_LOG);

    if (!blocked && !cached) {
        DNS_QUEUE.push({ domain, entry });
        if (!dnsProcessing) processDnsQueue();
    }
}

// ==================== STATS HELPERS ====================
function getTopBlocked() {
    const c = {};
    for (const q of QUERY_LOG) if (q.blocked) c[q.domain] = (c[q.domain] || 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([d, n]) => ({ domain: d, count: n }));
}

function getTopAllowed() {
    const c = {};
    for (const q of QUERY_LOG) if (!q.blocked) c[q.domain] = (c[q.domain] || 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([d, n]) => ({ domain: d, count: n }));
}

function getClients() {
    const c = {};
    for (const q of QUERY_LOG) { const k = "Tab " + (q.tabId || "?"); c[k] = (c[k] || 0) + 1; }
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, n]) => ({ client: k, count: n }));
}

function getQueryTypes() {
    const c = {};
    for (const q of QUERY_LOG) { const t = q.type || "other"; c[t] = (c[t] || 0) + 1; }
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([t, n]) => ({ type: t, count: n }));
}

// ==================== NATIVE MESSAGING (for geoip, bandwidth, ping) ====================
let nativePort = null;
let pendingRequests = new Map();
let requestId = 0;
let connecting = false;
let reconnectTimer = null;
let nativeRetries = 0;

function connectNative() {
    if (typeof browser.runtime.connectNative === "undefined") return;  // Android
    if (connecting || nativePort) return;
    connecting = true;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    nativeRetries++;

    try {
        nativePort = browser.runtime.connectNative("ipwatch_host");
        connecting = false;
        nativeRetries = 0;

        nativePort.onMessage.addListener((response) => {
            if (response._requestId !== undefined) {
                const pending = pendingRequests.get(response._requestId);
                if (pending) {
                    pending.resolve(response);
                    pendingRequests.delete(response._requestId);
                }
            }
        });

        nativePort.onDisconnect.addListener(() => {
            console.warn("Ad Bear: native host disconnected, reconnecting...");
            nativePort = null;
            connecting = false;
            scheduleNativeRetry();
        });

        console.debug("Ad Bear: connected to native host");
    } catch (e) {
        connecting = false;
        nativePort = null;
        scheduleNativeRetry();
    }
}

function scheduleNativeRetry() {
    const delays = [3000, 10000, 30000, 60000];
    const delay = delays[Math.min(nativeRetries - 1, delays.length - 1)];
    reconnectTimer = setTimeout(connectNative, delay);
}

async function sendNative(action, params = {}) {
    if (!nativePort) {
        if (!connecting) connectNative();
        let waited = 0;
        while (!nativePort && waited < 8000) {
            await new Promise(r => setTimeout(r, 200));
            waited += 200;
        }
        if (!nativePort) throw new Error("Native host not connected after waiting");
    }
    const id = ++requestId;
    const msg = { _requestId: id, action, ...params };
    return new Promise((resolve, reject) => {
        pendingRequests.set(id, { resolve, reject });
        try {
            nativePort.postMessage(msg);
        } catch (e) {
            pendingRequests.delete(id);
            nativePort = null;
            connectNative();
            reject(new Error("Native host post failed: " + e.message));
            return;
        }
        setTimeout(() => {
            if (pendingRequests.has(id)) {
                pendingRequests.delete(id);
                reject(new Error("Native host request timeout"));
            }
        }, 10000);
    });
}

// ==================== LOAD SAVED STATE ====================
browser.storage.local.get(["blocklist", "blockedIps", "whitelist", "filteringEnabled"]).then((data) => {
    if (data.blocklist) blockedDomains = new Set(data.blocklist);
    if (data.blockedIps) blockedIps = new Set(data.blockedIps);
    if (data.whitelist) whitelistedDomains = new Set(data.whitelist);
    if (data.filteringEnabled) filteringEnabled = data.filteringEnabled;
}).catch(() => {});

if (typeof browser.runtime.connectNative !== "undefined") {
    connectNative();
} else {
    console.info("Ad Bear: native messaging unavailable (mobile) — GeoIP/bandwidth disabled");
}

// ==================== MESSAGE HANDLER ====================
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case "get_stats":
            sendResponse({
                totalQueries, blockedCount,
                blockedPct: totalQueries > 0 ? ((blockedCount / totalQueries) * 100).toFixed(1) : 0,
                topBlocked: getTopBlocked(), topAllowed: getTopAllowed(),
                clients: getClients(), queryTypes: getQueryTypes(),
                filteringEnabled, domainCount: blockedDomains.size,
                uniqueDomains: uniqueDomains.size, dnsResolveCount, dnsResolveErrors,
                avgResolveTime: dnsResolveTimes.length > 0 ? (dnsResolveTimes.reduce((a, b) => a + b, 0) / dnsResolveTimes.length).toFixed(1) : 0,
                webRequestCount, blockedByListCount, allowedCount,
            });
            return true;

        case "get_query_log":
            const start = message.start || 0;
            const limit = message.limit || 100;
            sendResponse({
                queries: QUERY_LOG.slice().reverse().slice(start, start + limit),
                total: QUERY_LOG.length, blockedCount, totalQueries,
                blockedPct: totalQueries > 0 ? ((blockedCount / totalQueries) * 100).toFixed(1) : 0,
            });
            return true;

        case "update_blocklist":
            blockedDomains = new Set(message.domains || []);
            blockedIps = new Set(message.ips || []);
            whitelistedDomains = new Set(message.whitelist || []);
            filteringEnabled = message.enabled || false;
            browser.storage.local.set({ 
                blocklist: [...blockedDomains], 
                blockedIps: [...blockedIps],
                whitelist: [...whitelistedDomains], 
                filteringEnabled 
            }).catch(() => {});
            sendResponse({ success: true, count: blockedDomains.size + blockedIps.size });
            return true;

        case "clear_query_log":
            QUERY_LOG.length = 0;
            blockedCount = 0; totalQueries = 0; uniqueDomains.clear();
            dnsResolveTimes = []; webRequestCount = 0; blockedByListCount = 0; allowedCount = 0;
            bwSent = 0; bwReceived = 0;
            sendResponse({ success: true });
            return true;

        case "clear_dns_cache":
            DNS_CACHE.clear();
            sendResponse({ success: true });
            return true;

        case "get_connections":
            const conns = getActiveFirefoxConnections();
            sendResponse({ type: "connections", data: conns });
            return true;

        case "native_connections":
            sendResponse({ type: "connections", data: getActiveFirefoxConnections() });
            return true;

        case "native_detail":
            sendNative("detail", { ip: message.ip, port: message.port, proto: message.proto, dns: message.dns })
                .then((resp) => sendResponse(resp))
                .catch((e) => sendResponse({ type: "error", message: e.message }));
            return true;

        case "native_bandwidth":
            (async () => {
                try {
                    const resp = await sendNative("bandwidth");
                    sendResponse(resp);
                } catch {
                    sendResponse({
                        type: "bandwidth",
                        data: { Sent: bwSent, Received: bwReceived }
                    });
                }
            })();
            return true;

        case "native_ping":
            sendNative("ping")
                .then((resp) => sendResponse(resp))
                .catch((e) => sendResponse({ type: "error", message: e.message }));
            return true;

        case "set_filtering":
            filteringEnabled = message.enabled || false;
            browser.storage.local.set({ filteringEnabled }).catch(() => {});
            sendResponse({ success: true });
            return true;

        case "resolve_dns":
            resolveDomain(message.domain).then((resolved) => {
                sendResponse({ success: !!resolved, addresses: resolved ? resolved.result.addresses : [] });
            }).catch(() => sendResponse({ success: false, addresses: [] }));
            return true;

        case "get_platform":
            (async () => {
                try {
                    const info = await browser.runtime.getPlatformInfo();
                    sendResponse({
                        os: info.os, arch: info.arch,
                        isAndroid: info.os === "android",
                        hasSidebar: typeof browser.sidebarAction !== "undefined",
                        hasContextMenus: typeof browser.contextMenus !== "undefined",
                        hasNativeMessaging: typeof browser.runtime.connectNative !== "undefined",
                    });
                } catch { sendResponse({ os: "unknown", isAndroid: false }); }
            })();
            return true;

        default:
            console.warn("Ad Bear: unknown action:", message.action);
            sendResponse({ error: "unknown_action", action: message.action });
            return false;
    }
});
