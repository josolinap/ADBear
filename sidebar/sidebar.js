// ===== Mobile detection (Android compatibility) =====
(async function detectMobile() {
  try {
    const info = await browser.runtime.getPlatformInfo();
    if (info.os === "android") {
      document.body.classList.add("mobile");
      console.debug("Ad Bear: mobile mode (Android)");
    }
  } catch {}
  if (window.innerWidth < 600) document.body.classList.add("mobile");
  window.addEventListener("resize", () => {
    if (window.innerWidth < 600) document.body.classList.add("mobile");
    else document.body.classList.remove("mobile");
  });
})();

async function checkNativeAvailability() {
  try {
    const platform = await browser.runtime.sendMessage({ action: "get_platform" });
    if (platform && !platform.hasNativeMessaging) {
      const banner = document.createElement("div");
      banner.style.cssText = "background:#fef3c7;color:#92400e;padding:8px 12px;font-size:12px;border-bottom:1px solid #fcd34d;";
      banner.textContent = "GeoIP/bandwidth unavailable on mobile. Connection tracking still works.";
      document.body.insertBefore(banner, document.body.firstChild);
      document.querySelectorAll(".requires-native").forEach(el => el.style.display = "none");
    }
  } catch {}
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", checkNativeAvailability);
} else { checkNativeAvailability(); }

let connections = [];
let filteredConnections = [];
let previousConnections = new Set();
let sortKey = null;
let sortAsc = true;
let currentView = "grouped";
let expandedGroups = new Set();
let historySnapshots = [];
let favorites = new Set();
let blocklist = new Set();
let autoBlocklistIps = new Set();
let refreshInterval = 3000;
let refreshTimer = null;
let dnsProvider = "1.1.1.1";
let dnsFilteringEnabled = false;
let dnsFilteringDomains = [];
let customBlocklistUrls = [];
let manualBlockedDomains = [];
let whitelistedDomains = [];
let dnsStats = null;
let queryLogData = [];
let queryLogFilter = "all";
let queryLogSearch = "";
let streamFilter = "all";
let streamTabFilter = "all";
let streamEntries = [];
const MAX_STREAM = 200;
let prevBandwidth = { sent: 0, received: 0 };
let bandwidthRate = { sent: 0, received: 0 };
let alerts = [];
let alertCount = 0;
let connectAttempts = 0;
const MAX_ALERTS = 100;
const SUSPICIOUS_PORTS = new Set([4444, 5555, 6666, 8888, 1337, 31337, 12345, 65535, 1080, 9050, 9051]);
const HIGH_RISK_PORTS = new Set([23, 445, 3389, 5900, 6379, 27017, 1433, 3306, 5432]);

// Network Profiles
const PROFILES_KEY = "ipwatch_profiles";
const PROFILE_KEY = "ipwatch_current_profile";
const DEFAULT_PROFILES = {
    home: { name: "Home", icon: "\ud83c\udfe0", color: "#22c55e", gatewaySubnet: "192.168.1.", alertMode: "monitor", dnsFiltering: true, blocklistFeeds: true, strictMode: false },
    work: { name: "Work", icon: "\ud83c\udfe2", color: "#3b82f6", gatewaySubnet: "10.0.", alertMode: "alert", dnsFiltering: false, blocklistFeeds: false, strictMode: false },
    public: { name: "Public WiFi", icon: "\u2615", color: "#f59e0b", gatewaySubnet: "", alertMode: "strict", dnsFiltering: true, blocklistFeeds: true, strictMode: true },
};
let profiles = {};
let currentProfile = "home";
let detectedNetwork = null;

function loadProfiles() {
    try {
        const saved = localStorage.getItem(PROFILES_KEY);
        profiles = saved ? { ...DEFAULT_PROFILES, ...JSON.parse(saved) } : { ...DEFAULT_PROFILES };
    } catch (e) { profiles = { ...DEFAULT_PROFILES }; }
    try { currentProfile = localStorage.getItem(PROFILE_KEY) || "home"; } catch (e) { currentProfile = "home"; }
}

function saveProfiles() {
    try { localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles)); } catch (e) {}
}

function saveCurrentProfile() {
    try { localStorage.setItem(PROFILE_KEY, currentProfile); } catch (e) {}
}

function getProfile(id) { return profiles[id] || profiles.home; }

function applyProfileSettings() {
    const p = getProfile(currentProfile);
    if (p.dnsFiltering !== undefined) {
        dnsFilteringEnabled = p.dnsFiltering;
        dnsFilteringToggle.checked = dnsFilteringEnabled;
    }
    if (p.blocklistFeeds !== undefined) {
        blocklistAutoToggle.checked = p.blocklistFeeds;
        saveSettings();
        if (blocklistAutoToggle.checked) updateAutoBlocklist();
        else { autoBlocklistIps.clear(); localStorage.removeItem(AUTO_BLOCKLIST_KEY); browser.runtime.sendMessage({ action: "update_blocklist", domains: [...dnsFilteringDomains].slice(0, 100000), ips: [], whitelist: [...whitelistedDomains], enabled: dnsFilteringEnabled }).catch(() => {}); updateBlocklistStatus(); }
    }
    updateProfileIndicator();
    browser.runtime.sendMessage({ action: "set_filtering", enabled: dnsFilteringEnabled }).catch(() => {});
}

function updateProfileIndicator() {
    const p = getProfile(currentProfile);
    const el = $("profile-indicator");
    if (el) {
        el.textContent = `${p.icon} ${p.name}`;
        el.style.color = p.color;
        el.title = `Profile: ${p.name} (${p.alertMode} mode)`;
    }
}

function detectNetwork() {
    const conn = connections[0];
    if (!conn) return;
    const localIp = conn.local_ip;
    for (const [id, p] of Object.entries(profiles)) {
        if (p.gatewaySubnet && localIp.startsWith(p.gatewaySubnet)) {
            if (currentProfile !== id) {
                currentProfile = id;
                saveCurrentProfile();
                applyProfileSettings();
            }
            detectedNetwork = id;
            return;
        }
    }
    if (currentProfile !== "public") {
        currentProfile = "public";
        saveCurrentProfile();
        applyProfileSettings();
    }
    detectedNetwork = "public";
}

const HISTORY_KEY = "ipwatch_history";
const FAVORITES_KEY = "ipwatch_favorites";
const BLOCKLIST_KEY = "ipwatch_blocklist";
const AUTO_BLOCKLIST_KEY = "ipwatch_auto_blocklist";
const SETTINGS_KEY = "ipwatch_settings";
const CUSTOM_BLOCKLIST_KEY = "ipwatch_custom_blocklists";
const MANUAL_BLOCKLIST_KEY = "ipwatch_manual_domains";
const WHITELIST_KEY = "ipwatch_whitelist_domains";
const MAX_HISTORY = 200;
const DB_NAME = "ipwatch_db";
const DB_VERSION = 1;
const STORE_HISTORY = "connection_history";
const MAX_DB_HISTORY = 500;
let dbReady = false;
let dbConnection = null;

// Domain classification database (inspired by NextDNS Medic)
// Categories: login, video, checkout, maps, chat, ads, trackers, analytics, cdn, social, email, gaming, streaming, news, shopping, dev, cloud, misc
const DOMAIN_CLASSIFICATIONS = {
    "google.com": { service: "Google", category: "search", impact: "login", risk: "low" },
    "googleapis.com": { service: "Google APIs", category: "cdn", impact: "maps", risk: "low" },
    "google-analytics.com": { service: "Google Analytics", category: "analytics", impact: "tracking", risk: "low" },
    "googleadservices.com": { service: "Google Ads", category: "ads", impact: "ads", risk: "low" },
    "googletagmanager.com": { service: "Google Tag Manager", category: "analytics", impact: "tracking", risk: "low" },
    "gstatic.com": { service: "Google Static", category: "cdn", impact: "maps", risk: "low" },
    "youtube.com": { service: "YouTube", category: "streaming", impact: "video", risk: "low" },
    "ytimg.com": { service: "YouTube Images", category: "cdn", impact: "video", risk: "low" },
    "facebook.com": { service: "Facebook", category: "social", impact: "login", risk: "low" },
    "fbcdn.net": { service: "Facebook CDN", category: "cdn", impact: "social", risk: "low" },
    "facebook.net": { service: "Facebook Network", category: "social", impact: "login", risk: "low" },
    "instagram.com": { service: "Instagram", category: "social", impact: "login", risk: "low" },
    "twitter.com": { service: "Twitter/X", category: "social", impact: "login", risk: "low" },
    "x.com": { service: "X (Twitter)", category: "social", impact: "login", risk: "low" },
    "t.co": { service: "Twitter Shortener", category: "social", impact: "social", risk: "low" },
    "twimg.com": { service: "Twitter Images", category: "cdn", impact: "social", risk: "low" },
    "linkedin.com": { service: "LinkedIn", category: "social", impact: "login", risk: "low" },
    "amazon.com": { service: "Amazon", category: "shopping", impact: "checkout", risk: "low" },
    "amazonaws.com": { service: "AWS", category: "cloud", impact: "dev", risk: "low" },
    "awsstatic.com": { service: "AWS Static", category: "cdn", impact: "dev", risk: "low" },
    "cloudfront.net": { service: "CloudFront CDN", category: "cdn", impact: "cdn", risk: "low" },
    "apple.com": { service: "Apple", category: "cloud", impact: "login", risk: "low" },
    "icloud.com": { service: "iCloud", category: "cloud", impact: "login", risk: "low" },
    "microsoft.com": { service: "Microsoft", category: "cloud", impact: "login", risk: "low" },
    "windows.net": { service: "Azure", category: "cloud", impact: "dev", risk: "low" },
    "office.com": { service: "Microsoft 365", category: "cloud", impact: "login", risk: "low" },
    "live.com": { service: "Microsoft Live", category: "cloud", impact: "login", risk: "low" },
    "msn.com": { service: "MSN", category: "news", impact: "news", risk: "low" },
    "bing.com": { service: "Bing", category: "search", impact: "login", risk: "low" },
    "github.com": { service: "GitHub", category: "dev", impact: "dev", risk: "low" },
    "githubusercontent.com": { service: "GitHub Assets", category: "cdn", impact: "dev", risk: "low" },
    "stackoverflow.com": { service: "Stack Overflow", category: "dev", impact: "dev", risk: "low" },
    "cdn.jsdelivr.net": { service: "jsDelivr CDN", category: "cdn", impact: "dev", risk: "low" },
    "unpkg.com": { service: "unpkg CDN", category: "cdn", impact: "dev", risk: "low" },
    "npmjs.org": { service: "npm", category: "dev", impact: "dev", risk: "low" },
    "netflix.com": { service: "Netflix", category: "streaming", impact: "video", risk: "low" },
    "nflxvideo.net": { service: "Netflix Video", category: "cdn", impact: "video", risk: "low" },
    "spotify.com": { service: "Spotify", category: "streaming", impact: "streaming", risk: "low" },
    "spotifycdn.com": { service: "Spotify CDN", category: "cdn", impact: "streaming", risk: "low" },
    "twitch.tv": { service: "Twitch", category: "streaming", impact: "video", risk: "low" },
    "jtvnw.net": { service: "Twitch CDN", category: "cdn", impact: "video", risk: "low" },
    "discord.com": { service: "Discord", category: "chat", impact: "chat", risk: "low" },
    "discordapp.com": { service: "Discord App", category: "chat", impact: "chat", risk: "low" },
    "discordapp.net": { service: "Discord Network", category: "chat", impact: "chat", risk: "low" },
    "slack.com": { service: "Slack", category: "chat", impact: "chat", risk: "low" },
    "whatsapp.com": { service: "WhatsApp", category: "chat", impact: "chat", risk: "low" },
    "zoom.us": { service: "Zoom", category: "chat", impact: "chat", risk: "low" },
    "teams.microsoft.com": { service: "Teams", category: "chat", impact: "chat", risk: "low" },
    "mail.google.com": { service: "Gmail", category: "email", impact: "login", risk: "low" },
    "outlook.com": { service: "Outlook", category: "email", impact: "login", risk: "low" },
    "yahoo.com": { service: "Yahoo", category: "search", impact: "login", risk: "low" },
    "yahooapis.com": { service: "Yahoo APIs", category: "cdn", impact: "login", risk: "low" },
    "reddit.com": { service: "Reddit", category: "social", impact: "login", risk: "low" },
    "redd.it": { service: "Reddit Images", category: "cdn", impact: "social", risk: "low" },
    "redditmedia.com": { service: "Reddit Media", category: "cdn", impact: "social", risk: "low" },
    "tiktok.com": { service: "TikTok", category: "streaming", impact: "video", risk: "low" },
    "tiktokcdn.com": { service: "TikTok CDN", category: "cdn", impact: "video", risk: "low" },
    "pinterest.com": { service: "Pinterest", category: "social", impact: "login", risk: "low" },
    "pinimg.com": { service: "Pinterest Images", category: "cdn", impact: "social", risk: "low" },
    "tumblr.com": { service: "Tumblr", category: "social", impact: "login", risk: "low" },
    "snapchat.com": { service: "Snapchat", category: "social", impact: "login", risk: "low" },
    "maps.google.com": { service: "Google Maps", category: "maps", impact: "maps", risk: "low" },
    "maps.googleapis.com": { service: "Google Maps API", category: "maps", impact: "maps", risk: "low" },
    "stripe.com": { service: "Stripe", category: "payment", impact: "checkout", risk: "low" },
    "js.stripe.com": { service: "Stripe JS", category: "payment", impact: "checkout", risk: "low" },
    "paypal.com": { service: "PayPal", category: "payment", impact: "checkout", risk: "low" },
    "paypalobjects.com": { service: "PayPal CDN", category: "payment", impact: "checkout", risk: "low" },
    "shopify.com": { service: "Shopify", category: "shopping", impact: "checkout", risk: "low" },
    "myshopify.com": { service: "Shopify Store", category: "shopping", impact: "checkout", risk: "low" },
    "shopifycdn.com": { service: "Shopify CDN", category: "cdn", impact: "checkout", risk: "low" },
    "cloudflare.com": { service: "Cloudflare", category: "cdn", impact: "cdn", risk: "low" },
    "cloudflareinsights.com": { service: "Cloudflare Analytics", category: "analytics", impact: "tracking", risk: "low" },
    "fastly.net": { service: "Fastly CDN", category: "cdn", impact: "cdn", risk: "low" },
    "akamai.net": { service: "Akamai CDN", category: "cdn", impact: "cdn", risk: "low" },
    "akamaiedge.net": { service: "Akamai Edge", category: "cdn", impact: "cdn", risk: "low" },
    "doubleclick.net": { service: "DoubleClick Ads", category: "ads", impact: "ads", risk: "medium" },
    "adservice.google.com": { service: "Google Ad Service", category: "ads", impact: "ads", risk: "medium" },
    "adsystem.com": { service: "Ad System", category: "ads", impact: "ads", risk: "medium" },
    "adservice.com": { service: "Ad Service", category: "ads", impact: "ads", risk: "medium" },
    "adnxs.com": { service: "AppNexus Ads", category: "ads", impact: "ads", risk: "medium" },
    "taboola.com": { service: "Taboola", category: "ads", impact: "ads", risk: "medium" },
    "outbrain.com": { service: "Outbrain", category: "ads", impact: "ads", risk: "medium" },
    "scorecardresearch.com": { service: "Scorecard Research", category: "analytics", impact: "tracking", risk: "medium" },
    "quantserve.com": { service: "Quantcast", category: "analytics", impact: "tracking", risk: "medium" },
    "exelator.com": { service: "eXelator", category: "analytics", impact: "tracking", risk: "medium" },
    "2mdn.net": { service: "Doubleclick CDN", category: "ads", impact: "ads", risk: "medium" },
    "3lift.com": { service: "TripleLift", category: "ads", impact: "ads", risk: "medium" },
    "advertising.com": { service: "Advertising.com", category: "ads", impact: "ads", risk: "medium" },
    "adsafeprotected.com": { service: "IAS", category: "ads", impact: "ads", risk: "low" },
    "moatads.com": { service: "Moat Ads", category: "ads", impact: "ads", risk: "medium" },
    "googlesyndication.com": { service: "Google AdSense", category: "ads", impact: "ads", risk: "medium" },
    "ads-twitter.com": { service: "Twitter Ads", category: "ads", impact: "ads", risk: "medium" },
    "ads.linkedin.com": { service: "LinkedIn Ads", category: "ads", impact: "ads", risk: "medium" },
    "connect.facebook.net": { service: "Facebook Connect", category: "social", impact: "login", risk: "low" },
    "pixel.facebook.com": { service: "Facebook Pixel", category: "analytics", impact: "tracking", risk: "medium" },
    "analytics.google.com": { service: "Google Analytics", category: "analytics", impact: "tracking", risk: "medium" },
    "analytics.twitter.com": { service: "Twitter Analytics", category: "analytics", impact: "tracking", risk: "medium" },
    "hotjar.com": { service: "Hotjar", category: "analytics", impact: "tracking", risk: "medium" },
    "hotjar.io": { service: "Hotjar IO", category: "analytics", impact: "tracking", risk: "medium" },
    "mixpanel.com": { service: "Mixpanel", category: "analytics", impact: "tracking", risk: "medium" },
    "segment.com": { service: "Segment", category: "analytics", impact: "tracking", risk: "medium" },
    "amplitude.com": { service: "Amplitude", category: "analytics", impact: "tracking", risk: "medium" },
    "optimizely.com": { service: "Optimizely", category: "analytics", impact: "tracking", risk: "medium" },
    "crazyegg.com": { service: "Crazy Egg", category: "analytics", impact: "tracking", risk: "medium" },
    "newrelic.com": { service: "New Relic", category: "dev", impact: "dev", risk: "low" },
    "sentry.io": { service: "Sentry", category: "dev", impact: "dev", risk: "low" },
    "bugsnag.com": { service: "Bugsnag", category: "dev", impact: "dev", risk: "low" },
    "datadog.com": { service: "Datadog", category: "dev", impact: "dev", risk: "low" },
    "elastic.co": { service: "Elastic", category: "dev", impact: "dev", risk: "low" },
    "grafana.com": { service: "Grafana", category: "dev", impact: "dev", risk: "low" },
    "fonts.googleapis.com": { service: "Google Fonts", category: "cdn", impact: "cdn", risk: "low" },
    "fonts.gstatic.com": { service: "Google Fonts CDN", category: "cdn", impact: "cdn", risk: "low" },
    "ajax.googleapis.com": { service: "Google AJAX CDN", category: "cdn", impact: "dev", risk: "low" },
    "code.jquery.com": { service: "jQuery CDN", category: "cdn", impact: "dev", risk: "low" },
    "maxcdn.bootstrapcdn.com": { service: "Bootstrap CDN", category: "cdn", impact: "dev", risk: "low" },
    "cdnjs.cloudflare.com": { service: "Cloudflare CDNJS", category: "cdn", impact: "dev", risk: "low" },
    "recaptcha.net": { service: "reCAPTCHA", category: "security", impact: "login", risk: "low" },
    "hcaptcha.com": { service: "hCaptcha", category: "security", impact: "login", risk: "low" },
    "turnstile.com": { service: "Cloudflare Turnstile", category: "security", impact: "login", risk: "low" },
    "recaptcha.google.com": { service: "Google reCAPTCHA", category: "security", impact: "login", risk: "low" },
    "grecaptcha.com": { service: "Google reCAPTCHA", category: "security", impact: "login", risk: "low" },
    "auth0.com": { service: "Auth0", category: "security", impact: "login", risk: "low" },
    "okta.com": { service: "Okta", category: "security", impact: "login", risk: "low" },
    "onelogin.com": { service: "OneLogin", category: "security", impact: "login", risk: "low" },
    "duosecurity.com": { service: "Duo Security", category: "security", impact: "login", risk: "low" },
    "2fa.com": { service: "2FA", category: "security", impact: "login", risk: "low" },
    "adblock.turtlecute.org": { service: "Adblock Test", category: "ads", impact: "ads", risk: "low" },
};

const IMPACT_LABELS = {
    login: { label: "LOGIN", color: "impact-login", icon: "\ud83d\udd11" },
    video: { label: "VIDEO", color: "impact-video", icon: "\ud83c\udfac" },
    checkout: { label: "CHECKOUT", color: "impact-checkout", icon: "\ud83d\uded2" },
    maps: { label: "MAPS", color: "impact-maps", icon: "\ud83d\uddfa\ufe0f" },
    chat: { label: "CHAT", color: "impact-chat", icon: "\ud83d\udcac" },
    ads: { label: "ADS", color: "impact-ads", icon: "\ud83d\udce2" },
    tracking: { label: "TRACKING", color: "impact-tracking", icon: "\ud83d\udc41\ufe0f" },
    cdn: { label: "CDN", color: "impact-cdn", icon: "\u26a1" },
    social: { label: "SOCIAL", color: "impact-social", icon: "\ud83d\udc65" },
    dev: { label: "DEV", color: "impact-dev", icon: "\ud83d\udee0\ufe0f" },
    streaming: { label: "STREAM", color: "impact-streaming", icon: "\ud83c\udfb5" },
    news: { label: "NEWS", color: "impact-news", icon: "\ud83d\udcf0" },
    email: { label: "EMAIL", color: "impact-email", icon: "\u2709\ufe0f" },
    gaming: { label: "GAMING", color: "impact-gaming", icon: "\ud83c\udfae" },
    payment: { label: "PAYMENT", color: "impact-payment", icon: "\ud83d\udcb3" },
    security: { label: "SECURITY", color: "impact-security", icon: "\ud83d\udd12" },
};

const IMPACT_SEVERITY = {
    login: "high", video: "high", checkout: "high", maps: "medium",
    chat: "high", ads: "low", tracking: "medium", cdn: "low",
    social: "medium", dev: "low", streaming: "high", news: "low",
    email: "high", gaming: "medium", payment: "high", security: "high",
};

function classifyDomain(domain) {
    if (DOMAIN_CLASSIFICATIONS[domain]) return DOMAIN_CLASSIFICATIONS[domain];
    const parts = domain.split(".");
    for (let i = 1; i < parts.length; i++) {
        const parent = parts.slice(i).join(".");
        if (DOMAIN_CLASSIFICATIONS[parent]) return DOMAIN_CLASSIFICATIONS[parent];
    }
    return null;
}

function getImpactBadge(domain) {
    const cls = classifyDomain(domain);
    if (!cls) return null;
    const impact = IMPACT_LABELS[cls.impact];
    if (!impact) return null;
    return { ...impact, severity: IMPACT_SEVERITY[cls.impact] || "low", category: cls.category, service: cls.service };
}

function renderImpactBadge(impact) {
    if (!impact) return "";
    return `<span class="impact-badge ${impact.color}" title="${impact.service} - ${impact.label}">${impact.icon} ${impact.label}</span>`;
}

// Server fingerprinting database (inspired by PSNET)
// Maps port + protocol combinations to service fingerprints
const SERVICE_FINGERPRINTS = {
    20: { name: "FTP-Data", proto: "TCP", icon: "\ud83d\udcc2", category: "file-transfer", risk: "medium" },
    21: { name: "FTP", proto: "TCP", icon: "\ud83d\udcc2", category: "file-transfer", risk: "medium" },
    22: { name: "SSH", proto: "TCP", icon: "\ud83d\udd12", category: "remote-access", risk: "low" },
    23: { name: "Telnet", proto: "TCP", icon: "\u26a0\ufe0f", category: "remote-access", risk: "high" },
    25: { name: "SMTP", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    53: { name: "DNS", proto: "UDP/TCP", icon: "\ud83c\udf10", category: "dns", risk: "low" },
    67: { name: "DHCP", proto: "UDP", icon: "\ud83d\udd0c", category: "network", risk: "low" },
    68: { name: "DHCP", proto: "UDP", icon: "\ud83d\udd0c", category: "network", risk: "low" },
    80: { name: "HTTP", proto: "TCP", icon: "\ud83c\udf10", category: "web", risk: "low" },
    110: { name: "POP3", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    123: { name: "NTP", proto: "UDP", icon: "\u23f0", category: "time", risk: "low" },
    143: { name: "IMAP", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    161: { name: "SNMP", proto: "UDP", icon: "\ud83d\udcca", category: "monitoring", risk: "medium" },
    389: { name: "LDAP", proto: "TCP", icon: "\ud83d\udc65", category: "directory", risk: "low" },
    443: { name: "HTTPS", proto: "TCP", icon: "\ud83d\udd12", category: "web", risk: "low" },
    445: { name: "SMB", proto: "TCP", icon: "\ud83d\udcc1", category: "file-sharing", risk: "high" },
    465: { name: "SMTPS", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    514: { name: "Syslog", proto: "UDP", icon: "\ud83d\udccb", category: "monitoring", risk: "low" },
    587: { name: "SMTP-Submit", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    636: { name: "LDAPS", proto: "TCP", icon: "\ud83d\udd12", category: "directory", risk: "low" },
    993: { name: "IMAPS", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    995: { name: "POP3S", proto: "TCP", icon: "\u2709\ufe0f", category: "email", risk: "low" },
    1433: { name: "MSSQL", proto: "TCP", icon: "\ud83d\uddc4\ufe0f", category: "database", risk: "high" },
    1434: { name: "MSSQL-Browser", proto: "UDP", icon: "\ud83d\uddc4\ufe0f", category: "database", risk: "high" },
    1521: { name: "Oracle DB", proto: "TCP", icon: "\ud83d\uddc4\ufe0f", category: "database", risk: "high" },
    2049: { name: "NFS", proto: "TCP", icon: "\ud83d\udcc1", category: "file-sharing", risk: "medium" },
    3306: { name: "MySQL", proto: "TCP", icon: "\ud83d\uddc4\ufe0f", category: "database", risk: "high" },
    3389: { name: "RDP", proto: "TCP", icon: "\ud83d\udda5\ufe0f", category: "remote-access", risk: "high" },
    5432: { name: "PostgreSQL", proto: "TCP", icon: "\ud83d\uddc4\ufe0f", category: "database", risk: "high" },
    5900: { name: "VNC", proto: "TCP", icon: "\ud83d\udda5\ufe0f", category: "remote-access", risk: "high" },
    6379: { name: "Redis", proto: "TCP", icon: "\u26a1", category: "database", risk: "high" },
    8080: { name: "HTTP-Proxy", proto: "TCP", icon: "\ud83c\udf10", category: "web", risk: "low" },
    8443: { name: "HTTPS-Alt", proto: "TCP", icon: "\ud83d\udd12", category: "web", risk: "low" },
    8888: { name: "HTTP-Alt", proto: "TCP", icon: "\ud83c\udf10", category: "web", risk: "low" },
    9090: { name: "WebAdmin", proto: "TCP", icon: "\u2699\ufe0f", category: "admin", risk: "medium" },
    11211: { name: "Memcached", proto: "TCP", icon: "\u26a1", category: "cache", risk: "high" },
    27017: { name: "MongoDB", proto: "TCP", icon: "\ud83c\udf43", category: "database", risk: "high" },
    27018: { name: "MongoDB-Shard", proto: "TCP", icon: "\ud83c\udf43", category: "database", risk: "high" },
};

// Well-known service names for common ports (extends diagnostics.rs)
const WELL_KNOWN_SERVICES = {
    20: { name: "FTP-Data", desc: "File Transfer Protocol (Data)" },
    21: { name: "FTP", desc: "File Transfer Protocol (Control)" },
    22: { name: "SSH", desc: "Secure Shell" },
    23: { name: "Telnet", desc: "Telnet Protocol (Unencrypted)" },
    25: { name: "SMTP", desc: "Simple Mail Transfer Protocol" },
    53: { name: "DNS", desc: "Domain Name System" },
    67: { name: "DHCP-Server", desc: "Dynamic Host Configuration Protocol" },
    68: { name: "DHCP-Client", desc: "Dynamic Host Configuration Protocol" },
    80: { name: "HTTP", desc: "Hypertext Transfer Protocol" },
    110: { name: "POP3", desc: "Post Office Protocol v3" },
    123: { name: "NTP", desc: "Network Time Protocol" },
    143: { name: "IMAP", desc: "Internet Message Access Protocol" },
    161: { name: "SNMP", desc: "Simple Network Management Protocol" },
    389: { name: "LDAP", desc: "Lightweight Directory Access Protocol" },
    443: { name: "HTTPS", desc: "HTTP Secure (TLS/SSL)" },
    445: { name: "SMB", desc: "Server Message Block" },
    465: { name: "SMTPS", desc: "SMTP Secure" },
    514: { name: "Syslog", desc: "System Logging Protocol" },
    587: { name: "SMTP-Submission", desc: "Email Submission (STARTTLS)" },
    636: { name: "LDAPS", desc: "LDAP Secure" },
    993: { name: "IMAPS", desc: "IMAP Secure" },
    995: { name: "POP3S", desc: "POP3 Secure" },
    1433: { name: "MSSQL", desc: "Microsoft SQL Server" },
    1434: { name: "MSSQL-Browser", desc: "Microsoft SQL Server Browser" },
    1521: { name: "Oracle", desc: "Oracle Database" },
    2049: { name: "NFS", desc: "Network File System" },
    3306: { name: "MySQL", desc: "MySQL Database" },
    3389: { name: "RDP", desc: "Remote Desktop Protocol" },
    5432: { name: "PostgreSQL", desc: "PostgreSQL Database" },
    5900: { name: "VNC", desc: "Virtual Network Computing" },
    6379: { name: "Redis", desc: "Redis Key-Value Store" },
    8080: { name: "HTTP-Proxy", desc: "HTTP Alternate / Proxy" },
    8443: { name: "HTTPS-Alt", desc: "HTTPS Alternate" },
    9090: { name: "WebAdmin", desc: "Web Administration" },
    11211: { name: "Memcached", desc: "Memcached Cache" },
    27017: { name: "MongoDB", desc: "MongoDB Database" },
};

function getFingerprint(port) {
    return SERVICE_FINGERPRINTS[port] || null;
}

function getServiceName(port) {
    return WELL_KNOWN_SERVICES[port] || null;
}

function renderFingerprintBadge(port) {
    const fp = getFingerprint(port);
    if (!fp) return "";
    const riskColor = fp.risk === "high" ? "fingerprint-high" : fp.risk === "medium" ? "fingerprint-medium" : "fingerprint-low";
    return `<span class="fingerprint-badge ${riskColor}" title="${escapeHtml(fp.name)} (${escapeHtml(fp.proto)})">${fp.icon} ${escapeHtml(fp.name)}</span>`;
}

function enrichConnectionsWithFingerprints(conns) {
    for (const c of conns) {
        const fp = getFingerprint(c.remote_port);
        if (fp) {
            c.fingerprint = fp;
        }
        const svc = getServiceName(c.remote_port);
        if (svc) {
            c.service = svc;
        }
    }
    return conns;
}

async function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_HISTORY)) {
                const store = db.createObjectStore(STORE_HISTORY, { keyPath: "id", autoIncrement: true });
                store.createIndex("timestamp", "timestamp", { unique: false });
                store.createIndex("process", "process_name", { unique: false });
            }
        };
        req.onsuccess = (e) => { dbConnection = e.target.result; dbReady = true; resolve(); };
        req.onerror = (e) => { console.error("IndexedDB open failed:", e.target.error); reject(e.target.error); };
    });
}

async function saveConnectionsToDB(conns) {
    if (!dbReady || !dbConnection) return;
    const tx = dbConnection.transaction(STORE_HISTORY, "readwrite");
    const store = tx.objectStore(STORE_HISTORY);
    const now = Date.now();
    for (const c of conns) {
        store.add({ timestamp: now, ...c });
    }
    tx.oncomplete = async () => {
        const countReq = store.count();
        countReq.onsuccess = async () => {
            if (countReq.result > MAX_DB_HISTORY) {
                const deleteTx = dbConnection.transaction(STORE_HISTORY, "readwrite");
                const deleteStore = deleteTx.objectStore(STORE_HISTORY);
                const idx = deleteStore.index("timestamp");
                const toDelete = countReq.result - MAX_DB_HISTORY;
                let deleted = 0;
                const cursorReq = idx.openCursor();
                cursorReq.onsuccess = (e) => {
                    const cursor = e.target.result;
                    if (cursor && deleted < toDelete) {
                        cursor.delete();
                        deleted++;
                        cursor.continue();
                    }
                };
            }
        };
    };
}

async function loadConnectionsFromDB(limit = 100) {
    if (!dbReady || !dbConnection) return [];
    return new Promise((resolve) => {
        const tx = dbConnection.transaction(STORE_HISTORY, "readonly");
        const store = tx.objectStore(STORE_HISTORY);
        const idx = store.index("timestamp");
        const results = [];
        const cursorReq = idx.openCursor(null, "prev");
        cursorReq.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor && results.length < limit) {
                results.push(cursor.value);
                cursor.continue();
            } else {
                resolve(results.reverse());
            }
        };
        cursorReq.onerror = () => resolve([]);
    });
}

async function clearDB() {
    if (!dbReady || !dbConnection) return;
    const tx = dbConnection.transaction(STORE_HISTORY, "readwrite");
    tx.objectStore(STORE_HISTORY).clear();
}

const DNS_BLOCKLIST_FEEDS = [
    { name: "StevenBlack Unified", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" },
    { name: "OISD Big", url: "https://big.oisd.nl" },
];
const BLOCKLIST_FEEDS = DNS_BLOCKLIST_FEEDS;

const $ = (id) => document.getElementById(id);

function setHTML(el, html) {
    el.textContent = "";
    const prop = "innerHTML";
    el[prop] = html;
}

const statusBadge = $("status-badge");
const searchInput = $("search");
const stateFilterEl = $("state-filter");
const protoFilterEl = $("proto-filter");
const flatBody = $("connections-body");
const groupedView = $("grouped-view");
const showingCount = $("showing-count");
const lastUpdated = $("last-updated");

function stateBadge(state) {
    const s = (state || "").toUpperCase();
    if (s === "ESTABLISHED" || s === "ESTAB") return `<span class="state-badge state-estab">${escapeHtml(s)}</span>`;
    if (s === "LISTEN" || s === "LISTENING") return `<span class="state-badge state-listen">${escapeHtml(s)}</span>`;
    if (s === "CLOSE_WAIT" || s === "CLOSED" || s === "TIME_WAIT") return `<span class="state-badge state-close">${escapeHtml(s)}</span>`;
    return `<span class="state-badge state-other">${escapeHtml(s)}</span>`;
}

function riskBadge(level) {
    const l = (level || "unknown").toLowerCase();
    const labels = { safe: "SAFE", low: "LOW", medium: "MED", high: "HIGH", critical: "CRIT", unknown: "??" };
    const label = labels[l] || l.toUpperCase();
    return `<span class="risk-badge risk-${escapeHtml(l)}">${escapeHtml(label)}</span>`;
}

function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function csvEscape(val) {
    if (val == null) return "";
    const s = String(val);
    if (s.includes(",") || s.includes('"') || s.includes("\n")) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

// Advanced filter parser: port:443 process:firefox state:ESTABLISHED risk:high ip:192.168
function parseAdvancedFilter(query) {
    const rules = [];
    const freeText = [];
    const tokenRe = /(\w+):(\S+)/g;
    let match;
    let lastIdx = 0;
    while ((match = tokenRe.exec(query)) !== null) {
        if (match.index > lastIdx) {
            const free = query.slice(lastIdx, match.index).trim();
            if (free) freeText.push(free);
        }
        const key = match[1].toLowerCase();
        const val = match[2].toLowerCase();
        rules.push({ key, val });
        lastIdx = match.index + match[0].length;
    }
    const remaining = query.slice(lastIdx).trim();
    if (remaining) freeText.push(remaining);
    return { rules, freeText: freeText.join(" ") };
}

function matchesFilter(conn, rules, freeText) {
    for (const rule of rules) {
        switch (rule.key) {
            case "port":
            case "dport":
                if (!String(conn.remote_port).includes(rule.val)) return false;
                break;
            case "sport":
                if (!String(conn.local_port).includes(rule.val)) return false;
                break;
            case "process":
            case "proc":
                if (!(conn.process_name || "").toLowerCase().includes(rule.val)) return false;
                break;
            case "state":
                if (!conn.state.toUpperCase().includes(rule.val.toUpperCase())) return false;
                break;
            case "risk":
                if (!(conn.risk_level || "").toLowerCase().includes(rule.val)) return false;
                break;
            case "ip":
            case "remote":
            case "dst":
                if (!conn.remote_ip || !conn.remote_ip.includes(rule.val)) return false;
                break;
            case "local":
            case "src":
                if (!conn.local_ip || !conn.local_ip.includes(rule.val)) return false;
                break;
            case "proto":
                if (!conn.protocol.toLowerCase().includes(rule.val)) return false;
                break;
            case "asn":
                if (!(conn.asn || "").toLowerCase().includes(rule.val)) return false;
                break;
            case "fingerprint":
            case "fp":
                if (!conn.fingerprint || !conn.fingerprint.name.toLowerCase().includes(rule.val)) return false;
                break;
            case "service":
            case "svc":
                if (!conn.service || !conn.service.name.toLowerCase().includes(rule.val)) return false;
                break;
            case "category":
            case "cat":
                if (!conn.fingerprint || !conn.fingerprint.category.toLowerCase().includes(rule.val)) return false;
                break;
            default:
                return false;
        }
    }
    if (freeText) {
        const t = `${conn.remote_ip} ${conn.local_ip} ${conn.process_name || ""} ${conn.state}`.toLowerCase();
        if (!t.includes(freeText.toLowerCase())) return false;
    }
    return true;
}

function applyFilters() {
    const q = searchInput.value.toLowerCase().trim();
    const proto = protoFilterEl.value;
    const state = stateFilterEl.value;
    const { rules, freeText } = parseAdvancedFilter(q);
    const hasAdvanced = rules.length > 0;

    filteredConnections = connections.filter((c) => {
        if (proto !== "all" && c.protocol !== proto) return false;
        if (state !== "all" && !c.state.toUpperCase().includes(state)) return false;
        if (hasAdvanced) {
            if (!matchesFilter(c, rules, freeText)) return false;
        } else if (q) {
            const t = `${c.remote_ip} ${c.local_ip} ${c.process_name || ""} ${c.state}`.toLowerCase();
            if (!t.includes(q)) return false;
        }
        return true;
    });
    filteredConnections.sort((a, b) => {
        const aB = blocklist.has(a.remote_ip) || autoBlocklistIps.has(a.remote_ip);
        const bB = blocklist.has(b.remote_ip) || autoBlocklistIps.has(b.remote_ip);
        if (aB && !bB) return -1;
        if (!aB && bB) return 1;
        if (favorites.has(a.remote_ip) && !favorites.has(b.remote_ip)) return -1;
        if (!favorites.has(a.remote_ip) && favorites.has(b.remote_ip)) return 1;
        if (sortKey) {
            let va = (a[sortKey] || "").toString().toLowerCase();
            let vb = (b[sortKey] || "").toString().toLowerCase();
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
        }
        return 0;
    });
    render();
    updateStats();
    updateFilterIndicator(hasAdvanced ? rules.length : 0);
}

function updateFilterIndicator(ruleCount) {
    let el = $("filter-indicator");
    if (!el) {
        el = document.createElement("span");
        el.id = "filter-indicator";
        el.className = "filter-indicator";
        searchInput.parentNode.appendChild(el);
    }
    if (ruleCount > 0) {
        el.textContent = `${ruleCount} filter${ruleCount > 1 ? "s" : ""}`;
        el.style.display = "inline";
    } else {
        el.style.display = "none";
    }
}

function updateStats() {
    const estab = connections.filter((c) => c.state.toUpperCase().includes("ESTAB")).length;
    $("stat-total-val").textContent = connections.length;
    $("stat-estab-val").textContent = estab;
    if (dnsStats) {
        $("stat-dns-queries-val").textContent = dnsStats.totalQueries.toLocaleString();
        $("stat-dns-blocked-val").textContent = dnsStats.blockedCount.toLocaleString();
        $("stat-domains-val").textContent = dnsStats.uniqueDomains.toLocaleString();
    }
    showingCount.textContent = `${filteredConnections.length} of ${connections.length}`;
}

function render() {
    const wasDetail = expandedDetailRow && expandedDetailData;
    if (currentView === "dns") { renderStream(); }
    else if (currentView === "querylog") { renderQueryLogTable(); }
    else if (currentView === "history") { renderHistory(); }
    else if (currentView === "favorites") { renderFavoritesView(); }
    else if (currentView === "blocked") { renderBlockedView(); }
    else if (currentView === "alerts") { renderAlerts(); }
    else if (currentView === "topology") { Topology.update(); }
    else { renderGrouped(); }
    if (wasDetail && expandedDetailRow) restoreDetailRow();
}

let dbSaveCounter = 0;

async function fetchConnections() {
    try {
        const data = await browser.runtime.sendMessage({ action: "get_connections" });
        if (data.type === "connections") {
            connectAttempts = 0;
            const newConns = data.data || [];
            const newSet = new Set(newConns.map((c) => c.id || `${c.remote_ip}:${c.remote_port}:${c.protocol}`));
            const oldSet = previousConnections;

            previousConnections = newSet;
            connections = newConns.map((c) => {
                const key = c.id || `${c.remote_ip}:${c.remote_port}:${c.protocol}`;
                c.isNew = !oldSet.has(key);
                c.isClosed = false;
                return c;
            });
            enrichConnectionsWithFingerprints(connections);

            statusBadge.textContent = "Connected";
            statusBadge.className = "badge-online";
            statusBadge.style.color = "";
            lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
            saveHistorySnapshot();
            checkAlerts(connections);
            detectNetwork();

            dbSaveCounter++;
            if (dbSaveCounter % 5 === 0 && connections.length) {
                saveConnectionsToDB(connections);
            }

            applyFilters();
        }
    } catch (e) {
        connectAttempts++;
        if (connectAttempts <= 5) {
            statusBadge.textContent = "Connecting...";
            statusBadge.className = "badge-offline";
            lastUpdated.textContent = "Establishing connection...";
        } else {
            statusBadge.textContent = "Disconnected";
            statusBadge.className = "badge-offline";
            lastUpdated.textContent = "Connection lost";
        }
    }
}

function renderGrouped() {
    const groups = {};
    for (const c of filteredConnections) { const k = c.process_name || "unknown"; (groups[k] = groups[k] || []).push(c); }
    const sorted = Object.entries(groups).sort((a, b) => { if (a[0] === "unknown") return 1; if (b[0] === "unknown") return -1; return b[1].length - a[1].length; });
    let html = "";
    for (const [name, conns] of sorted) {
        const expanded = expandedGroups.has(name);
        html += `<div class="group-header ${expanded ? '' : 'collapsed'}" data-group="${escapeHtml(name)}"><svg class="expand-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg><span class="group-name">${escapeHtml(name)}</span><span class="group-count">${conns.length}</span></div>`;
        html += `<div class="group-connections ${expanded ? '' : 'collapsed'}" data-group="${escapeHtml(name)}"><table><thead><tr><th style="width:40px">Proto</th><th style="width:80px">Service</th><th style="width:140px">Local</th><th style="width:160px">Remote</th><th style="width:55px">Risk</th><th>State</th></tr></thead><tbody>`;
        for (const c of conns) {
            const remote = c.remote_ip === "0.0.0.0" ? "*:*" : `${c.remote_ip}:${c.remote_port}`;
            const local = `${c.local_ip}:${c.local_port}`;
            const isFav = favorites.has(c.remote_ip);
            const isBlocked = blocklist.has(c.remote_ip) || autoBlocklistIps.has(c.remote_ip);
            let cls = "";
            if (isBlocked) cls = "row-blocked";
            else if (isFav) cls = "row-favorite";
            if (c.isNew) cls = cls ? cls + " row-new" : "row-new";
            html += `<tr class="${cls}"><td style="width:40px">${escapeHtml(c.protocol)}</td><td style="width:80px">${renderFingerprintBadge(c.remote_port)}</td><td style="width:140px">${escapeHtml(local)}</td><td style="width:160px">${isFav ? "\u2b50 " : ""}${escapeHtml(remote)}</td><td style="width:55px">${riskBadge(c.risk_level)}</td><td>${stateBadge(c.state)}</td></tr>`;
        }
        html += `</tbody></table></div>`;
    }
    if (!sorted.length) html = `<div class="empty-state"><p>No connections match your filter</p></div>`;
    setHTML(groupedView, html);
    groupedView.querySelectorAll(".group-header").forEach((h) => {
        h.addEventListener("click", () => {
            const n = h.dataset.group;
            const b = groupedView.querySelector(`.group-connections[data-group="${n}"]`);
            if (expandedGroups.has(n)) { expandedGroups.delete(n); h.classList.add("collapsed"); b.classList.add("collapsed"); }
            else { expandedGroups.add(n); h.classList.remove("collapsed"); b.classList.remove("collapsed"); }
        });
    });
    attachRowClickHandlers();
    attachContextMenu();
}

function renderFavoritesView() {
    const el = $("favorites-body");

    const favIPs = new Set();
    const favDomains = new Set();
    for (const f of favorites) {
        if (f.includes(".")) favDomains.add(f);
        else favIPs.add(f);
    }

    const agg = {};
    for (const c of connections) {
        const key = c.remote_ip !== "0.0.0.0" ? c.remote_ip : c.domain;
        if (!key || key === "0.0.0.0" || key === "127.0.0.1") continue;
        const isFav = favorites.has(c.remote_ip) || favorites.has(c.domain);
        if (!isFav) continue;
        if (!agg[key]) {
            agg[key] = { remote_ip: c.remote_ip, domain: c.domain, ports: new Set(), sources: new Set(), risk_level: c.risk_level, state: c.state, requestCount: 0 };
        }
        agg[key].requestCount += c.requestCount || 1;
        if (c.remote_port) agg[key].ports.add(c.remote_port);
        if (c.process_name) agg[key].sources.add(c.process_name);
        if (c.state && c.state !== "CLOSE_WAIT") agg[key].state = c.state;
    }

    for (const ip of favIPs) {
        if (!agg[ip]) {
            agg[ip] = { remote_ip: ip, domain: "", ports: new Set(), sources: new Set(), risk_level: null, state: null, requestCount: 0 };
        }
    }

    let rows = "";
    for (const [key, a] of Object.entries(agg)) {
        const portStr = [...a.ports].sort((x, y) => x - y).slice(0, 3).join(", ") + (a.ports.size > 3 ? "..." : "");
        const sourceStr = [...a.sources].slice(0, 2).join(", ") + (a.sources.size > 2 ? "..." : "");
        const display = a.domain || a.remote_ip;
        const remote = a.domain ? `${a.remote_ip}:${portStr || "?"}` : `${a.remote_ip}:${portStr || "*"}`;
        const reqs = a.requestCount || 1;
        rows += `<tr data-fav="${escapeHtml(a.remote_ip)}" data-domain="${escapeHtml(a.domain || "")}">
            <td>⭐ ${escapeHtml(display)}</td>
            <td>${escapeHtml(a.domain || "-")}</td>
            <td>${portStr || "-"}</td>
            <td>${sourceStr ? escapeHtml(sourceStr) : "-"}</td>
            <td>${a.risk_level ? riskBadge(a.risk_level) : riskBadge("unknown")}</td>
            <td>${a.state ? stateBadge(a.state) : "-"}</td>
            <td>${reqs}</td>
        </tr>`;
    }

    for (const d of favDomains) {
        if (!agg[d]) {
            rows += `<tr class="row-favorite" data-fav-domain="${escapeHtml(d)}">
                <td>⭐ ${escapeHtml(d)}</td>
                <td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td>
            </tr>`;
        }
    }

    if (!rows) {
        setHTML(el, `<tr><td colspan="8" class="empty-state"><p>No favorites. Right-click an IP or domain in Connections to favorite.</p></td></tr>`);
        return;
    }

    setHTML(el, rows);
    attachContextMenuToFavBlocked();
}

function renderBlockedView() {
    const el = $("blocked-body");
    const blConns = connections.filter((c) => blocklist.has(c.remote_ip) || blocklist.has(c.domain));
    const blDomains = [...blocklist].filter((f) => f.includes("."));
    const blIPs = [...blocklist].filter((f) => !f.includes("."));

    if (!blConns.length && !blDomains.length) {
        setHTML(el, `<tr><td colspan="7" class="empty-state"><p>No blocked connections. Right-click an IP or domain in Connections to block.</p></td></tr>`);
        return;
    }

    let rows = "";
    for (const c of blConns) {
        const remote = c.remote_ip === "0.0.0.0" ? c.domain : `${c.remote_ip}:${c.remote_port}`;
        const isNew = c.isNew ? "row-new" : "";
        const source = c.process_name || (c.tab_id ? `Tab ${c.tab_id}` : "-");
        rows += `<tr class="row-blocked ${isNew}" data-block="${escapeHtml(c.remote_ip)}" data-domain="${escapeHtml(c.domain || "")}">
            <td>🚫 ${escapeHtml(remote)}</td>
            <td>${escapeHtml(c.domain || "-")}</td>
            <td>${c.remote_port || "-"}</td>
            <td>${escapeHtml(source)}</td>
            <td>${riskBadge(c.risk_level)}</td>
            <td>${stateBadge(c.state)}</td>
            <td>${c.requestCount || 1}</td>
        </tr>`;
    }

    for (const d of blDomains) {
        const domainConns = connections.filter((c) => c.domain === d);
        if (domainConns.length === 0) {
            rows += `<tr class="row-blocked" data-block-domain="${escapeHtml(d)}">
                <td>🚫 ${escapeHtml(d)}</td>
                <td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td>
            </tr>`;
        }
    }

    if (!rows) {
        setHTML(el, `<tr><td colspan="8" class="empty-state"><p>No blocked connections. Right-click an IP or domain in Connections to block.</p></td></tr>`);
        return;
    }

    setHTML(el, rows);
    attachContextMenuToFavBlocked();
}

function attachContextMenuToFavBlocked() {
    document.querySelectorAll("#favorites-body tr[data-fav], #favorites-body tr[data-fav-domain], #blocked-body tr[data-block], #blocked-body tr[data-block-domain]").forEach((row) => {
        row.addEventListener("contextmenu", (e) => {
            e.preventDefault();
            const ip = row.dataset.fav || row.dataset.block || "";
            const domain = row.dataset.domain || "";
            const target = ip || domain;
            if (!target) return;

            const ex = document.getElementById("ctx-menu");
            if (ex) ex.remove();

            const isFav = favorites.has(ip) || favorites.has(domain);
            const isBl = blocklist.has(ip) || blocklist.has(domain);

            const menu = document.createElement("div");
            menu.id = "ctx-menu";
            menu.className = "ctx-menu";
            setHTML(menu, `
                <div class="ctx-item" data-action="copy">📋 Copy ${escapeHtml(target)}</div>
                <div class="ctx-item" data-action="fav">${isFav ? "⭐ Unfavorite" : "☆ Favorite"} ${escapeHtml(target)}</div>
                <div class="ctx-item" data-action="block">${isBl ? "🚫 Unblock" : "🛑 Block"} ${escapeHtml(target)}</div>
            `);
            document.body.appendChild(menu);
            menu.style.top = `${e.clientY}px`;
            menu.style.left = `${Math.min(e.clientX, window.innerWidth - 180)}px`;
            menu.querySelectorAll(".ctx-item").forEach((item) => {
                item.addEventListener("click", () => {
                    const a = item.dataset.action;
                    if (a === "copy") copyToClipboard(target);
                    else if (a === "fav") {
                        if (ip) toggleFavorite(ip);
                        if (domain) toggleFavorite(domain);
                    }
                    else if (a === "block") {
                        if (ip) toggleBlocklist(ip);
                        if (domain) toggleBlocklist(domain);
                    }
                    menu.remove();
                });
            });
            setTimeout(() => {
                const cl = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener("mousedown", cl); } };
                document.addEventListener("mousedown", cl);
            }, 10);
        });
    });
}

function renderAlerts() {
    const el = $("alerts-body");
    const sevFilter = $("alerts-severity-filter")?.value || "all";
    let f = alerts;
    if (sevFilter === "high") f = f.filter((a) => a.severity === "high" || a.severity === "critical");
    else if (sevFilter === "medium") f = f.filter((a) => a.severity === "medium");

    if (!f.length) {
        setHTML(el, `<div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><p>No security alerts</p><p class="empty-state-sub">Alerts appear when new connections match risk rules</p></div>`);
        return;
    }

    const icons = { risk: "⚠️", port: "⚡", exposed: "🔓", blocked: "🚫", domain: "🌐", tracker: "👁️" };
    setHTML(el, f.slice(0, 100).map((a, i) => {
        const t = new Date(a.time).toLocaleTimeString();
        const icon = icons[a.type] || "❗";
        const sevClass = a.severity === "high" || a.severity === "critical" ? "high" : a.severity === "medium" ? "medium" : "low";
        return `<div class="alert-item" data-alert-idx="${i}" data-alert-ip="${escapeHtml(a.ip || "")}" data-alert-domain="${escapeHtml(a.domain || "")}">
            <div class="alert-icon ${sevClass}">${icon}</div>
            <div class="alert-content">
                <div class="alert-message">${escapeHtml(a.message)}<span class="alert-type-badge">${a.type}</span></div>
                <div class="alert-time">${t}${a.domain ? ` • ${escapeHtml(a.domain)}` : ""}</div>
            </div>
        </div>`;
    }).join(""));

    el.querySelectorAll(".alert-item").forEach((item) => {
        item.addEventListener("click", (e) => {
            if (e.target.closest(".alert-action")) return;
            const ip = item.dataset.alertIp || "";
            const domain = item.dataset.alertDomain || "";
            const ex = document.getElementById("ctx-menu");
            if (ex) ex.remove();

            const menu = document.createElement("div");
            menu.id = "ctx-menu";
            menu.className = "ctx-menu";
            let items = "";
            if (ip) items += `<div class="ctx-item" data-action="copy-ip">📋 Copy IP: ${escapeHtml(ip)}</div>`;
            if (domain) items += `<div class="ctx-item" data-action="copy-domain">📋 Copy Domain: ${escapeHtml(domain)}</div>`;
            if (ip) items += `<div class="ctx-item" data-action="block-ip">🛑 Block ${escapeHtml(ip)}</div>`;
            if (domain) items += `<div class="ctx-item" data-action="block-domain">🛑 Block ${escapeHtml(domain)}</div>`;
            if (ip) items += `<div class="ctx-item" data-action="fav-ip">⭐ Favorite ${escapeHtml(ip)}</div>`;
            if (domain) items += `<div class="ctx-item" data-action="fav-domain">⭐ Favorite ${escapeHtml(domain)}</div>`;
            setHTML(menu, items);
            document.body.appendChild(menu);
            menu.style.top = `${e.clientY}px`;
            menu.style.left = `${Math.min(e.clientX, window.innerWidth - 200)}px`;

            menu.querySelectorAll(".ctx-item").forEach((mi) => {
                mi.addEventListener("click", () => {
                    const a = mi.dataset.action;
                    if (a === "copy-ip") copyToClipboard(ip);
                    else if (a === "copy-domain") copyToClipboard(domain);
                    else if (a === "block-ip") toggleBlocklist(ip);
                    else if (a === "block-domain") toggleBlocklist(domain);
                    else if (a === "fav-ip") toggleFavorite(ip);
                    else if (a === "fav-domain") toggleFavorite(domain);
                    menu.remove();
                });
            });
            setTimeout(() => {
                const cl = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener("mousedown", cl); } };
                document.addEventListener("mousedown", cl);
            }, 10);
        });
    });
}

$("alerts-severity-filter").addEventListener("change", () => renderAlerts());
$("alerts-clear-btn").addEventListener("click", () => { if (confirm("Clear all alerts?")) { alerts = []; alertCount = 0; renderAlerts(); } });

function saveHistorySnapshot() {
    const estab = connections.filter((c) => c.state.toUpperCase().includes("ESTAB")).length;
    const listen = connections.filter((c) => c.state.toUpperCase().includes("LISTEN")).length;
    const highRisk = connections.filter((c) => ["high", "critical"].includes((c.risk_level || "").toLowerCase())).length;
    const domains = new Set(connections.map((c) => c.domain).filter(Boolean)).size;
    const blocked = connections.filter((c) => c.blocked).length;
    historySnapshots.push({ time: Date.now(), total: connections.length, estab, listen, highRisk, domains, blocked });
    if (historySnapshots.length > MAX_HISTORY) historySnapshots = historySnapshots.slice(-MAX_HISTORY);
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(historySnapshots)); } catch (e) { if (historySnapshots.length > 50) { historySnapshots = historySnapshots.slice(-50); localStorage.setItem(HISTORY_KEY, JSON.stringify(historySnapshots)); } }
}

function loadHistory() { try { const s = localStorage.getItem(HISTORY_KEY); if (s) historySnapshots = JSON.parse(s); } catch (e) { historySnapshots = []; } }

function renderHistory() {
    const chartEl = $("history-chart");
    const bodyEl = $("history-body");
    if (!historySnapshots.length) {
        setHTML(chartEl, `<div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><p>No history yet</p><p class="empty-state-sub">Browse the web to build connection history</p></div>`);
        setHTML(bodyEl, `<tr><td colspan="6" class="empty-state"><p>History snapshots will appear here</p></td></tr>`);
        return;
    }

    const maxT = Math.max(...historySnapshots.map((s) => s.total), 1);
    setHTML(chartEl, `<div class="history-bars">` + historySnapshots.map((s) => {
        const h = Math.max(4, Math.floor((s.total / maxT) * 120));
        const rh = Math.max(2, Math.floor((s.highRisk / maxT) * 120));
        const t = new Date(s.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        return `<div class="history-bar-wrapper" title="${t}: ${s.total} conns, ${s.domains || 0} domains, ${s.highRisk} high risk">
            <div class="history-bar" style="height:${h}px"></div>
            <div class="history-bar-risk" style="height:${rh}px"></div>
            <span class="history-bar-label">${s.total}</span>
        </div>`;
    }).join("") + `</div>`);

    setHTML(bodyEl, [...historySnapshots].reverse().slice(0, 100).map((s) => {
        const t = new Date(s.time).toLocaleTimeString();
        return `<tr><td>${t}</td><td class="h-total">${s.total}</td><td class="h-estab">${s.estab}</td><td class="h-listen">${s.listen}</td><td class="h-risk">${s.highRisk}</td><td>${s.domains || 0}</td></tr>`;
    }).join(""));
}

// DNS Monitor - polling
let lastLogCount = 0;
let pollCount = 0;
let dnsPollingActive = true;
let dnsPollTimer = null;

function startDnsPolling() {
    if (dnsPollTimer) clearInterval(dnsPollTimer);
    dnsPollingActive = true;
    $("dns-live-toggle").classList.add("active");
    $("dns-live-text").textContent = "Live: ON";
    dnsPollTimer = setInterval(async () => {
        if (!dnsPollingActive) return;
        pollCount++;
        try {
            const stats = await browser.runtime.sendMessage({ action: "get_stats" });
            if (!stats) return;
            dnsStats = stats;

            // Stream: fetch recent entries for live view
            const streamLog = await browser.runtime.sendMessage({ action: "get_query_log", start: 0, limit: 100 });
            const streamCount = (streamLog && streamLog.total) || 0;

            // Stats cards
            $("dns-total-queries").textContent = stats.totalQueries.toLocaleString();
            $("dns-blocked").textContent = stats.blockedCount.toLocaleString();
            $("dns-blocked-pct").textContent = stats.blockedPct + "%";
            $("dns-unique").textContent = stats.uniqueDomains.toLocaleString();
            $("dns-avg-time").textContent = stats.avgResolveTime + "ms";
            $("dns-rules").textContent = stats.domainCount.toLocaleString();
            $("stat-dns-queries-val").textContent = stats.totalQueries.toLocaleString();
            $("stat-dns-blocked-val").textContent = stats.blockedCount.toLocaleString();
            $("stat-domains-val").textContent = stats.uniqueDomains.toLocaleString();

            // Status
            const dot = $("dns-status-dot");
            const txt = $("dns-status-text");
            const btn = $("dns-toggle-btn");
            if (stats.filteringEnabled) { dot.className = "status-dot online"; txt.textContent = "DNS Filtering Active"; btn.className = "btn-dns enabled"; btn.textContent = "Disable"; }
            else { dot.className = "status-dot offline"; txt.textContent = "DNS Filtering Disabled"; btn.className = "btn-dns disabled"; btn.textContent = "Enable"; }

            // Stream: only update when new entries exist
            if (streamLog && streamLog.queries && streamCount !== lastLogCount) {
                for (const e of streamLog.queries) { if (!streamEntries.find((x) => x.time === e.time && x.domain === e.domain)) streamEntries.unshift(e); }
                if (streamEntries.length > MAX_STREAM) streamEntries.length = MAX_STREAM;
                lastLogCount = streamCount;
                renderStream();
            }

            // Query Log view: fetch full dataset when active
            if (currentView === "querylog") {
                const fullLog = await browser.runtime.sendMessage({ action: "get_query_log", start: 0, limit: 10000 });
                if (fullLog && fullLog.queries) { queryLogData = fullLog.queries; renderQueryLogTable(); }
            }

            // Dashboard sections
            if (currentView === "dns") renderDnsSections(stats);
        } catch (e) {
            if (pollCount <= 3) console.error("DNS poll error:", e.message);
        }
    }, 500);
}

function toggleDnsLive() {
    dnsPollingActive = !dnsPollingActive;
    const btn = $("dns-live-toggle");
    const txt = $("dns-live-text");
    if (dnsPollingActive) {
        btn.classList.add("active");
        txt.textContent = "Live: ON";
    } else {
        btn.classList.remove("active");
        txt.textContent = "Live: OFF";
    }
}

function renderDnsSections(stats) {
    const qt = $("dns-query-types");
    if (qt) {
        if (stats.queryTypes && stats.queryTypes.length) {
            const mx = Math.max(...stats.queryTypes.map((q) => q.count), 1);
            setHTML(qt, stats.queryTypes.map((q) => `<div class="query-type-item"><span class="query-type-name">${escapeHtml(q.type)}</span><div class="query-type-bar-bg"><div class="query-type-bar" style="width:${(q.count / mx) * 100}%"></div></div><span class="query-type-count">${q.count}</span></div>`).join(""));
        } else {
            setHTML(qt, `<div class="query-type-item" style="justify-content:center;color:var(--text-dim)">No request types yet</div>`);
        }
    }

    // Impact severity breakdown
    const impactCounts = { high: 0, medium: 0, low: 0 };
    const impactServices = {};
    for (const q of streamEntries) {
        const impact = getImpactBadge(q.domain);
        if (impact) {
            impactCounts[impact.severity] = (impactCounts[impact.severity] || 0) + 1;
            const key = `${impact.service} (${impact.label})`;
            impactServices[key] = (impactServices[key] || 0) + 1;
        }
    }
    const is = $("dns-impact-severity");
    if (is) {
        setHTML(is, [
            { sev: "high", label: "High Impact", count: impactCounts.high, color: "impact-severity-high" },
            { sev: "medium", label: "Medium Impact", count: impactCounts.medium, color: "impact-severity-medium" },
            { sev: "low", label: "Low Impact", count: impactCounts.low, color: "impact-severity-low" },
        ].map((s) => `<div class="impact-severity-item ${s.color}"><span class="impact-severity-label">${s.label}</span><span class="impact-severity-count">${s.count}</span></div>`).join(""));
    }

    const tb = $("dns-top-blocked");
    if (tb) {
        if (stats.topBlocked.length) setHTML(tb, stats.topBlocked.map((d) => {
            const impact = getImpactBadge(d.domain);
            const impactHtml = impact ? `<span class="impact-badge-mini ${impact.color}" title="${impact.service}">${impact.icon}</span>` : "";
            return `<div class="dns-domain-item"><span class="dns-domain-name" title="${escapeHtml(d.domain)}">${impactHtml} ${escapeHtml(d.domain)}</span><span class="dns-domain-count">${d.count}</span></div>`;
        }).join(""));
        else setHTML(tb, `<div class="dns-domain-item" style="justify-content:center;color:var(--text-dim)">No blocked domains yet</div>`);
    }
    const ta = $("dns-top-allowed");
    if (ta) {
        if (stats.topAllowed.length) setHTML(ta, stats.topAllowed.map((d) => {
            const impact = getImpactBadge(d.domain);
            const impactHtml = impact ? `<span class="impact-badge-mini ${impact.color}" title="${impact.service}">${impact.icon}</span>` : "";
            return `<div class="dns-domain-item"><span class="dns-domain-name" title="${escapeHtml(d.domain)}">${impactHtml} ${escapeHtml(d.domain)}</span><span class="dns-domain-count">${d.count}</span></div>`;
        }).join(""));
        else setHTML(ta, `<div class="dns-domain-item" style="justify-content:center;color:var(--text-dim)">No allowed domains yet</div>`);
    }
    const cl = $("dns-clients");
    if (cl) {
        if (stats.clients.length) setHTML(cl, stats.clients.map((c) => `<div class="dns-domain-item"><span class="dns-domain-name" title="${escapeHtml(c.client)}">${escapeHtml(c.client)}</span><span class="dns-domain-count">${c.count}</span></div>`).join(""));
        else setHTML(cl, `<div class="dns-domain-item" style="justify-content:center;color:var(--text-dim)">No tab data yet</div>`);
    }

    // Time chart
    browser.runtime.sendMessage({ action: "get_query_log", start: 0, limit: 200 }).then((log) => {
        if (!log || !log.queries || !log.queries.length) return;
        const recent = log.queries;
        const bs = Math.max(1, Math.floor(recent.length / 20));
        const buckets = [];
        for (let i = 0; i < 20; i++) { const sl = recent.slice(i * bs, i * bs + bs); buckets.push({ blocked: sl.filter((q) => q.blocked).length, allowed: sl.length - sl.filter((q) => q.blocked).length, total: sl.length }); }
        const mx = Math.max(...buckets.map((b) => b.total), 1);
        setHTML($("dns-time-chart"), buckets.map((b) => {
            const ah = Math.max(2, Math.floor((b.allowed / mx) * 60));
            const bh = b.blocked > 0 ? Math.max(1, Math.floor((b.blocked / mx) * 60)) : 0;
            return `<div class="time-bar-wrapper" title="${b.total} queries"><div class="time-bar-blocked" style="height:${bh}px"></div><div class="time-bar-allowed" style="height:${ah}px"></div><span class="time-bar-label">${b.total}</span></div>`;
        }).join(""));
    }).catch(() => {});
}

function renderStream() {
    const el = $("dns-query-stream");
    let f = filterStreamByTab(streamEntries);
    if (streamFilter === "blocked") f = f.filter((e) => e.blocked);
    else if (streamFilter === "allowed") f = f.filter((e) => !e.blocked);
    if (!f.length) { setHTML(el, `<div class="empty-state" style="padding:20px"><p>No queries captured yet. Browse the web to see DNS activity.</p></div>`); return; }
    setHTML(el, f.slice(0, 100).map((e) => {
        const t = new Date(e.time).toLocaleTimeString();
        const sc = e.blocked ? "blocked" : "allowed";
        const st = e.blocked ? "BLOCKED" : "OK";
        const ips = (e.resolvedIps && e.resolvedIps.length) ? e.resolvedIps.slice(0, 2).join(", ") : "";
        const rt = e.resolveTime > 0 ? e.resolveTime + "ms" : e.cached ? "cache" : "";
        const rc = e.resolveTime > 0 ? (e.resolveTime < 50 ? "fast" : e.resolveTime < 200 ? "medium" : "slow") : "";
        const impact = getImpactBadge(e.domain);
        const impactHtml = impact ? `<span class="impact-badge ${impact.color}" title="${impact.service}">${impact.icon} ${impact.label}</span>` : "";
        return `<div class="stream-entry ${sc}"><span class="stream-time">${t}</span><span class="stream-type">${escapeHtml(e.type)}</span><span class="stream-domain" title="${escapeHtml(e.domain)}">${escapeHtml(e.domain)}</span>${impactHtml}${ips ? `<span class="stream-ips">${escapeHtml(ips)}</span>` : ""}${rt ? `<span class="stream-resolve ${rc}">${rt}</span>` : ""}<span class="stream-status ${sc}">${st}</span></div>`;
    }).join(""));
}

$("stream-filter").addEventListener("change", (e) => { streamFilter = e.target.value; renderStream(); });
$("dns-tab-filter").addEventListener("change", (e) => { streamTabFilter = e.target.value; renderStream(); });

// Stream resize handle
const streamResizeHandle = $("stream-resize-handle");
const streamContainer = $("dns-query-stream");
if (streamResizeHandle && streamContainer) {
    let isResizing = false;
    let startY = 0;
    let startHeight = 0;

    streamResizeHandle.addEventListener("mousedown", (e) => {
        isResizing = true;
        startY = e.clientY;
        startHeight = streamContainer.offsetHeight;
        document.body.style.cursor = "ns-resize";
        document.body.style.userSelect = "none";
        e.preventDefault();
    });

    document.addEventListener("mousemove", (e) => {
        if (!isResizing) return;
        const delta = e.clientY - startY;
        const newHeight = Math.max(60, Math.min(500, startHeight + delta));
        streamContainer.style.height = newHeight + "px";
    });

    document.addEventListener("mouseup", () => {
        if (isResizing) {
            isResizing = false;
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
        }
    });
}

$("dns-toggle-btn").addEventListener("click", () => {
    const n = !dnsStats?.filteringEnabled;
    dnsFilteringEnabled = n;
    dnsFilteringToggle.checked = n;
    saveSettings();
    if (n) updateDnsFiltering();
    else browser.runtime.sendMessage({ action: "set_filtering", enabled: false });
});

$("dns-live-toggle").addEventListener("click", toggleDnsLive);

// DNS section collapse/expand
const DNS_COLLAPSE_KEY = "ipwatch_dns_collapsed";
function loadDnsSectionState() {
    try {
        const saved = JSON.parse(localStorage.getItem(DNS_COLLAPSE_KEY) || "{}");
        document.querySelectorAll(".dns-section[data-section]").forEach((section) => {
            const id = section.dataset.section;
            if (saved[id]) {
                section.classList.add("collapsed");
                const btn = section.querySelector(".dns-section-toggle");
                if (btn) btn.title = "Expand";
            }
        });
    } catch (e) {}
}
function saveDnsSectionState() {
    const state = {};
    document.querySelectorAll(".dns-section.collapsed[data-section]").forEach((section) => {
        state[section.dataset.section] = true;
    });
    try { localStorage.setItem(DNS_COLLAPSE_KEY, JSON.stringify(state)); } catch (e) {}
}
document.querySelectorAll(".dns-section-toggle").forEach((btn) => {
    btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const target = btn.dataset.toggle;
        const section = document.querySelector(`.dns-section[data-section="${target}"]`);
        if (!section) return;
        section.classList.toggle("collapsed");
        btn.title = section.classList.contains("collapsed") ? "Expand" : "Minimize";
        saveDnsSectionState();
    });
});
loadDnsSectionState();

// Query Log
function renderQueryLog() {
    browser.runtime.sendMessage({ action: "get_query_log", start: 0, limit: 500 }).then((d) => { queryLogData = d.queries; renderQueryLogTable(); }).catch(() => {});
}

function renderQueryLogTable() {
    const el = $("querylog-body");
    let f = queryLogData;
    if (queryLogFilter === "blocked") f = f.filter((q) => q.blocked);
    else if (queryLogFilter === "allowed") f = f.filter((q) => !q.blocked);
    if (queryLogSearch) { const s = queryLogSearch.toLowerCase(); f = f.filter((q) => q.domain.toLowerCase().includes(s)); }
    if (!f.length) { setHTML(el, `<tr><td colspan="6" class="empty-state"><p>No queries match your filter</p></td></tr>`); return; }
    setHTML(el, f.slice(0, 200).map((q) => {
        const t = new Date(q.time).toLocaleTimeString();
        const sc = q.blocked ? "blocked" : "allowed";
        const st = q.blocked ? "BLOCKED" : "OK";
        const ips = (q.resolvedIps && q.resolvedIps.length) ? q.resolvedIps.slice(0, 2).join(", ") : "-";
        const rt = q.resolveTime > 0 ? q.resolveTime + "ms" : "-";
        const rc = q.resolveTime > 0 ? (q.resolveTime < 50 ? "fast" : q.resolveTime < 200 ? "medium" : "slow") : "";
        return `<tr><td class="querylog-time">${t}</td><td class="querylog-type">${escapeHtml(q.type)}</td><td class="querylog-domain" title="${escapeHtml(q.domain)}">${escapeHtml(q.domain)}</td><td class="querylog-ips">${escapeHtml(ips)}</td><td class="querylog-resolve-time ${rc}">${rt}</td><td><span class="querylog-status ${sc}">${st}</span></td></tr>`;
    }).join(""));
}

$("querylog-filter").addEventListener("change", (e) => { queryLogFilter = e.target.value; renderQueryLogTable(); });
$("querylog-search").addEventListener("input", (e) => { queryLogSearch = e.target.value.toLowerCase(); renderQueryLogTable(); });
$("querylog-clear-btn").addEventListener("click", () => { if (confirm("Clear all query log data?")) { browser.runtime.sendMessage({ action: "clear_query_log" }).then(() => { streamEntries = []; lastLogCount = 0; renderStream(); renderQueryLog(); }); } });

// Detail row
let expandedDetailRow = null;
let expandedDetailData = null;
let expandedDetailHtml = null;

function openDetail(ip, port, protocol, clickedRow) {
    if (!ip || ip === "0.0.0.0" || ip === "*") return;
    if (expandedDetailData && expandedDetailData.ip === ip) { closeDetail(); return; }
    closeDetail();
    expandedDetailData = { ip, port, protocol };
    if (refreshTimer) clearInterval(refreshTimer);
    const dr = document.createElement("tr");
    dr.className = "detail-row";
    setHTML(dr, `<td colspan="7"><div class="detail-loading"><div class="spinner"></div><p>Fetching details for ${ip}...</p></div></td>`);
    if (clickedRow && clickedRow.parentNode) {
        clickedRow.after(dr);
    } else if (currentView === "topology") {
        const target = document.querySelector("#grouped-view .group-connections tbody, #connections-body");
        if (target) target.appendChild(dr);
    }
    expandedDetailRow = dr;
    browser.runtime.sendMessage({ action: "native_detail", ip, port, proto: protocol, dns: dnsProvider }).then((d) => {
        if (d.type === "detail" && expandedDetailData && expandedDetailData.ip === ip) { expandedDetailHtml = buildDetailHtml(d, ip, port); if (expandedDetailRow) setHTML(expandedDetailRow, `<td colspan="7">${expandedDetailHtml}</td>`); }
    }).catch(() => { if (expandedDetailRow) setHTML(expandedDetailRow, `<td colspan="7"><div class="detail-error">Failed to load details</div></td>`); });
}

function closeDetail() {
    if (expandedDetailRow) { expandedDetailRow.remove(); expandedDetailRow = null; }
    expandedDetailData = null;
    expandedDetailHtml = null;
    if (!refreshTimer) refreshTimer = setInterval(fetchConnections, refreshInterval);
}

function restoreDetailRow() {
    if (!expandedDetailData || !expandedDetailRow) return;
    const { ip } = expandedDetailData;
    let target = null;
    document.querySelectorAll("#connections-body tr, .group-connections tr").forEach((r) => {
        if (r.classList.contains("detail-row")) return;
        const cells = r.querySelectorAll("td");
        if (cells.length >= 3 && cells[2].textContent.trim().replace(/^[\u2b50\s]+/, "").startsWith(ip + ":")) target = r;
    });
    if (target) { const ex = target.nextElementSibling; if (ex !== expandedDetailRow) { if (ex && ex.classList.contains("detail-row")) ex.remove(); target.after(expandedDetailRow); } if (expandedDetailHtml) setHTML(expandedDetailRow, `<td colspan="7">${expandedDetailHtml}</td>`); }
    else closeDetail();
}

function buildDetailHtml(data, ip, port) {
    let h = `<div class="detail-content">`;
    h += `<div class="detail-section"><h3>Connection</h3><div class="detail-grid"><div class="detail-item"><div class="label">Remote</div><div class="value">${escapeHtml(ip)}</div></div><div class="detail-item"><div class="label">Port</div><div class="value">${escapeHtml(port)}</div></div><div class="detail-item"><div class="label">Packets</div><div class="value">${escapeHtml(data.ping.packets_received)}/${escapeHtml(data.ping.packets_sent)}</div></div><div class="detail-item"><div class="label">Loss</div><div class="value">${escapeHtml(data.ping.packet_loss_pct)}%</div></div></div></div>`;
    h += `<div class="detail-section"><h3>Service</h3>${data.service ? `<div class="service-name">${escapeHtml(data.service.name)}</div><div class="service-desc">${escapeHtml(data.service.description)}</div>` : `<div class="dns-none">Unknown</div>`}</div>`;
    const fp = getFingerprint(port);
    if (fp) {
        const riskLabel = fp.risk === "high" ? "High Risk" : fp.risk === "medium" ? "Medium Risk" : "Low Risk";
        h += `<div class="detail-section"><h3>Fingerprint</h3><div class="fingerprint-detail"><div class="fp-icon">${fp.icon}</div><div class="fp-name">${escapeHtml(fp.name)}</div><div class="fp-proto">${escapeHtml(fp.proto)}</div><div class="fp-category">${escapeHtml(fp.category)}</div><div class="fp-risk ${escapeHtml(fp.risk)}">${escapeHtml(riskLabel)}</div></div></div>`;
    }
    h += `<div class="detail-section"><h3>DNS</h3>${data.dns.hostname ? `<div class="dns-hostname">${escapeHtml(data.dns.hostname)}</div>` : `<div class="dns-none">No reverse DNS</div>`}</div>`;
    h += `<div class="detail-section"><h3>Latency</h3><div class="ping-stats"><div class="ping-stat"><div class="label">Min</div><div class="value">${escapeHtml(data.ping.min_ms ?? "-")}</div><div class="unit">ms</div></div><div class="ping-stat"><div class="label">Avg</div><div class="value">${escapeHtml(data.ping.avg_ms ?? "-")}</div><div class="unit">ms</div></div><div class="ping-stat"><div class="label">Max</div><div class="value">${escapeHtml(data.ping.max_ms ?? "-")}</div><div class="unit">ms</div></div><div class="ping-stat"><div class="label">Hops</div><div class="value">${escapeHtml(data.trace_hops.length)}</div></div></div></div>`;
    h += `<div class="detail-section"><h3>Route</h3><div class="route-map">`;
    h += `<div class="route-hop local"><div class="hop-node">0</div><div class="hop-info"><div class="hop-ip">Your PC</div></div><div class="hop-rtt fast">local</div></div>`;
    for (const hop of data.trace_hops) {
        const rt = hop.rtt_ms ?? hop.rtt2_ms ?? hop.rtt3_ms;
        const to = !rt;
        const rc = to ? "timeout" : rt < 20 ? "fast" : rt < 100 ? "medium" : rt < 200 ? "slow" : "timeout";
        const hc = to ? "timeout" : "reachable";
        h += `<div class="route-hop ${escapeHtml(hc)}"><div class="hop-node">${escapeHtml(hop.hop)}</div><div class="hop-info"><div class="hop-ip">${escapeHtml(hop.ip)}</div>${hop.hostname ? `<div class="hop-hostname">${escapeHtml(hop.hostname)}</div>` : ""}</div><div class="hop-rtt ${escapeHtml(rc)}">${to ? "*" : rt.toFixed(1) + " ms"}</div></div>`;
    }
    h += `</div></div></div>`;
    return h;
}

function attachRowClickHandlers() {
    document.querySelectorAll("#connections-body tr, .group-connections tr").forEach((r) => { r.removeEventListener("click", handleRowClick); r.addEventListener("click", handleRowClick); });
}

function handleRowClick(e) {
    if (e.target.closest(".group-header") || e.target.closest(".detail-row")) return;
    const cells = e.currentTarget.querySelectorAll("td");
    if (cells.length >= 4) {
        const text = cells[2].textContent.trim().replace(/^[\u2b50\s]+/, "");
        const m = text.match(/^([\d.]+|[\da-f:]+):(\d+)$/);
        if (m) { const ip = m[1]; if (expandedDetailData && expandedDetailData.ip === ip) { closeDetail(); return; } openDetail(ip, parseInt(m[2]), cells[0].textContent.trim(), e.currentTarget); }
    }
}

function loadFavorites() { try { const s = localStorage.getItem(FAVORITES_KEY); if (s) favorites = new Set(JSON.parse(s)); } catch (e) { favorites = new Set(); } }
function saveFavorites() { try { localStorage.setItem(FAVORITES_KEY, JSON.stringify([...favorites])); } catch (e) {} }
function loadBlocklist() { try { const s = localStorage.getItem(BLOCKLIST_KEY); if (s) blocklist = new Set(JSON.parse(s)); } catch (e) { blocklist = new Set(); } }
function saveBlocklist() { try { localStorage.setItem(BLOCKLIST_KEY, JSON.stringify([...blocklist])); } catch (e) {} }
function toggleFavorite(ip) { if (favorites.has(ip)) favorites.delete(ip); else favorites.add(ip); saveFavorites(); render(); }
function toggleBlocklist(val) {
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val);
    if (blocklist.has(val)) {
        blocklist.delete(val);
        if (isIP) {
            autoBlocklistIps.delete(val);
        } else {
            const idx = manualBlockedDomains.indexOf(val);
            if (idx >= 0) manualBlockedDomains.splice(idx, 1);
            saveManualBlockedDomains();
            dnsFilteringDomains = dnsFilteringDomains.filter(d => d !== val);
        }
    } else {
        blocklist.add(val);
        if (isIP) {
            autoBlocklistIps.add(val);
        } else if (!manualBlockedDomains.includes(val)) {
            manualBlockedDomains.push(val);
            saveManualBlockedDomains();
            dnsFilteringDomains.push(val);
        }
    }
    saveBlocklist();
    try { localStorage.setItem(AUTO_BLOCKLIST_KEY, JSON.stringify([...autoBlocklistIps])); } catch (e) {}
    browser.runtime.sendMessage({
        action: "update_blocklist",
        domains: [...dnsFilteringDomains].slice(0, 100000),
        ips: [], // IPs no longer used (parser now extracts domains)
        whitelist: [...whitelistedDomains],
        enabled: dnsFilteringEnabled
    }).catch(() => {});
    render();
}
function copyToClipboard(text) { navigator.clipboard.writeText(text).catch(() => {}); }

function attachContextMenu() {
    document.querySelectorAll("#connections-body tr, .group-connections tr").forEach((row) => {
        row.addEventListener("contextmenu", (e) => {
            e.preventDefault();
            const cells = row.querySelectorAll("td");
            if (cells.length < 4) return;
            const remoteText = cells[3].textContent.trim();
            const m = remoteText.match(/^([\d.]+|[\da-f:]+):(\d+)$/);
            const ip = m ? m[1] : null;
            const domain = cells[1]?.textContent?.trim() || "";

            const ex = document.getElementById("ctx-menu");
            if (ex) ex.remove();

            const targets = [];
            if (ip) targets.push({ label: ip, value: ip });
            if (domain && domain !== "-" && domain !== "Service") targets.push({ label: domain, value: domain });
            if (targets.length === 0) return;

            const primaryTarget = targets[0];
            const isFav = favorites.has(primaryTarget.value);
            const isBl = blocklist.has(primaryTarget.value);

            let menuItems = `<div class="ctx-item" data-action="copy">📋 Copy ${escapeHtml(primaryTarget.label)}</div>`;
            menuItems += `<div class="ctx-item" data-action="fav">${isFav ? "⭐ Unfavorite" : "☆ Favorite"} ${escapeHtml(primaryTarget.label)}</div>`;
            menuItems += `<div class="ctx-item" data-action="block">${isBl ? "🚫 Unblock" : "🛑 Block"} ${escapeHtml(primaryTarget.label)}</div>`;

            if (targets.length > 1) {
                menuItems += `<div class="ctx-separator"></div>`;
                for (const t of targets.slice(1)) {
                    const tFav = favorites.has(t.value);
                    const tBl = blocklist.has(t.value);
                    menuItems += `<div class="ctx-item" data-action="fav-${escapeHtml(t.value)}">${tFav ? "⭐" : "☆"} ${escapeHtml(t.label)}</div>`;
                    menuItems += `<div class="ctx-item" data-action="block-${escapeHtml(t.value)}">${tBl ? "🚫" : "🛑"} ${escapeHtml(t.label)}</div>`;
                }
            }

            const menu = document.createElement("div");
            menu.id = "ctx-menu";
            menu.className = "ctx-menu";
            setHTML(menu, menuItems);
            document.body.appendChild(menu);
            menu.style.top = `${e.clientY}px`;
            menu.style.left = `${Math.min(e.clientX, window.innerWidth - 180)}px`;
            menu.querySelectorAll(".ctx-item").forEach((item) => {
                item.addEventListener("click", () => {
                    const a = item.dataset.action;
                    if (a === "copy") copyToClipboard(primaryTarget.value);
                    else if (a === "fav") toggleFavorite(primaryTarget.value);
                    else if (a === "block") toggleBlocklist(primaryTarget.value);
                    else if (a.startsWith("fav-")) toggleFavorite(a.replace("fav-", ""));
                    else if (a.startsWith("block-")) toggleBlocklist(a.replace("block-", ""));
                    menu.remove();
                });
            });
            setTimeout(() => { const cl = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener("mousedown", cl); } }; document.addEventListener("mousedown", cl); }, 10);
        });
    });
}

// Settings
const settingsOverlay = $("settings-overlay");
const settingsClose = $("settings-close");
const settingsBtn = $("settings-btn");
const exportBtn = $("export-btn");
const blocklistAutoToggle = $("setting-blocklist-auto");
const blocklistStatus = $("blocklist-status");
const blocklistUpdateBtn = $("blocklist-update-btn");
const refreshIntervalSelect = $("setting-refresh-interval");
const dnsProviderSelect = $("setting-dns-provider");
const dnsCustomInput = $("setting-dns-custom");
const dnsFilteringToggle = $("setting-dns-filtering");
const dnsFilteringStatus = $("dns-filtering-status");
const dnsFilteringUpdateBtn = $("dns-filtering-update-btn");
const dnsCacheClearBtn = $("dns-cache-clear-btn");

settingsBtn.addEventListener("click", () => settingsOverlay.classList.remove("hidden"));
settingsClose.addEventListener("click", () => settingsOverlay.classList.add("hidden"));
settingsOverlay.addEventListener("click", (e) => { if (e.target === settingsOverlay) settingsOverlay.classList.add("hidden"); });
exportBtn.addEventListener("click", () => exportConnections("csv"));

function loadSettings() {
    try {
        const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
        if (s.refreshInterval) refreshInterval = s.refreshInterval;
        if (s.blocklistAuto !== undefined) blocklistAutoToggle.checked = s.blocklistAuto;
        if (s.dnsProvider) { dnsProvider = s.dnsProvider; const known = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222"]; if (known.includes(dnsProvider)) dnsProviderSelect.value = dnsProvider; else { dnsProviderSelect.value = "custom"; dnsCustomInput.value = dnsProvider; dnsCustomInput.style.display = "block"; } }
        if (s.dnsFilteringEnabled !== undefined) { dnsFilteringEnabled = s.dnsFilteringEnabled; dnsFilteringToggle.checked = dnsFilteringEnabled; }
    } catch (e) {}
    refreshIntervalSelect.value = String(refreshInterval);
    updateBlocklistStatus();
    updateDnsFilteringStatus();
    loadCustomBlocklists();
    loadManualBlockedDomains();
    loadWhitelistedDomains();
    loadProfiles();
    renderProfileSelector();
    applyProfileSettings();
}

function renderProfileSelector() {
    document.querySelectorAll(".profile-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.profile === currentProfile);
    });
    const p = getProfile(currentProfile);
    $("profile-alert-mode").value = p.alertMode || "monitor";
    $("profile-dns-filtering").checked = !!p.dnsFiltering;
    $("profile-blocklist-feeds").checked = !!p.blocklistFeeds;
    $("profile-strict-mode").checked = !!p.strictMode;
    $("profile-gateway-subnet").value = p.gatewaySubnet || "";
}

function saveProfileSettings() {
    const p = getProfile(currentProfile);
    p.alertMode = $("profile-alert-mode").value;
    p.dnsFiltering = $("profile-dns-filtering").checked;
    p.blocklistFeeds = $("profile-blocklist-feeds").checked;
    p.strictMode = $("profile-strict-mode").checked;
    p.gatewaySubnet = $("profile-gateway-subnet").value.trim();
    profiles[currentProfile] = p;
    saveProfiles();
    applyProfileSettings();
}

function saveSettings() { try { localStorage.setItem(SETTINGS_KEY, JSON.stringify({ refreshInterval, blocklistAuto: blocklistAutoToggle.checked, dnsProvider, dnsFilteringEnabled })); } catch (e) {} }

function updateBlocklistStatus() { const c = autoBlocklistIps.size; let l = "never"; try { l = localStorage.getItem(AUTO_BLOCKLIST_KEY + "_updated") || "never"; } catch (e) {} blocklistStatus.textContent = `${c.toLocaleString()} IPs \u2022 Updated: ${l}`; }
function loadAutoBlocklist() { try { const s = localStorage.getItem(AUTO_BLOCKLIST_KEY); if (s) autoBlocklistIps = new Set(JSON.parse(s)); } catch (e) { autoBlocklistIps = new Set(); } updateBlocklistStatus(); }

async function fetchBlocklistFeed(url) {
    try {
        const resp = await fetch(url);
        if (!resp.ok) {
            console.warn(`Ad Bear: blocklist ${url} returned HTTP ${resp.status}`);
            return new Set();
        }
        const text = await resp.text();
        const domains = new Set();

        // Regex: valid domain (RFC 1035 simplified) — excludes pure IPs
        const domainRegex = /^(?!^\d+\.\d+\.\d+\.\d+$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

        for (const line of text.split("\n")) {
            const t = line.trim();
            // Skip comments and empty lines
            if (!t || t.startsWith("#") || t.startsWith("!")) continue;

            // AdBlock format: ||example.com^ or ||example.com^$options
            if (t.startsWith("||")) {
                const match = t.match(/^\|\|([a-z0-9.-]+)\^?/i);
                if (match) {
                    const d = match[1].toLowerCase();
                    // Filter out IPs and invalid domains
                    if (!ipRegex.test(d) && domainRegex.test(d)) {
                        domains.add(d);
                    }
                }
                continue;
            }

            // Hosts format: IP domain [aliases...]
            // e.g. "0.0.0.0 example.com" or "127.0.0.1 example.com www.example.com"
            const parts = t.split(/\s+/);
            if (parts.length >= 2 && ipRegex.test(parts[0])) {
                // Take all parts after the IP — they're domain aliases
                for (let i = 1; i < parts.length; i++) {
                    const d = parts[i].toLowerCase();
                    if (domainRegex.test(d) && d !== "localhost" && d !== "ip6-localhost" && d !== "broadcasthost") {
                        domains.add(d);
                    }
                }
                continue;
            }

            // Domain-only line (some lists are just "example.com" one per line)
            if (parts.length === 1) {
                const d = parts[0].toLowerCase();
                if (domainRegex.test(d) && !ipRegex.test(d)) {
                    domains.add(d);
                }
                continue;
            }
        }

        console.debug(`Ad Bear: parsed ${domains.size} domains from ${url.split("/").pop()}`);
        return domains;
    } catch (e) {
        console.warn(`Ad Bear: failed to fetch blocklist ${url}:`, e.message);
        return new Set();
    }
}


async function updateAutoBlocklist() {
    if (!blocklistAutoToggle.checked) { blocklistStatus.textContent = "Auto-download disabled"; return; }
    blocklistStatus.textContent = "Downloading...";
    for (const feed of BLOCKLIST_FEEDS) {
        blocklistStatus.textContent = `Downloading ${feed.name}...`;
        const domains = await fetchBlocklistFeed(feed.url);
        for (const d of domains) dnsFilteringDomains.add(d);
        blocklistStatus.textContent = `${feed.name}: ${dnsFilteringDomains.size} domains total`;
    }
    try { localStorage.setItem(AUTO_BLOCKLIST_KEY, JSON.stringify([...autoBlocklistIps])); localStorage.setItem(AUTO_BLOCKLIST_KEY + "_updated", new Date().toLocaleString()); } catch (e) {}
    try { await browser.runtime.sendMessage({ action: "update_blocklist", domains: [...dnsFilteringDomains].slice(0, 100000), ips: [], whitelist: [...whitelistedDomains], enabled: dnsFilteringEnabled }); } catch (e) {}
    updateBlocklistStatus();
    render();
}

blocklistAutoToggle.addEventListener("change", () => { saveSettings(); if (blocklistAutoToggle.checked) updateAutoBlocklist(); else { autoBlocklistIps.clear(); localStorage.removeItem(AUTO_BLOCKLIST_KEY); browser.runtime.sendMessage({ action: "update_blocklist", domains: [...dnsFilteringDomains].slice(0, 100000), ips: [], whitelist: [...whitelistedDomains], enabled: dnsFilteringEnabled }).catch(() => {}); updateBlocklistStatus(); render(); } });
blocklistUpdateBtn.addEventListener("click", updateAutoBlocklist);
refreshIntervalSelect.addEventListener("change", () => { refreshInterval = parseInt(refreshIntervalSelect.value); saveSettings(); if (refreshTimer) clearInterval(refreshTimer); refreshTimer = setInterval(fetchConnections, refreshInterval); });
dnsProviderSelect.addEventListener("change", () => { if (dnsProviderSelect.value === "custom") { dnsCustomInput.style.display = "block"; dnsCustomInput.focus(); } else { dnsCustomInput.style.display = "none"; dnsProvider = dnsProviderSelect.value; saveSettings(); } });
dnsCustomInput.addEventListener("input", () => { const v = dnsCustomInput.value.trim(); if (v) { dnsProvider = v; saveSettings(); } });

document.querySelectorAll(".profile-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        currentProfile = btn.dataset.profile;
        saveCurrentProfile();
        renderProfileSelector();
        applyProfileSettings();
    });
});
$("profile-alert-mode").addEventListener("change", saveProfileSettings);
$("profile-dns-filtering").addEventListener("change", saveProfileSettings);
$("profile-blocklist-feeds").addEventListener("change", saveProfileSettings);
$("profile-strict-mode").addEventListener("change", saveProfileSettings);
$("profile-gateway-subnet").addEventListener("change", saveProfileSettings);

function updateDnsFilteringStatus() { if (!dnsFilteringEnabled) { dnsFilteringStatus.textContent = "Disabled"; return; } let updated = "never"; try { updated = localStorage.getItem("ipwatch_dns_filtering_updated") || "never"; } catch (e) {} dnsFilteringStatus.textContent = `${dnsFilteringDomains.length.toLocaleString()} domains \u2022 Updated: ${updated}`; }

async function updateDnsFiltering() {
    if (!dnsFilteringEnabled) return;
    dnsFilteringStatus.textContent = "Downloading...";
    dnsFilteringUpdateBtn.disabled = true;
    let all = new Set(dnsFilteringDomains);
    for (const feed of DNS_BLOCKLIST_FEEDS) {
        try {
            const resp = await fetch(feed.url);
            if (!resp.ok) continue;
            const text = await resp.text();
            for (const line of text.split("\n")) {
                const t = line.trim();
                if (!t || t.startsWith("#")) continue;
                if (t.startsWith("0.0.0.0") || t.startsWith("127.0.0.1")) { const p = t.split(/\s+/); if (p.length >= 2 && !p[1].includes(":") && p[1] !== "localhost") all.add(p[1]); }
                else if (!t.includes(" ") && !t.includes("\t") && !t.includes(":") && t !== "localhost") all.add(t);
            }
            if (typeof BlocklistManager !== "undefined") BlocklistManager.syncFeedDownloaded(feed.url);
        } catch (e) {}
    }
    for (const url of customBlocklistUrls) {
        try {
            const resp = await fetch(url);
            if (!resp.ok) continue;
            const text = await resp.text();
            for (const line of text.split("\n")) {
                const t = line.trim();
                if (!t || t.startsWith("#")) continue;
                if (t.startsWith("0.0.0.0") || t.startsWith("127.0.0.1")) { const p = t.split(/\s+/); if (p.length >= 2 && !p[1].includes(":") && p[1] !== "localhost") all.add(p[1]); }
                else if (!t.includes(" ") && !t.includes("\t") && !t.includes(":") && t !== "localhost") all.add(t);
            }
        } catch (e) {}
    }
    for (const d of manualBlockedDomains) all.add(d);
    const domains = [...all];
    try { localStorage.setItem("ipwatch_dns_filtering_domains", JSON.stringify(domains)); localStorage.setItem("ipwatch_dns_filtering_updated", new Date().toLocaleString()); } catch (e) {}
    try { await browser.runtime.sendMessage({ action: "update_blocklist", domains: domains.slice(0, 100000), ips: [], whitelist: [...whitelistedDomains], enabled: true }); } catch (e) {}
    dnsFilteringUpdateBtn.disabled = false;
    updateDnsFilteringStatus();
}

dnsFilteringToggle.addEventListener("change", () => { dnsFilteringEnabled = dnsFilteringToggle.checked; saveSettings(); if (dnsFilteringEnabled) updateDnsFiltering(); else { browser.runtime.sendMessage({ action: "set_filtering", enabled: false }).catch(() => {}); updateDnsFilteringStatus(); } });
dnsFilteringUpdateBtn.addEventListener("click", updateDnsFiltering);
dnsCacheClearBtn.addEventListener("click", () => { browser.runtime.sendMessage({ action: "clear_dns_cache" }).then(() => { dnsCacheClearBtn.textContent = "Cleared!"; setTimeout(() => { dnsCacheClearBtn.textContent = "Clear DNS Cache"; }, 2000); }).catch(() => {}); });

// Custom blocklists
const customBlocklistUrlInput = $("custom-blocklist-url");
const addCustomBlocklistBtn = $("add-custom-blocklist-btn");
const customBlocklistList = $("custom-blocklist-list");
function loadCustomBlocklists() { try { const s = localStorage.getItem(CUSTOM_BLOCKLIST_KEY); if (s) customBlocklistUrls = JSON.parse(s); } catch (e) { customBlocklistUrls = []; } renderCustomBlocklistList(); }
function saveCustomBlocklists() { try { localStorage.setItem(CUSTOM_BLOCKLIST_KEY, JSON.stringify(customBlocklistUrls)); } catch (e) {} }
function renderCustomBlocklistList() { if (!customBlocklistUrls.length) { setHTML(customBlocklistList, `<div class="setting-desc" style="font-style:italic">No custom blocklists</div>`); return; } setHTML(customBlocklistList, customBlocklistUrls.map((u, i) => `<div class="blocklist-item"><span class="url" title="${escapeHtml(u)}">${escapeHtml(u)}</span><button class="remove-btn" data-idx="${i}">\u00d7</button></div>`).join("")); customBlocklistList.querySelectorAll(".remove-btn").forEach((b) => { b.addEventListener("click", () => { customBlocklistUrls.splice(parseInt(b.dataset.idx), 1); saveCustomBlocklists(); renderCustomBlocklistList(); }); }); }
const manualDomainList = $("manual-domain-list");
const manualDomainInput = $("manual-domain-input");
const addManualDomainBtn = $("add-manual-domain-btn");
const whitelistDomainInput = $("whitelist-domain-input");
const whitelistDomainList = $("whitelist-domain-list");
const addWhitelistDomainBtn = $("add-whitelist-domain-btn");

function loadManualBlockedDomains() { try { const s = localStorage.getItem(MANUAL_BLOCKLIST_KEY); if (s) manualBlockedDomains = JSON.parse(s); } catch (e) { manualBlockedDomains = []; } renderManualDomainList(); }
function saveManualBlockedDomains() { try { localStorage.setItem(MANUAL_BLOCKLIST_KEY, JSON.stringify(manualBlockedDomains)); } catch (e) {} }
function loadWhitelistedDomains() { try { const s = localStorage.getItem(WHITELIST_KEY); if (s) whitelistedDomains = JSON.parse(s); } catch (e) { whitelistedDomains = []; } renderWhitelistDomainList(); }
function saveWhitelistedDomains() { try { localStorage.setItem(WHITELIST_KEY, JSON.stringify(whitelistedDomains)); } catch (e) {} }

function renderManualDomainList() { if (!manualBlockedDomains.length) { setHTML(manualDomainList, `<div class="setting-desc" style="font-style:italic">No blocked domains</div>`); return; } setHTML(manualDomainList, manualBlockedDomains.map((d, i) => `<div class="domain-item"><span class="domain" title="${escapeHtml(d)}">${escapeHtml(d)}</span><button class="remove-btn" data-idx="${i}">\u00d7</button></div>`).join("")); manualDomainList.querySelectorAll(".remove-btn").forEach((b) => { b.addEventListener("click", () => { manualBlockedDomains.splice(parseInt(b.dataset.idx), 1); saveManualBlockedDomains(); renderManualDomainList(); if (dnsFilteringEnabled) updateDnsFiltering(); }); }); }
function renderWhitelistDomainList() { if (!whitelistedDomains.length) { setHTML(whitelistDomainList, `<div class="setting-desc" style="font-style:italic">No whitelisted domains</div>`); return; } setHTML(whitelistDomainList, whitelistedDomains.map((d, i) => `<div class="domain-item"><span class="domain" title="${escapeHtml(d)}">${escapeHtml(d)}</span><button class="remove-btn" data-idx="${i}">\u00d7</button></div>`).join("")); whitelistDomainList.querySelectorAll(".remove-btn").forEach((b) => { b.addEventListener("click", () => { whitelistedDomains.splice(parseInt(b.dataset.idx), 1); saveWhitelistedDomains(); renderWhitelistDomainList(); if (dnsFilteringEnabled) updateDnsFiltering(); }); }); }
addManualDomainBtn.addEventListener("click", () => { const d = manualDomainInput.value.trim().toLowerCase(); if (d && !manualBlockedDomains.includes(d)) { manualBlockedDomains.push(d); saveManualBlockedDomains(); renderManualDomainList(); manualDomainInput.value = ""; if (dnsFilteringEnabled) updateDnsFiltering(); } });
manualDomainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addManualDomainBtn.click(); });
addWhitelistDomainBtn.addEventListener("click", () => { const d = whitelistDomainInput.value.trim().toLowerCase(); if (d && !whitelistedDomains.includes(d)) { whitelistedDomains.push(d); saveWhitelistedDomains(); renderWhitelistDomainList(); whitelistDomainInput.value = ""; if (dnsFilteringEnabled) updateDnsFiltering(); } });
whitelistDomainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addWhitelistDomainBtn.click(); });

// Export
function exportConnections(format) {
    if (!connections.length) return;
    let content, filename, type;
    if (format === "csv") { content = "Protocol,Local IP,Local Port,Remote IP,Remote Port,State,PID,Process,Risk Level\n" + connections.map((c) => `${csvEscape(c.protocol)},${csvEscape(c.local_ip)},${csvEscape(c.local_port)},${csvEscape(c.remote_ip)},${csvEscape(c.remote_port)},${csvEscape(c.state)},${csvEscape(c.pid)},${csvEscape(c.process_name)},${csvEscape(c.risk_level)}`).join("\n"); filename = `ipwatch-${Date.now()}.csv`; type = "text/csv"; }
    else { content = JSON.stringify(connections, null, 2); filename = `ipwatch-${Date.now()}.json`; type = "application/json"; }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = filename;
    a.click();
}

$("export-csv-btn").addEventListener("click", () => exportConnections("csv"));
$("export-json-btn").addEventListener("click", () => exportConnections("json"));
$("clear-history-btn").addEventListener("click", () => { if (confirm("Clear history?")) { historySnapshots = []; localStorage.removeItem(HISTORY_KEY); render(); } });
$("clear-favorites-btn").addEventListener("click", () => { if (confirm("Clear favorites?")) { favorites.clear(); saveFavorites(); render(); } });
$("clear-blocklist-btn").addEventListener("click", () => { if (confirm("Clear blocklist?")) { blocklist.clear(); autoBlocklistIps.clear(); saveBlocklist(); localStorage.removeItem(AUTO_BLOCKLIST_KEY); browser.runtime.sendMessage({ action: "update_blocklist", domains: [...dnsFilteringDomains].slice(0, 100000), ips: [], whitelist: [...whitelistedDomains], enabled: dnsFilteringEnabled }).catch(() => {}); updateBlocklistStatus(); render(); } });
$("clear-querylog-btn").addEventListener("click", () => { if (confirm("Clear query log?")) { browser.runtime.sendMessage({ action: "clear_query_log" }).then(() => { streamEntries = []; lastLogCount = 0; renderStream(); renderQueryLog(); }); } });
$("clear-db-btn").addEventListener("click", () => { if (confirm("Clear persistent connection database? This cannot be undone.")) { clearDB().then(() => { $("clear-db-btn").textContent = "Cleared!"; setTimeout(() => { $("clear-db-btn").textContent = "Clear Persistent DB"; }, 2000); }); } });

// Search, filters, sort, views
searchInput.addEventListener("input", applyFilters);
stateFilterEl.addEventListener("change", applyFilters);
protoFilterEl.addEventListener("change", applyFilters);
document.querySelectorAll("#connections-table th").forEach((th) => { th.addEventListener("click", () => { const k = th.dataset.sort; if (sortKey === k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = true; } applyFilters(); }); });

// View tab click handlers
document.querySelectorAll(".view-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".view-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        currentView = btn.dataset.view;
        document.querySelectorAll(".view-panel").forEach((p) => p.classList.remove("active"));
        const map = { grouped: "grouped-view", dns: "dns-view", querylog: "querylog-view", history: "history-view", favorites: "favorites-view", blocked: "blocked-view", alerts: "alerts-view", topology: "topology-view", blocklists: "blocklists-view" };
        if (map[currentView]) $(map[currentView]).classList.add("active");
        if (currentView === "topology") { Topology.init(); Topology.update(); }
        if (currentView === "blocklists") BlocklistManager.init();
        render();
    });
});

// Drag-and-drop tab reordering
const viewToggle = $("view-toggle");
let draggedBtn = null;

viewToggle.addEventListener("dragstart", (e) => {
    if (!e.target.classList.contains("view-btn")) return;
    draggedBtn = e.target;
    e.target.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", e.target.dataset.view);
});

viewToggle.addEventListener("dragend", (e) => {
    if (e.target.classList.contains("view-btn")) {
        e.target.classList.remove("dragging");
    }
    document.querySelectorAll(".view-btn").forEach((b) => {
        b.classList.remove("drag-over");
    });
    draggedBtn = null;
});

viewToggle.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    const target = e.target.closest(".view-btn");
    if (target && target !== draggedBtn) {
        document.querySelectorAll(".view-btn").forEach((b) => b.classList.remove("drag-over"));
        target.classList.add("drag-over");
    }
});

viewToggle.addEventListener("dragleave", (e) => {
    const target = e.target.closest(".view-btn");
    if (target) target.classList.remove("drag-over");
});

viewToggle.addEventListener("drop", (e) => {
    e.preventDefault();
    const target = e.target.closest(".view-btn");
    if (!target || !draggedBtn || target === draggedBtn) return;

    const buttons = Array.from(viewToggle.querySelectorAll(".view-btn"));
    const draggedIdx = buttons.indexOf(draggedBtn);
    const targetIdx = buttons.indexOf(target);

    if (draggedIdx < targetIdx) {
        viewToggle.insertBefore(draggedBtn, target.nextSibling);
    } else {
        viewToggle.insertBefore(draggedBtn, target);
    }

    document.querySelectorAll(".view-btn").forEach((b) => b.classList.remove("drag-over"));

    const order = Array.from(viewToggle.querySelectorAll(".view-btn")).map((b) => b.dataset.view);
    try { localStorage.setItem("ipwatch_tab_order", JSON.stringify(order)); } catch (e) {}
});

// Restore saved tab order
function restoreTabOrder() {
    try {
        const saved = localStorage.getItem("ipwatch_tab_order");
        if (!saved) return;
        const order = JSON.parse(saved);
        const btnMap = new Map();
        document.querySelectorAll(".view-btn").forEach((b) => btnMap.set(b.dataset.view, b));
        for (const view of order) {
            const btn = btnMap.get(view);
            if (btn) viewToggle.appendChild(btn);
        }
    } catch (e) {}
}
restoreTabOrder();
$("refresh-btn").addEventListener("click", fetchConnections);

// Keyboard shortcuts
document.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key === "k") { e.preventDefault(); searchInput.focus(); searchInput.select(); }
    if (e.ctrlKey && e.key === "e") { e.preventDefault(); exportConnections("csv"); }
    if (e.ctrlKey && e.key === ",") { e.preventDefault(); settingsOverlay.classList.toggle("hidden"); }
    if (e.ctrlKey && e.key === "d") { e.preventDefault(); document.querySelector('[data-view="dns"]').click(); }
    if (e.ctrlKey && e.key === "b") { e.preventDefault(); document.querySelector('[data-view="querylog"]').click(); }
    if (e.ctrlKey && e.key === "l") { e.preventDefault(); document.querySelector('[data-view="blocklists"]').click(); }
    if (e.key === "Escape") { if (expandedDetailData) closeDetail(); settingsOverlay.classList.add("hidden"); }
});

// Init
(async function init() {
    await openDB();
    const dbHistory = await loadConnectionsFromDB(50);
    if (dbHistory.length) {
        historySnapshots.push({ time: Date.now(), total: dbHistory.length, estab: dbHistory.filter((c) => c.state?.toUpperCase().includes("ESTAB")).length, listen: dbHistory.filter((c) => c.state?.toUpperCase().includes("LISTEN")).length, highRisk: dbHistory.filter((c) => ["high", "critical"].includes((c.risk_level || "").toLowerCase())).length, fromDb: true });
    }

    loadSettings();
    loadAutoBlocklist();
    loadDnsFilteringDomains();
    loadWhitelistedDomains();
    if (blocklistAutoToggle.checked) updateAutoBlocklist();
    if (dnsFilteringEnabled) updateDnsFiltering();
    function loadDnsFilteringDomains() { try { const s = localStorage.getItem("ipwatch_dns_filtering_domains"); if (s) { dnsFilteringDomains = JSON.parse(s); updateDnsFilteringStatus(); } } catch (e) {} }

    loadHistory();
    loadFavorites();
    loadBlocklist();
    ping();
    fetchConnections();
    refreshTimer = setInterval(fetchConnections, refreshInterval);
    startDnsPolling();

    browser.runtime.sendMessage({ action: "get_stats" }).then((stats) => {
        if (stats) {
            const bgEnabled = !!stats.filteringEnabled;
            dnsFilteringEnabled = bgEnabled;
            dnsFilteringToggle.checked = bgEnabled;
            dnsStats = stats;
            if (bgEnabled) updateDnsFilteringStatus();
            else { dnsFilteringStatus.textContent = "Disabled"; }
        }
    }).catch(() => {});

    fetchPublicIp();
    updateTabFilter();
    setInterval(updateTabFilter, 10000);
    fetchBandwidth();
    setInterval(fetchBandwidth, 30000);
    setInterval(ping, 15000);

    const manifest = browser.runtime.getManifest();
    const versionEl = $("ext-version");
    if (versionEl) versionEl.textContent = `v${manifest.version}`;
})();

async function ping() {
    try {
        const d = await browser.runtime.sendMessage({ action: "native_ping" });
        if (d.type === "pong") {
            connectAttempts = 0;
            statusBadge.textContent = "Connected";
            statusBadge.className = "badge-online";
        }
    } catch (e) {
        connectAttempts++;
        if (connectAttempts <= 5) {
            statusBadge.textContent = "Connecting...";
            statusBadge.className = "badge-offline";
        } else {
            statusBadge.textContent = "Disconnected";
            statusBadge.className = "badge-offline";
        }
    }
}


async function fetchPublicIp() {
    try {
        const resp = await fetch("https://api.ipify.org?format=json");
        if (resp.ok) {
            const data = await resp.json();
            const el = $("public-ip");
            if (el) { el.textContent = data.ip; el.title = `Public IP: ${data.ip}`; }
        }
    } catch (e) {}
}

async function updateTabFilter() {
    try {
        const tabs = await browser.tabs.query({});
        const select = $("dns-tab-filter");
        if (!select) return;
        const currentVal = select.value;
        const tabMap = new Map();
        for (const tab of tabs) {
            if (tab.url && (tab.url.startsWith("http") || tab.url.startsWith("file"))) {
                try {
                    const hostname = new URL(tab.url).hostname;
                    tabMap.set(tab.id, hostname);
                } catch (e) {}
            }
        }
        setHTML(select, '<option value="all">All Tabs</option>');
        for (const [id, host] of tabMap) {
            const opt = document.createElement("option");
            opt.value = String(id);
            opt.textContent = host;
            select.appendChild(opt);
        }
        if (tabMap.has(parseInt(currentVal))) select.value = currentVal;
    } catch (e) {}
}

function filterStreamByTab(entries) {
    if (streamTabFilter === "all") return entries;
    const tabId = parseInt(streamTabFilter);
    return entries.filter((e) => e.tabId === tabId);
}

function checkAlerts(newConns) {
    const newAlerts = [];
    for (const c of newConns) {
        if (!c.isNew) continue;
        if (c.remote_ip === "0.0.0.0" || c.remote_ip === "127.0.0.1") continue;
        if (c.blocked) continue;

        const port = c.remote_port;
        const risk = (c.risk_level || "").toLowerCase();
        const domain = c.domain || "";

        if (["critical"].includes(risk)) {
            newAlerts.push({ time: Date.now(), type: "risk", severity: "critical", message: `${c.process_name || "Unknown"} → ${c.remote_ip} [CRITICAL: ${c.risk_reason}]`, ip: c.remote_ip, port, domain });
        }
        if (["high"].includes(risk)) {
            newAlerts.push({ time: Date.now(), type: "risk", severity: "high", message: `${c.process_name || "Unknown"} → ${c.remote_ip} [HIGH: ${c.risk_reason}]`, ip: c.remote_ip, port, domain });
        }
        if (SUSPICIOUS_PORTS.has(port)) {
            newAlerts.push({ time: Date.now(), type: "port", severity: "high", message: `${c.process_name || "Unknown"} → ${c.remote_ip}:${port} [suspicious port]`, ip: c.remote_ip, port, domain });
        }
        if (HIGH_RISK_PORTS.has(port) && !["safe", "low"].includes(risk)) {
            newAlerts.push({ time: Date.now(), type: "exposed", severity: "medium", message: `${c.process_name || "Unknown"} → ${c.remote_ip}:${port} [exposed service]`, ip: c.remote_ip, port, domain });
        }
        if (blocklist.has(c.remote_ip) || blocklist.has(domain) || autoBlocklistIps.has(c.remote_ip)) {
            newAlerts.push({ time: Date.now(), type: "blocked", severity: "high", message: `${c.process_name || "Unknown"} → ${c.remote_ip} [blocklisted]`, ip: c.remote_ip, port, domain });
        }
        if (risk === "medium" && c.risk_reason === "Tracker") {
            newAlerts.push({ time: Date.now(), type: "tracker", severity: "medium", message: `${c.process_name || "Unknown"} → ${domain || c.remote_ip} [tracker detected]`, ip: c.remote_ip, port, domain });
        }
        if (domain && /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(domain) && domain !== "127.0.0.1") {
            newAlerts.push({ time: Date.now(), type: "domain", severity: "medium", message: `${c.process_name || "Unknown"} → direct IP connection ${domain}`, ip: c.remote_ip, port, domain });
        }
    }
    if (newAlerts.length) {
        alerts = [...newAlerts, ...alerts].slice(0, MAX_ALERTS);
        alertCount += newAlerts.length;
        updateAlertBadge();
    }
}

function updateAlertBadge() {
    const alertsBtn = document.querySelector('[data-view="alerts"]');
    if (!alertsBtn) return;
    const existing = alertsBtn.querySelector(".alert-badge-count");
    if (alertCount > 0) {
        if (!existing) {
            const badge = document.createElement("span");
            badge.className = "alert-badge-count";
            badge.textContent = alertCount > 99 ? "99+" : alertCount;
            alertsBtn.appendChild(badge);
        } else {
            existing.textContent = alertCount > 99 ? "99+" : alertCount;
        }
    } else if (existing) {
        existing.remove();
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatRate(bytesPerSec) {
    if (bytesPerSec < 1024) return Math.round(bytesPerSec) + " B/s";
    if (bytesPerSec < 1048576) return (bytesPerSec / 1024).toFixed(1) + " KB/s";
    return (bytesPerSec / 1048576).toFixed(1) + " MB/s";
}

async function fetchBandwidth() {
    const el = $("stat-bandwidth-val");
    if (!el) return;

    try {
        const data = await browser.runtime.sendMessage({ action: "native_bandwidth" });
        if (data.type === "bandwidth" && data.data) {
            const sent = data.data.Sent || 0;
            const received = data.data.Received || 0;
            const now = Date.now();
            if (prevBandwidth.sent > 0 || prevBandwidth.received > 0) {
                const elapsed = (now - (fetchBandwidth.lastTime || now)) / 1000;
                if (elapsed > 0) {
                    bandwidthRate.sent = Math.max(0, (sent - prevBandwidth.sent) / elapsed);
                    bandwidthRate.received = Math.max(0, (received - prevBandwidth.received) / elapsed);
                }
            }
            prevBandwidth = { sent, received };
            fetchBandwidth.lastTime = now;
            const rateStr = formatRate(bandwidthRate.received);
            el.textContent = rateStr;
            el.title = `↓ ${formatRate(bandwidthRate.received)} | ↑ ${formatRate(bandwidthRate.sent)}`;
            return;
        }
    } catch (e) {}

    if (!fetchBandwidth._fallbackSet && navigator.connection) {
        fetchBandwidth._fallbackSet = true;
        const downlink = navigator.connection.downlink;
        if (downlink != null && downlink > 0) {
            el.textContent = downlink >= 10 ? downlink.toFixed(0) + " Mbps" : downlink.toFixed(1) + " Mbps";
            el.title = `Connection speed (navigator.connection)`;
        } else {
            el.textContent = "N/A";
            el.title = "Native host not available for bandwidth monitoring";
        }
    } else if (!fetchBandwidth._fallbackSet) {
        fetchBandwidth._fallbackSet = true;
        el.textContent = "N/A";
        el.title = "Native host not available for bandwidth monitoring";
    }
}

/* ==================== BLOCKLIST MANAGER ==================== */

const BlocklistManager = {
    downloaded: {},
    downloading: new Set(),
    errors: {},
    filterCategory: "all",
    filterSearch: "",
    expandedTemplate: null,
    batchTotal: 0,
    batchDone: 0,

    syncFeedDownloaded(url) {
        const normalized = url.replace(/\/+$/, '');
        const entry = BLOCKLIST_CATALOG.find(l => l.url.replace(/\/+$/, '') === normalized);
        if (!entry || this.downloaded[entry.id]) return;
        this.downloaded[entry.id] = { updated: Date.now(), paused: false };
        delete this.errors[entry.id];
        this.saveState();
        this.renderTemplates();
        this.renderList();
        this.renderDownloaded();
        this.updateCountInfo();
    },

    init() {
        this.loadState();
        this.renderTemplates();
        this.renderList();
        this.renderDownloaded();
        if (!this._bound) { this.bindEvents(); this._bound = true; }
        this.updateCountInfo();
    },

    loadState() {
        try {
            const saved = localStorage.getItem("ipwatch_blocklists_downloaded");
            if (saved) {
                const data = JSON.parse(saved);
                this.downloaded = data.downloaded || data;
                this.errors = data.errors || {};
            }
        } catch (e) {}
    },

    saveState() {
        try {
            localStorage.setItem("ipwatch_blocklists_downloaded", JSON.stringify({
                downloaded: this.downloaded,
                errors: this.errors
            }));
        } catch (e) {}
    },

    bindEvents() {
        const catFilter = $("blocklist-category-filter");
        const searchInput = $("blocklist-search");
        const downloadAllBtn = $("blocklist-download-all-btn");
        const updateAllBtn = $("blocklist-update-all-btn");
        const pauseAllBtn = $("blocklist-pause-all-btn");
        const resumeAllBtn = $("blocklist-resume-all-btn");
        const removeAllBtn = $("blocklist-remove-all-btn");

        if (catFilter) catFilter.addEventListener("change", (e) => { this.filterCategory = e.target.value; this.expandedTemplate = null; this.renderList(); this.renderTemplates(); });
        if (searchInput) searchInput.addEventListener("input", (e) => { this.filterSearch = e.target.value.toLowerCase(); this.renderList(); this.renderTemplates(); });
        if (downloadAllBtn) downloadAllBtn.addEventListener("click", () => this.downloadAllVisible());
        if (updateAllBtn) updateAllBtn.addEventListener("click", () => this.updateAll());
        if (pauseAllBtn) pauseAllBtn.addEventListener("click", () => this.pauseAll());
        if (resumeAllBtn) resumeAllBtn.addEventListener("click", () => this.resumeAll());
        if (removeAllBtn) removeAllBtn.addEventListener("click", () => this.removeAll());
    },

    getFilteredLists() {
        return BLOCKLIST_CATALOG.filter(list => {
            if (this.filterCategory !== "all" && list.category !== this.filterCategory) return false;
            if (this.filterSearch && !list.title.toLowerCase().includes(this.filterSearch) && !list.description.toLowerCase().includes(this.filterSearch)) return false;
            return true;
        });
    },

    getDownloadedCount() {
        return Object.keys(this.downloaded).length;
    },

    getTotalRules() {
        let total = 0;
        for (const id in this.downloaded) {
            const dl = this.downloaded[id];
            if (dl.paused) continue;
            if (dl.domains) total += dl.domains.length;
        }
        return total;
    },

    getPausedCount() {
        let count = 0;
        for (const id in this.downloaded) {
            if (this.downloaded[id].paused) count++;
        }
        return count;
    },

    updateCountInfo() {
        const info = $("blocklist-count-info");
        const rules = $("blocklist-total-rules");
        const pausedCount = this.getPausedCount();
        const errorCount = Object.keys(this.errors).length;
        let infoText = `${this.getDownloadedCount()} of ${BLOCKLIST_CATALOG.length} lists downloaded`;
        if (pausedCount) infoText += ` (${pausedCount} paused)`;
        if (errorCount) infoText += ` (${errorCount} failed)`;
        if (this.batchTotal > 0) infoText = `Downloading ${this.batchDone}/${this.batchTotal}...`;
        if (info) info.textContent = infoText;
        if (rules) {
            const cats = this.getCategoryBreakdown();
            if (cats.length) {
                rules.textContent = cats.map(c => `${c.label}: ${c.count.toLocaleString()}`).join(' \u00b7 ');
            } else {
                rules.textContent = `${this.getTotalRules().toLocaleString()} total domains blocked`;
            }
        }
    },

    getCategoryBreakdown() {
        const counts = {};
        for (const id in this.downloaded) {
            const dl = this.downloaded[id];
            if (dl.paused || !dl.domains) continue;
            const catalog = BLOCKLIST_CATALOG.find(l => l.id === id);
            const cat = catalog ? catalog.category : "other";
            counts[cat] = (counts[cat] || 0) + dl.domains.length;
        }
        return Object.entries(counts).map(([cat, count]) => {
            const meta = CATEGORY_META[cat] || { label: cat, icon: "" };
            return { category: cat, label: `${meta.icon} ${meta.label}`, count };
        }).sort((a, b) => b.count - a.count);
    },

    renderTemplates() {
        const container = $("blocklist-templates");
        if (!container) return;

        const filtered = BLOCKLIST_TEMPLATES.filter(t => {
            if (this.filterSearch && !t.name.toLowerCase().includes(this.filterSearch) && !t.description.toLowerCase().includes(this.filterSearch)) return false;
            return true;
        });

        setHTML(container, filtered.map(t => {
            const applied = t.lists.every(id => this.downloaded[id]);
            const allPaused = applied && t.lists.every(id => this.downloaded[id]?.paused);
            const pausedCount = t.lists.filter(id => this.downloaded[id]?.paused).length;
            const isExpanded = this.expandedTemplate === t.id;
            let statusLabel = applied ? 'Update' : 'Apply';
            let pauseNote = '';
            let pauseBtn = '';
            if (pausedCount > 0) {
                pauseNote = `<span class="template-pause-note">${pausedCount} paused</span>`;
            }
            if (applied) {
                if (allPaused) {
                    pauseBtn = `<button class="template-resume-btn" data-template-resume="${t.id}">Resume</button>`;
                } else {
                    pauseBtn = `<button class="template-pause-btn" data-template-pause="${t.id}">Pause</button>`;
                }
            }
            let detailHtml = '';
            if (isExpanded) {
                detailHtml = `<div class="template-detail">${t.lists.map(id => {
                    const catalog = BLOCKLIST_CATALOG.find(l => l.id === id);
                    const name = catalog ? catalog.title : id;
                    const dl = this.downloaded[id];
                    const err = this.errors[id];
                    let badge, action;
                    if (err) {
                        badge = `<span class="template-detail-badge badge-error" title="${escapeHtml(err)}">Error</span>`;
                        action = `<button class="template-detail-action" data-template-dl="${id}">Retry</button>`;
                    } else if (this.downloading.has(id)) {
                        badge = `<span class="template-detail-badge badge-downloading">Downloading...</span>`;
                        action = '';
                    } else if (dl) {
                        if (dl.paused) {
                            badge = `<span class="template-detail-badge badge-paused">Paused</span>`;
                            action = `<button class="template-detail-action" data-detail-resume="${id}">Resume</button>`;
                        } else {
                            const ago = Math.round((Date.now() - dl.updated) / 3600000);
                            badge = `<span class="template-detail-badge badge-ok">${ago < 1 ? 'Just now' : ago + 'h ago'}</span>`;
                            action = `<button class="template-detail-action" data-detail-pause="${id}">Pause</button>`;
                        }
                    } else {
                        badge = `<span class="template-detail-badge badge-missing">Not downloaded</span>`;
                        action = `<button class="template-detail-action" data-template-dl="${id}">Download</button>`;
                    }
                    const cat = catalog ? CATEGORY_META[catalog.category] : null;
                    const dot = cat ? `<span class="blocklist-cat-dot" style="background:${cat.color};display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:4px"></span>` : '';
                    return `<div class="template-detail-item">${dot}${escapeHtml(name)} ${badge} ${action}</div>`;
                }).join('')}</div>`;
            }
            return `
                <div class="template-card ${applied ? 'applied' : ''} ${isExpanded ? 'expanded' : ''}" data-template="${t.id}">
                    <h4>${t.name}</h4>
                    <p>${t.description}</p>
                    <div class="template-meta">
                        <span class="template-count">${t.lists.length} lists</span>
                        ${pauseNote}
                        ${pauseBtn}
                        <button class="template-apply-btn" data-template-apply="${t.id}">${statusLabel}</button>
                    </div>
                    ${detailHtml}
                </div>
            `;
        }).join(""));

        container.querySelectorAll(".template-card").forEach(card => {
            card.addEventListener("click", (e) => {
                if (e.target.closest("button")) return;
                const tid = card.dataset.template;
                this.expandedTemplate = this.expandedTemplate === tid ? null : tid;
                this.renderTemplates();
            });
        });
        container.querySelectorAll("[data-template-apply]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.applyTemplate(btn.dataset.templateApply);
            });
        });
        container.querySelectorAll("[data-template-pause]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.pauseTemplate(btn.dataset.templatePause);
            });
        });
        container.querySelectorAll("[data-template-resume]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.resumeTemplate(btn.dataset.templateResume);
            });
        });
        container.querySelectorAll("[data-template-dl]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.downloadList(btn.dataset.templateDl);
            });
        });
        container.querySelectorAll("[data-detail-pause]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.togglePause(btn.dataset.detailPause);
            });
        });
        container.querySelectorAll("[data-detail-resume]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.togglePause(btn.dataset.detailResume);
            });
        });
    },

    renderList() {
        const container = $("blocklist-list");
        if (!container) return;

        const filtered = this.getFilteredLists();
        if (filtered.length === 0) {
            setHTML(container, `<div class="blocklist-item"><span class="blocklist-item-desc">No blocklists match your filter</span></div>`);
            return;
        }

        setHTML(container, filtered.map(list => {
            const cat = CATEGORY_META[list.category] || { color: "#6b7280", icon: "?" };
            const dl = this.downloaded[list.id];
            const isDownloading = this.downloading.has(list.id);
            let statusClass, statusText, actions;
            let paused = false;

            if (isDownloading) {
                statusClass = "downloading";
                statusText = "Downloading...";
                actions = "";
            } else if (dl) {
                paused = dl.paused;
                statusClass = paused ? "paused" : "downloaded";
                statusText = paused ? "Paused" : `Updated ${new Date(dl.updated).toLocaleDateString()}`;
                actions = `<div class="blocklist-item-actions">
                    <button class="btn-update" data-update="${list.id}">Update</button>
                    <button class="${paused ? 'btn-resume' : 'btn-pause'}" data-pause="${list.id}">${paused ? 'Resume' : 'Pause'}</button>
                    <button class="btn-remove" data-remove="${list.id}">Remove</button>
                </div>`;
            } else {
                const err = this.errors[list.id];
                if (err) {
                    statusClass = "error";
                    statusText = "Error";
                    actions = `<div class="blocklist-item-actions">
                        <button class="btn-download" data-download="${list.id}">Retry</button>
                        <button class="btn-remove" data-remove="${list.id}">Dismiss</button>
                    </div>`;
                } else {
                    statusClass = "downloadable";
                    statusText = "Available";
                    actions = `<div class="blocklist-item-actions">
                        <button class="btn-download" data-download="${list.id}">Download</button>
                    </div>`;
                }
            }

            return `
                <div class="blocklist-item ${paused ? 'paused' : dl ? 'downloaded' : ''} ${isDownloading ? 'downloading' : ''} ${this.errors[list.id] ? 'has-error' : ''}" data-list="${list.id}" title="${this.errors[list.id] ? escapeHtml(this.errors[list.id]) : ''}">
                    <span class="blocklist-cat-dot" style="background:${cat.color}"></span>
                    <div class="blocklist-item-info">
                        <div class="blocklist-item-title">${cat.icon} ${list.title}</div>
                        <div class="blocklist-item-desc">${list.description}</div>
                        <a class="blocklist-item-url" href="${list.url}" target="_blank" rel="noopener noreferrer" title="${list.url}">${list.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').substring(0, 50)}${list.url.length > 60 ? '...' : ''}</a>
                    </div>
                    <div class="blocklist-item-meta">
                        <span class="blocklist-item-rules">${list.rules}</span>
                        <span class="blocklist-item-status ${statusClass}">${statusText}</span>
                    </div>
                    ${actions}
                </div>
            `;
        }).join(""));

        container.querySelectorAll("[data-download]").forEach(btn => {
            btn.addEventListener("click", () => this.downloadList(btn.dataset.download));
        });
        container.querySelectorAll("[data-update]").forEach(btn => {
            btn.addEventListener("click", () => this.downloadList(btn.dataset.update));
        });
        container.querySelectorAll("[data-remove]").forEach(btn => {
            btn.addEventListener("click", () => this.removeList(btn.dataset.remove));
        });
        container.querySelectorAll("[data-pause]").forEach(btn => {
            btn.addEventListener("click", () => this.togglePause(btn.dataset.pause));
        });
    },

    renderDownloaded() {
        const container = $("blocklist-downloaded");
        if (!container) return;

        const downloadedIds = Object.keys(this.downloaded);
        if (downloadedIds.length === 0) {
            setHTML(container, `<div class="blocklist-item"><span class="blocklist-item-desc">No blocklists downloaded yet. Apply a template or download individual lists above.</span></div>`);
            return;
        }

        setHTML(container, downloadedIds.map(id => {
            const dl = this.downloaded[id];
            const catalog = BLOCKLIST_CATALOG.find(l => l.id === id);
            const name = catalog ? catalog.title : id;
            const domainCount = dl.domains ? dl.domains.length : 0;
            const updated = new Date(dl.updated).toLocaleString();
            const paused = dl.paused;
            return `
                <div class="downloaded-item ${paused ? 'paused' : ''}">
                    <span class="downloaded-item-name">${name}${paused ? ' <span class="paused-badge">Paused</span>' : ''}</span>
                    <div class="downloaded-item-details">
                        <span>${domainCount.toLocaleString()} domains</span>
                        <span class="downloaded-item-updated">${updated}</span>
                        <button class="${paused ? 'btn-resume' : 'btn-pause'}" data-pause-dl="${id}" style="font-size:10px;padding:1px 6px;border-radius:2px;border:1px solid rgba(107,114,128,0.3);background:transparent;cursor:pointer">${paused ? 'Resume' : 'Pause'}</button>
                        <button class="btn-remove" data-remove-dl="${id}" style="font-size:10px;padding:1px 4px;border-radius:2px;border:1px solid rgba(239,68,68,0.3);background:transparent;color:#ef4444;cursor:pointer">Remove</button>
                    </div>
                </div>
            `;
        }).join(""));

        container.querySelectorAll("[data-remove-dl]").forEach(btn => {
            btn.addEventListener("click", () => this.removeList(btn.dataset.removeDl));
        });
        container.querySelectorAll("[data-pause-dl]").forEach(btn => {
            btn.addEventListener("click", () => this.togglePause(btn.dataset.pauseDl));
        });
    },

    async applyTemplate(templateId) {
        const template = BLOCKLIST_TEMPLATES.find(t => t.id === templateId);
        if (!template || this._applying) return;
        this._applying = true;

        try {
            const toDownload = template.lists.filter(id => !this.downloaded[id] && !this.downloading.has(id));
            const toUpdate = template.lists.filter(id => this.downloaded[id]);

            if (toDownload.length === 0 && toUpdate.length === 0) return;
            if (toUpdate.length > 0 && toDownload.length === 0) {
                await this.updateLists(toUpdate);
                return;
            }

            this.batchTotal = toDownload.length;
            this.batchDone = 0;
            this.updateCountInfo();

            for (const id of toDownload) {
                await this.downloadList(id);
                this.batchDone++;
                this.updateCountInfo();
            }
        } finally {
            this._applying = false;
            this.batchTotal = 0;
            this.batchDone = 0;
            this.updateCountInfo();
        }
    },

    pauseTemplate(templateId) {
        const template = BLOCKLIST_TEMPLATES.find(t => t.id === templateId);
        if (!template) return;
        for (const id of template.lists) {
            if (this.downloaded[id]) this.downloaded[id].paused = true;
        }
        this.saveState();
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    resumeTemplate(templateId) {
        const template = BLOCKLIST_TEMPLATES.find(t => t.id === templateId);
        if (!template) return;
        for (const id of template.lists) {
            if (this.downloaded[id]) this.downloaded[id].paused = false;
        }
        this.saveState();
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    async downloadList(id) {
        if (this.downloading.has(id)) return;
        delete this.errors[id];
        this.downloading.add(id);
        this.renderList();
        this.renderTemplates();
        this.updateCountInfo();

        try {
            const catalog = BLOCKLIST_CATALOG.find(l => l.id === id);
            if (!catalog) throw new Error("List not found in catalog");

            const resp = await fetch(catalog.url);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();

            const domains = this.parseBlocklist(text);
            const wasPaused = this.downloaded[id]?.paused || false;

            this.downloaded[id] = {
                url: catalog.url,
                updated: Date.now(),
                domains: domains,
                rawSize: text.length,
                paused: wasPaused
            };
            this.saveState();

            await this.syncToDnsFiltering();
        } catch (e) {
            this.errors[id] = e.message || "Download failed";
            console.error(`BlocklistManager: failed to download ${id}:`, e);
        } finally {
            this.downloading.delete(id);
            this.renderList();
            this.renderDownloaded();
            this.renderTemplates();
            this.updateCountInfo();
        }
    },

    parseBlocklist(text) {
        const domains = new Set();
        const lines = text.split("\n");
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("!") || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
            if (trimmed.startsWith("||")) {
                const domain = trimmed.replace("||", "").split("^")[0].split("$")[0].split("*")[0].trim();
                if (domain && !domain.includes("/") && !domain.includes("?")) domains.add(domain);
            } else if (trimmed.startsWith("0.0.0.0") || trimmed.startsWith("127.0.0.1")) {
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 2) {
                    const domain = parts[1];
                    if (domain !== "localhost" && domain !== "localhost.localdomain" && domain !== "broadcasthost" && !domain.startsWith("0.0.0.0") && !domain.startsWith("127.0.0.1")) {
                        domains.add(domain);
                    }
                }
            } else if (trimmed.includes(".")) {
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 2) {
                    const domain = parts[1];
                    if (domain && domain.includes(".")) domains.add(domain);
                } else if (parts.length === 1 && trimmed.includes(".")) {
                    domains.add(trimmed);
                }
            }
        }
        return Array.from(domains);
    },

    async syncToDnsFiltering() {
        const activeDomains = new Set();
        const allDownloaded = new Set();
        for (const id in this.downloaded) {
            const dl = this.downloaded[id];
            if (dl.domains) {
                for (const d of dl.domains) {
                    allDownloaded.add(d);
                    if (!dl.paused) activeDomains.add(d);
                }
            }
        }

        const nonDownloaded = dnsFilteringDomains.filter(d => !allDownloaded.has(d));
        const merged = new Set(nonDownloaded);
        for (const d of activeDomains) merged.add(d);

        dnsFilteringDomains = Array.from(merged);
        try {
            localStorage.setItem("ipwatch_dns_filtering_domains", JSON.stringify(dnsFilteringDomains));
        } catch (e) {}

        try {
            await browser.runtime.sendMessage({
                action: "update_blocklist",
                domains: dnsFilteringDomains.slice(0, 100000),
                ips: [], // IPs no longer used (parser now extracts domains)
                whitelist: [...whitelistedDomains],
                enabled: dnsFilteringEnabled
            });
        } catch (e) {}
    },

    removeList(id) {
        const removedDomains = new Set(this.downloaded[id]?.domains || []);
        delete this.downloaded[id];
        delete this.errors[id];
        this.saveState();
        dnsFilteringDomains = dnsFilteringDomains.filter(d => !removedDomains.has(d));
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    async downloadAllVisible() {
        const filtered = this.getFilteredLists();
        const toDownload = filtered.filter(l => !this.downloaded[l.id] && !this.downloading.has(l.id));
        if (!toDownload.length) return;
        this.batchTotal = toDownload.length;
        this.batchDone = 0;
        this.updateCountInfo();
        for (const list of toDownload) {
            await this.downloadList(list.id);
            this.batchDone++;
            this.updateCountInfo();
        }
        this.batchTotal = 0;
        this.batchDone = 0;
        this.updateCountInfo();
    },

    async updateAll() {
        const toUpdate = Object.keys(this.downloaded);
        await this.updateLists(toUpdate);
    },

    async updateLists(ids) {
        if (!ids.length) return;
        this.batchTotal = ids.length;
        this.batchDone = 0;
        this.updateCountInfo();
        for (const id of ids) {
            await this.downloadList(id);
            this.batchDone++;
            this.updateCountInfo();
        }
        this.batchTotal = 0;
        this.batchDone = 0;
        this.updateCountInfo();
    },

    removeAll() {
        const removedDomains = new Set();
        for (const id in this.downloaded) {
            if (this.downloaded[id].domains) {
                for (const d of this.downloaded[id].domains) {
                    removedDomains.add(d);
                }
            }
            delete this.downloaded[id];
        }
        this.errors = {};
        this.saveState();
        dnsFilteringDomains = dnsFilteringDomains.filter(d => !removedDomains.has(d));
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    togglePause(id) {
        if (!this.downloaded[id]) return;
        this.downloaded[id].paused = !this.downloaded[id].paused;
        this.saveState();
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    pauseAll() {
        for (const id in this.downloaded) {
            this.downloaded[id].paused = true;
        }
        this.saveState();
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    },

    resumeAll() {
        for (const id in this.downloaded) {
            this.downloaded[id].paused = false;
        }
        this.saveState();
        this.syncToDnsFiltering();
        this.renderList();
        this.renderDownloaded();
        this.renderTemplates();
        this.updateCountInfo();
    }
};

/* ==================== TOPOLOGY VIEW ==================== */

const Topology = {
    canvas: null,
    ctx: null,
    nodes: [],
    edges: [],
    clusters: [],
    hoveredNode: null,
    draggedNode: null,
    panOffset: { x: 0, y: 0 },
    zoom: 1,
    isPanning: false,
    lastMouse: { x: 0, y: 0 },
    animFrame: null,
    layout: "force",
    groupBy: "process",

    init() {
        if (this._ready) return;
        this.canvas = $("topology-canvas");
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext("2d");
        this.resize();
        this.bindEvents();
        this._ready = true;
        this.startAnimation();
    },

    resize() {
        if (!this.canvas) return;
        const container = this.canvas.parentElement;
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = container.clientWidth * dpr;
        this.canvas.height = container.clientHeight * dpr;
        this.canvas.style.width = container.clientWidth + "px";
        this.canvas.style.height = container.clientHeight + "px";
        this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        this.width = container.clientWidth;
        this.height = container.clientHeight;
    },

    bindEvents() {
        if (!this.canvas) return;
        this.canvas.addEventListener("mousemove", (e) => this.onMouseMove(e));
        this.canvas.addEventListener("mousedown", (e) => this.onMouseDown(e));
        this.canvas.addEventListener("mouseup", (e) => this.onMouseUp(e));
        this.canvas.addEventListener("mouseleave", (e) => this.onMouseLeave(e));
        this.canvas.addEventListener("wheel", (e) => this.onWheel(e), { passive: false });
        window.addEventListener("resize", () => this.resize());

        const layoutSel = $("topology-layout");
        const groupSel = $("topology-group-by");
        const resetBtn = $("topology-reset-btn");
        const exportBtn = $("topology-export-btn");

        if (layoutSel) layoutSel.addEventListener("change", (e) => { this.layout = e.target.value; this.rebuild(); });
        if (groupSel) groupSel.addEventListener("change", (e) => { this.groupBy = e.target.value; this.rebuild(); });
        if (resetBtn) resetBtn.addEventListener("click", () => { this.panOffset = { x: 0, y: 0 }; this.zoom = 1; this.rebuild(); });
        if (exportBtn) exportBtn.addEventListener("click", () => this.exportPNG());
    },

    rebuild() {
        this.hoveredNode = null;
        this.hideTooltip();
        this.computeGraph();
        this.applyLayout();
        this.updateStats();
        this.render();
    },

    computeGraph() {
        const nodeMap = new Map();
        const edgeMap = new Map();
        this.clusters = [];
        const now = Date.now();
        const prevIds = new Set(this.nodes.map(n => n.id));

        const localNodeId = "__local__";
        const hadLocal = prevIds.has(localNodeId);
        nodeMap.set(localNodeId, {
            id: localNodeId,
            label: "This PC",
            type: "local",
            x: this.width / 2,
            y: this.height / 2,
            vx: 0, vy: 0,
            radius: 18,
            risk: "safe",
            connections: 0,
            birthTime: hadLocal ? (this.nodes.find(n => n.id === localNodeId).birthTime || now) : now
        });

        for (const conn of connections) {
            if (conn.remote_ip === "0.0.0.0" || conn.remote_ip === "127.0.0.1") continue;

            const remoteId = `remote:${conn.remote_ip}`;
            if (!nodeMap.has(remoteId)) {
                const prevNode = this.nodes.find(n => n.id === remoteId);
                nodeMap.set(remoteId, {
                    id: remoteId,
                    label: conn.remote_ip,
                    type: "remote",
                    ip: conn.remote_ip,
                    port: conn.remote_port,
                    process: conn.process_name || "Unknown",
                    service: conn.service || "",
                    risk: conn.risk_level || "unknown",
                    state: conn.state,
                    x: prevNode ? prevNode.x : this.width / 2 + (Math.random() - 0.5) * 200,
                    y: prevNode ? prevNode.y : this.height / 2 + (Math.random() - 0.5) * 200,
                    vx: prevNode ? prevNode.vx : (Math.random() - 0.5) * 4,
                    vy: prevNode ? prevNode.vy : (Math.random() - 0.5) * 4,
                    radius: 10,
                    connections: 0,
                    blocked: false,
                    birthTime: prevNode ? (prevNode.birthTime || now) : now
                });
            }
            const remoteNode = nodeMap.get(remoteId);
            remoteNode.connections++;
            remoteNode.port = conn.remote_port || remoteNode.port;
            remoteNode.state = conn.state || remoteNode.state;
            if (conn.blocked) remoteNode.blocked = true;

            remoteNode.radius = remoteNode.connections <= 1 ? 10 :
                remoteNode.connections <= 5 ? 14 :
                remoteNode.connections <= 15 ? 18 : 22;

            const edgeKey = `${localNodeId}-${remoteId}`;
            if (!edgeMap.has(edgeKey)) {
                edgeMap.set(edgeKey, {
                    source: localNodeId,
                    target: remoteId,
                    state: conn.state,
                    protocol: conn.protocol,
                    count: 0
                });
            }
            edgeMap.get(edgeKey).count++;

            if (this.groupBy !== "none") {
                let clusterKey, clusterLabel;
                switch (this.groupBy) {
                    case "process":
                        clusterKey = `proc:${conn.process_name || "Unknown"}`;
                        clusterLabel = conn.process_name || "Unknown";
                        break;
                    case "service":
                        clusterKey = `svc:${conn.service || "Unknown"}`;
                        clusterLabel = conn.service || "Unknown";
                        break;
                    case "risk":
                        clusterKey = `risk:${conn.risk_level || "unknown"}`;
                        clusterLabel = (conn.risk_level || "unknown").toUpperCase();
                        break;
                    default:
                        clusterKey = "all";
                        clusterLabel = "All";
                }

                if (!nodeMap.has(clusterKey)) {
                    const prevCluster = this.nodes.find(n => n.id === clusterKey);
                    nodeMap.set(clusterKey, {
                        id: clusterKey,
                        label: clusterLabel,
                        type: "cluster",
                        x: prevCluster ? prevCluster.x : this.width / 2 + (Math.random() - 0.5) * 300,
                        y: prevCluster ? prevCluster.y : this.height / 2 + (Math.random() - 0.5) * 300,
                        vx: prevCluster ? prevCluster.vx : (Math.random() - 0.5) * 4,
                        vy: prevCluster ? prevCluster.vy : (Math.random() - 0.5) * 4,
                        radius: 24,
                        risk: "safe",
                        connections: 0,
                        isCluster: true,
                        birthTime: prevCluster ? prevCluster.birthTime : now
                    });
                    this.clusters.push(clusterKey);
                }
                const clusterNode = nodeMap.get(clusterKey);
                clusterNode.connections++;

                const clusterEdgeKey = `${remoteId}-${clusterKey}`;
                if (!edgeMap.has(clusterEdgeKey)) {
                    edgeMap.set(clusterEdgeKey, {
                        source: remoteId,
                        target: clusterKey,
                        state: "cluster",
                        protocol: "",
                        count: 0
                    });
                }
                edgeMap.get(clusterEdgeKey).count++;
            }
        }

        this.nodes = Array.from(nodeMap.values());
        this.edges = Array.from(edgeMap.values());
    },

    applyLayout() {
        if (this.layout === "radial") {
            this.applyRadialLayout();
        } else if (this.layout === "hierarchical") {
            this.applyHierarchicalLayout();
        }
    },

    applyRadialLayout() {
        const cx = this.width / 2;
        const cy = this.height / 2;
        const local = this.nodes.find(n => n.id === "__local__");
        if (local) { local.x = cx; local.y = cy; }

        const remotes = this.nodes.filter(n => n.type === "remote");
        const clusters = this.nodes.filter(n => n.isCluster);

        const clusterRadius = Math.min(this.width, this.height) * 0.35;
        clusters.forEach((c, i) => {
            const angle = (i / Math.max(clusters.length, 1)) * Math.PI * 2 - Math.PI / 2;
            c.x = cx + Math.cos(angle) * clusterRadius;
            c.y = cy + Math.sin(angle) * clusterRadius;
        });

        const remoteRadius = Math.min(this.width, this.height) * 0.2;
        remotes.forEach((r, i) => {
            const angle = (i / Math.max(remotes.length, 1)) * Math.PI * 2 - Math.PI / 2;
            r.x = cx + Math.cos(angle) * remoteRadius;
            r.y = cy + Math.sin(angle) * remoteRadius;
        });
    },

    applyHierarchicalLayout() {
        const cx = this.width / 2;
        const local = this.nodes.find(n => n.id === "__local__");
        if (local) { local.x = cx; local.y = 60; }

        const clusters = this.nodes.filter(n => n.isCluster);
        const remotes = this.nodes.filter(n => n.type === "remote");

        const clusterY = this.height * 0.4;
        const clusterSpacing = this.width / (clusters.length + 1);
        clusters.forEach((c, i) => {
            c.x = clusterSpacing * (i + 1);
            c.y = clusterY;
        });

        const remoteY = this.height * 0.75;
        const remoteSpacing = this.width / (remotes.length + 1);
        remotes.forEach((r, i) => {
            r.x = remoteSpacing * (i + 1);
            r.y = remoteY;
        });
    },

    simulate() {
        if (this.layout !== "force") return;

        const alpha = 0.3;
        const damping = 0.85;
        const repulsion = 8000;
        const attraction = 0.005;
        const centerGravity = 0.01;
        const cx = this.width / 2;
        const cy = this.height / 2;

        for (let i = 0; i < this.nodes.length; i++) {
            const a = this.nodes[i];
            if (a === this.draggedNode) continue;

            let fx = 0, fy = 0;

            for (let j = 0; j < this.nodes.length; j++) {
                if (i === j) continue;
                const b = this.nodes[j];
                let dx = a.x - b.x;
                let dy = a.y - b.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                let force = repulsion / (dist * dist);
                fx += (dx / dist) * force;
                fy += (dy / dist) * force;
            }

            for (const edge of this.edges) {
                if (edge.source === a.id || edge.target === a.id) {
                    const other = this.nodes.find(n => n.id === (edge.source === a.id ? edge.target : edge.source));
                    if (other) {
                        let dx = other.x - a.x;
                        let dy = other.y - a.y;
                        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                        fx += dx * attraction;
                        fy += dy * attraction;
                    }
                }
            }

            fx += (cx - a.x) * centerGravity;
            fy += (cy - a.y) * centerGravity;

            a.vx = (a.vx + fx * alpha) * damping;
            a.vy = (a.vy + fy * alpha) * damping;
            a.x += a.vx;
            a.y += a.vy;

            const margin = a.radius + 10;
            a.x = Math.max(margin, Math.min(this.width - margin, a.x));
            a.y = Math.max(margin, Math.min(this.height - margin, a.y));
        }
    },

    render() {
        if (!this.ctx) return;
        const ctx = this.ctx;
        ctx.clearRect(0, 0, this.width, this.height);
        ctx.save();
        ctx.translate(this.panOffset.x, this.panOffset.y);
        ctx.scale(this.zoom, this.zoom);

        this.drawEdges(ctx);
        this.drawNodes(ctx);
        this.drawHoverEffect(ctx);

        ctx.restore();
    },

    drawEdges(ctx) {
        for (const edge of this.edges) {
            const source = this.nodes.find(n => n.id === edge.source);
            const target = this.nodes.find(n => n.id === edge.target);
            if (!source || !target) continue;

            ctx.beginPath();
            ctx.moveTo(source.x, source.y);
            ctx.lineTo(target.x, target.y);

            const thick = edge.count <= 1 ? 1.5 :
                edge.count <= 3 ? 3 :
                edge.count <= 8 ? 5 : 7;

            let color;
            const isHoveredEdge = this.hoveredNode && (edge.source === this.hoveredNode.id || edge.target === this.hoveredNode.id);
            switch (edge.state) {
                case "ESTABLISHED": color = isHoveredEdge ? "rgba(34, 197, 94, 0.95)" : "rgba(34, 197, 94, 0.6)"; break;
                case "LISTENING": color = isHoveredEdge ? "rgba(59, 130, 246, 0.95)" : "rgba(59, 130, 246, 0.6)"; break;
                case "cluster": color = isHoveredEdge ? "rgba(139, 92, 246, 0.7)" : "rgba(139, 92, 246, 0.3)"; break;
                default: color = isHoveredEdge ? "rgba(245, 158, 11, 0.8)" : "rgba(245, 158, 11, 0.4)";
            }

            ctx.strokeStyle = color;
            ctx.lineWidth = thick;
            ctx.stroke();

            if (isHoveredEdge && thick >= 3) {
                ctx.save();
                const mx = (source.x + target.x) / 2;
                const my = (source.y + target.y) / 2;
                ctx.fillStyle = "rgba(0,0,0,0.75)";
                ctx.fillRect(mx - 12, my - 7, 24, 14);
                ctx.fillStyle = "#fff";
                ctx.font = "bold 8px sans-serif";
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillText(edge.count.toString(), mx, my);
                ctx.restore();
            }
        }
    },

    drawNodes(ctx) {
        const now = Date.now();
        for (const node of this.nodes) {
            const isHovered = node === this.hoveredNode;
            const isConnected = this.hoveredNode && this.edges.some(e =>
                (e.source === this.hoveredNode.id && e.target === node.id) ||
                (e.target === this.hoveredNode.id && e.source === node.id)
            );
            const dimmed = this.hoveredNode && !isHovered && !isConnected;

            ctx.save();
            if (dimmed) ctx.globalAlpha = 0.2;

            let fillColor, strokeColor;
            switch (node.type) {
                case "local":
                    fillColor = "#8b5cf6";
                    strokeColor = "#a78bfa";
                    break;
                case "cluster":
                    fillColor = "rgba(139, 92, 246, 0.15)";
                    strokeColor = "#8b5cf6";
                    break;
                default:
                    const riskColors = {
                        safe: "#22c55e", low: "#3b82f6", medium: "#f59e0b",
                        high: "#f97316", critical: "#ef4444", unknown: "#6b7280"
                    };
                    fillColor = riskColors[node.risk] || "#6b7280";
                    strokeColor = fillColor;
            }

            if (node.type === "remote" && node.blocked) {
                strokeColor = "#ef4444";
            }

            const age = now - (node.birthTime || now);
            const isNew = age < 2000 && node.connections > 0;

            if (isNew) {
                ctx.beginPath();
                const pulseRadius = node.radius + 8 + (1 - age / 2000) * 10;
                ctx.arc(node.x, node.y, pulseRadius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(255, 255, 255, ${0.15 * (1 - age / 2000)})`;
                ctx.fill();
            }

            ctx.beginPath();
            if (node.isCluster) {
                ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
                ctx.fillStyle = fillColor;
                ctx.fill();
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            } else {
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            }
            ctx.fillStyle = fillColor;
            ctx.fill();
            ctx.strokeStyle = isHovered ? "#fff" : strokeColor;
            ctx.lineWidth = isHovered ? 3 : 1.5;

            if (node.type === "remote" && node.blocked && !isHovered) {
                ctx.setLineDash([4, 4]);
            }

            ctx.stroke();
            ctx.setLineDash([]);

            ctx.fillStyle = node.isCluster ? "#c4b5fd" : "#e5e7eb";
            ctx.font = node.isCluster ? "bold 9px sans-serif" : "8px sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            const label = node.label.length > 15 ? node.label.substring(0, 15) + "..." : node.label;
            ctx.fillText(label, node.x, node.y + node.radius + 6);

            if (node.connections > 1 && !node.isCluster) {
                ctx.fillStyle = "#f59e0b";
                ctx.font = "bold 8px sans-serif";
                ctx.textBaseline = "bottom";
                ctx.fillText(node.connections.toString(), node.x + node.radius - 2, node.y - node.radius + 2);
            }

            ctx.restore();
        }
    },

    drawHoverEffect(ctx) {
        if (!this.hoveredNode) return;
        const node = this.hoveredNode;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 12, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
    },

    getNodeAt(mx, my) {
        const x = (mx - this.panOffset.x) / this.zoom;
        const y = (my - this.panOffset.y) / this.zoom;
        for (let i = this.nodes.length - 1; i >= 0; i--) {
            const n = this.nodes[i];
            const dx = x - n.x;
            const dy = y - n.y;
            const hitRadius = n.isCluster ? n.radius + 8 : n.radius;
            if (dx * dx + dy * dy <= hitRadius * hitRadius) return n;
        }
        return null;
    },

    onMouseMove(e) {
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;

        if (this.draggedNode) {
            this.draggedNode.x = (mx - this.panOffset.x) / this.zoom;
            this.draggedNode.y = (my - this.panOffset.y) / this.zoom;
            this.draggedNode.vx = 0;
            this.draggedNode.vy = 0;
            return;
        }

        if (this.isPanning) {
            this.panOffset.x += mx - this.lastMouse.x;
            this.panOffset.y += my - this.lastMouse.y;
            this.lastMouse = { x: mx, y: my };
            return;
        }

        const node = this.getNodeAt(mx, my);
        this.hoveredNode = node;
        this.showTooltip(node, mx, my);
        this.canvas.style.cursor = node ? "pointer" : "grab";
    },

    onMouseDown(e) {
        this._mouseDownPos = { x: e.clientX, y: e.clientY };
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const node = this.getNodeAt(mx, my);

        if (node) {
            this.draggedNode = node;
            this.canvas.style.cursor = "grabbing";
        } else {
            this.isPanning = true;
            this.lastMouse = { x: mx, y: my };
            this.canvas.style.cursor = "grabbing";
        }
    },

    onMouseUp(e) {
        if (!this._mouseDownPos) return;
        const dx = e.clientX - this._mouseDownPos.x;
        const dy = e.clientY - this._mouseDownPos.y;
        const wasDragged = Math.abs(dx) > 3 || Math.abs(dy) > 3;
        const clickedNode = this.hoveredNode;
        this.draggedNode = null;
        this.isPanning = false;
        this.canvas.style.cursor = this.hoveredNode ? "pointer" : "grab";

        if (!wasDragged && clickedNode && clickedNode.type === "remote") {
            if (currentView !== "grouped") {
                currentView = "grouped";
                document.querySelectorAll(".view-btn").forEach((b) => b.classList.remove("active"));
                document.querySelectorAll(".view-panel").forEach((p) => p.classList.remove("active"));
                const vbtn = document.querySelector(`.view-btn[data-view="grouped"]`);
                if (vbtn) vbtn.classList.add("active");
                const panel = $("grouped-view");
                if (panel) panel.classList.add("active");
                render();
            }
            openDetail(clickedNode.ip, clickedNode.port, "tcp", null);
        }
    },

    onMouseLeave() {
        this.hoveredNode = null;
        this.draggedNode = null;
        this.isPanning = false;
        this.hideTooltip();
    },

    onWheel(e) {
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        this.zoom = Math.max(0.2, Math.min(5, this.zoom * delta));
    },

    showTooltip(node, mx, my) {
        const tooltip = $("topology-tooltip");
        const content = $("topology-tooltip-content");
        if (!tooltip || !content) return;

        if (!node) {
            this.hideTooltip();
            return;
        }

        if (node === this._tooltipNode) {
            this._positionTooltip(mx, my, tooltip);
            return;
        }
        this._tooltipNode = node;

        let html = `<div class="tooltip-title">${node.label}</div>`;
        if (node.type === "remote") {
            html += `<div class="tooltip-row"><span class="tooltip-label">IP:</span><span class="tooltip-value">${node.ip}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">Port:</span><span class="tooltip-value">${node.port}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">Process:</span><span class="tooltip-value">${node.process}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">Service:</span><span class="tooltip-value">${node.service}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">Risk:</span><span class="tooltip-value">${node.risk}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">State:</span><span class="tooltip-value">${node.state}</span></div>`;
            html += `<div class="tooltip-row"><span class="tooltip-label">Connections:</span><span class="tooltip-value">${node.connections}</span></div>`;
            if (node.blocked) {
                html += `<div class="tooltip-row"><span class="tooltip-label">Blocked:</span><span class="tooltip-value" style="color:#ef4444">Yes</span></div>`;
            }
            html += `<div class="tooltip-row" style="margin-top:4px;color:var(--text-dim);font-size:8px">Click to inspect</div>`;
        } else if (node.isCluster) {
            html += `<div class="tooltip-row"><span class="tooltip-label">Connections:</span><span class="tooltip-value">${node.connections}</span></div>`;
        } else if (node.type === "local") {
            html += `<div class="tooltip-row"><span class="tooltip-label">Connections:</span><span class="tooltip-value">${node.connections}</span></div>`;
        }

        setHTML(content, html);
        tooltip.classList.remove("hidden");
        this._positionTooltip(mx, my, tooltip);
    },

    _positionTooltip(mx, my, tooltip) {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        let tx = mx + 15;
        let ty = my - 10;
        if (tx + 250 > rect.width) tx = mx - 260;
        if (ty + 150 > rect.height) ty = my - 150;
        tooltip.style.left = tx + "px";
        tooltip.style.top = ty + "px";
    },

    hideTooltip() {
        this._tooltipNode = null;
        const tooltip = $("topology-tooltip");
        if (tooltip) tooltip.classList.add("hidden");
    },

    updateStats() {
        const nc = $("topo-node-count");
        const ec = $("topo-edge-count");
        const cc = $("topo-cluster-count");
        if (nc) nc.textContent = `${this.nodes.length} nodes`;
        if (ec) ec.textContent = `${this.edges.length} edges`;
        if (cc) cc.textContent = `${this.clusters.length} clusters`;
    },

    startAnimation() {
        if (this.animFrame) cancelAnimationFrame(this.animFrame);
        const loop = () => {
            this.animFrame = requestAnimationFrame(loop);
            if (currentView !== "topology") return;
            this.simulate();
            this.render();
        };
        this.animFrame = requestAnimationFrame(loop);
    },

    exportPNG() {
        if (!this.canvas) return;
        const link = document.createElement("a");
        link.download = `ipwatch-topology-${Date.now()}.png`;
        link.href = this.canvas.toDataURL("image/png");
        link.click();
    },

    update() {
        this.rebuild();
    }
};
