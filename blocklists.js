const BLOCKLIST_CATALOG = [
    {
        id: "ubo-filters-ads",
        category: "ads",
        title: "uBlock filters – Ads",
        description: "Official uBlock ad filters, optimized for uBO syntax",
        url: "https://ublockorigin.github.io/uAssets/filters/filters.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~150K",
        enabled: false
    },
    {
        id: "easylist",
        category: "ads",
        title: "EasyList",
        description: "The most popular ad blocking filter list",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt",
        home: "https://easylist.to/",
        rules: "~95K",
        enabled: false
    },
    {
        id: "adguard-ads",
        category: "ads",
        title: "AdGuard – Ads",
        description: "AdGuard's comprehensive ad blocking filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~55K",
        enabled: false
    },
    {
        id: "adguard-mobile-ads",
        category: "ads",
        title: "AdGuard – Mobile Ads",
        description: "Mobile-specific ad blocking rules",
        url: "https://filters.adtidy.org/extension/ublock/filters/11.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~12K",
        enabled: false
    },
    {
        id: "peter-lowe",
        category: "ads",
        title: "Peter Lowe's Ad & Tracking Server List",
        description: "Curated list of ad and tracking servers, low false positives",
        url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext",
        home: "https://pgl.yoyo.org/adservers/",
        rules: "~4.5K",
        enabled: false
    },
    {
        id: "dan-pollock",
        category: "ads",
        title: "Dan Pollock's hosts file",
        description: "Long-standing hosts file blocking ads and trackers",
        url: "https://someonewhocares.org/hosts/hosts",
        home: "https://someonewhocares.org/hosts/",
        rules: "~28K",
        enabled: false
    },
    {
        id: "ubo-privacy",
        category: "privacy",
        title: "uBlock filters – Privacy",
        description: "uBlock privacy filters for tracking protection",
        url: "https://ublockorigin.github.io/uAssets/filters/privacy.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~15K",
        enabled: false
    },
    {
        id: "easyprivacy",
        category: "privacy",
        title: "EasyPrivacy",
        description: "EasyList's privacy-focused filter list",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt",
        home: "https://easylist.to/",
        rules: "~35K",
        enabled: false
    },
    {
        id: "adguard-tracking",
        category: "privacy",
        title: "AdGuard Tracking Protection",
        description: "AdGuard's dedicated tracking protection filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/3.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~25K",
        enabled: false
    },
    {
        id: "adguard-url-tracking",
        category: "privacy",
        title: "AdGuard/uBO – URL Tracking Protection",
        description: "Blocks URL tracking parameters like ?utm_source, ?fbclid",
        url: "https://ublockorigin.github.io/uAssets/filters/privacy-removeparam.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~8K",
        enabled: false
    },
    {
        id: "fanboy-antifacebook",
        category: "privacy",
        title: "Fanboy – Anti-Facebook",
        description: "Blocks Facebook tracking pixels and social widgets",
        url: "https://secure.fanboy.co.nz/fanboy-antifacebook.txt",
        home: "https://github.com/ryanbr/fanboy-adblock",
        rules: "~3K",
        enabled: false
    },
    {
        id: "block-lan",
        category: "privacy",
        title: "Block Outsider Intrusion into LAN",
        description: "Prevents websites from scanning your local network",
        url: "https://ublockorigin.github.io/uAssets/filters/lan-block.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~200",
        enabled: false
    },
    {
        id: "ubo-badware",
        category: "security",
        title: "uBlock filters – Badware risks",
        description: "Blocks known malware distribution and phishing sites",
        url: "https://ublockorigin.github.io/uAssets/filters/badware.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~12K",
        enabled: false
    },
    {
        id: "urlhaus",
        category: "security",
        title: "Online Malicious URL Blocklist (URLHaus)",
        description: "Real-time malicious URL blocklist by abuse.ch",
        url: "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-ag-online.txt",
        home: "https://gitlab.com/malware-filter/urlhaus-filter",
        rules: "~30K",
        enabled: false
    },
    {
        id: "phishing-filter",
        category: "security",
        title: "Phishing URL Blocklist",
        description: "Continuously updated phishing domain blocklist",
        url: "https://malware-filter.gitlab.io/phishing-filter/phishing-filter.txt",
        home: "https://gitlab.com/malware-filter/phishing-filter",
        rules: "~50K",
        enabled: false
    },
    {
        id: "stevenblack-unified",
        category: "security",
        title: "StevenBlack Unified Hosts (Ads + Malware)",
        description: "Consolidated hosts file from multiple curated sources",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        home: "https://github.com/StevenBlack/hosts",
        rules: "~92K",
        enabled: false
    },
    {
        id: "oisd-small",
        category: "security",
        title: "OISD Small",
        description: "Highly curated low-breakage DNS blocklist, zero false positives",
        url: "https://small.oisd.nl/",
        home: "https://oisd.nl/",
        rules: "~56K",
        enabled: false
    },
    {
        id: "oisd-big",
        category: "security",
        title: "OISD Big",
        description: "Massive combined DNS blocklist, aggressive but reliable",
        url: "https://big.oisd.nl/",
        home: "https://oisd.nl/",
        rules: "~330K",
        enabled: false
    },
    {
        id: "hagezi-light",
        category: "security",
        title: "HaGeZi Multi Light",
        description: "Lightweight multi-purpose DNS blocklist",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~55K",
        enabled: false
    },
    {
        id: "hagezi-normal",
        category: "security",
        title: "HaGeZi Multi Normal",
        description: "Balanced multi-purpose DNS blocklist (recommended)",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~159K",
        enabled: false
    },
    {
        id: "hagezi-pro",
        category: "security",
        title: "HaGeZi Multi PRO",
        description: "Extended protection, larger coverage (recommended)",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~150K",
        enabled: false
    },
    {
        id: "hagezi-tif",
        category: "security",
        title: "HaGeZi Threat Intelligence Feeds",
        description: "Malware, phishing, scam, spam from threat intel feeds",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~970K",
        enabled: false
    },
    {
        id: "ubo-quick-fixes",
        category: "unbreak",
        title: "uBlock filters – Quick fixes",
        description: "Temporary fixes for sites broken by filter lists",
        url: "https://ublockorigin.github.io/uAssets/filters/quick-fixes.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~5K",
        enabled: false
    },
    {
        id: "ubo-unbreak",
        category: "unbreak",
        title: "uBlock filters – Unbreak",
        description: "Filters to fix sites broken by other lists",
        url: "https://ublockorigin.github.io/uAssets/filters/unbreak.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~8K",
        enabled: false
    },
    {
        id: "ubo-annoyances",
        category: "annoyances",
        title: "uBlock filters – Annoyances",
        description: "Blocks anti-adblock messages and other annoyances",
        url: "https://ublockorigin.github.io/uAssets/filters/annoyances.min.txt",
        home: "https://github.com/uBlockOrigin/uAssets",
        rules: "~20K",
        enabled: false
    },
    {
        id: "easylist-cookies",
        category: "annoyances",
        title: "EasyList/uBO – Cookie Notices",
        description: "Hides GDPR cookie consent banners",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-cookies.txt",
        home: "https://easylist.to/",
        rules: "~10K",
        enabled: false
    },
    {
        id: "adguard-cookies",
        category: "annoyances",
        title: "AdGuard – Cookie Notices",
        description: "AdGuard's cookie consent filter list",
        url: "https://filters.adtidy.org/extension/ublock/filters/18.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~8K",
        enabled: false
    },
    {
        id: "easylist-social",
        category: "annoyances",
        title: "EasyList – Social Widgets",
        description: "Blocks Facebook, Twitter, and other social media widgets",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-social.txt",
        home: "https://easylist.to/",
        rules: "~5K",
        enabled: false
    },
    {
        id: "adguard-social",
        category: "annoyances",
        title: "AdGuard – Social Widgets",
        description: "AdGuard's social widget blocking filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/4.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~4K",
        enabled: false
    },
    {
        id: "easylist-newsletters",
        category: "annoyances",
        title: "EasyList – Newsletter Notices",
        description: "Hides newsletter subscription popups",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-newsletters.txt",
        home: "https://easylist.to/",
        rules: "~2K",
        enabled: false
    },
    {
        id: "easylist-notifications",
        category: "annoyances",
        title: "EasyList – Notifications",
        description: "Blocks browser notification permission prompts",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-notifications.txt",
        home: "https://easylist.to/",
        rules: "~3K",
        enabled: false
    },
    {
        id: "adguard-popup-overlays",
        category: "annoyances",
        title: "AdGuard – Popup Overlays",
        description: "Blocks popup overlays and interstitial ads",
        url: "https://filters.adtidy.org/extension/ublock/filters/19.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~6K",
        enabled: false
    },
    {
        id: "adguard-mobile-app-banners",
        category: "annoyances",
        title: "AdGuard – Mobile App Banners",
        description: "Hides 'Get our app' banners and prompts",
        url: "https://filters.adtidy.org/extension/ublock/filters/20.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~4K",
        enabled: false
    },
    {
        id: "easylist-ai",
        category: "annoyances",
        title: "EasyList – AI Widgets",
        description: "Blocks AI chat widgets and assistant popups",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-ai.txt",
        home: "https://easylist.to/",
        rules: "~1K",
        enabled: false
    },
    {
        id: "easylist-chat",
        category: "annoyances",
        title: "EasyList – Chat Widgets",
        description: "Blocks live chat and support widgets",
        url: "https://ublockorigin.github.io/uAssets/thirdparties/easylist-chat.txt",
        home: "https://easylist.to/",
        rules: "~2K",
        enabled: false
    },
    {
        id: "regional-china",
        category: "regional",
        title: "🇨🇳 AdGuard Chinese (中文)",
        description: "Chinese language ad blocking filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/224.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~15K",
        enabled: false
    },
    {
        id: "regional-germany",
        category: "regional",
        title: "🇩🇪 EasyList Germany",
        description: "German, Swiss, Austrian site filters",
        url: "https://easylist.to/easylistgermany/easylistgermany.txt",
        home: "https://forums.lanik.us/viewforum.php?f=90",
        rules: "~8K",
        enabled: false
    },
    {
        id: "regional-france",
        category: "regional",
        title: "🇫🇷 AdGuard Français",
        description: "French and French Canadian filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/16.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~6K",
        enabled: false
    },
    {
        id: "regional-japan",
        category: "regional",
        title: "🇯🇵 AdGuard Japanese",
        description: "Japanese language ad blocking filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/7.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~10K",
        enabled: false
    },
    {
        id: "regional-korea",
        category: "regional",
        title: "🇰🇷 List-KR Classic",
        description: "Korean language ad blocking filters",
        url: "https://cdn.jsdelivr.net/npm/@list-kr/filterslists@latest/dist/filterslist-uBlockOrigin-classic.txt",
        home: "https://github.com/List-KR/List-KR",
        rules: "~12K",
        enabled: false
    },
    {
        id: "regional-russia",
        category: "regional",
        title: "🇷🇺 RU AdList",
        description: "Russian, Ukrainian, Kazakh filters",
        url: "https://raw.githubusercontent.com/easylist/ruadlist/master/RuAdList-uBO.txt",
        home: "https://forums.lanik.us/viewforum.php?f=102",
        rules: "~25K",
        enabled: false
    },
    {
        id: "regional-spain",
        category: "regional",
        title: "🇪🇸 AdGuard Spanish/Portuguese",
        description: "Spanish and Portuguese filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/9.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~8K",
        enabled: false
    },
    {
        id: "regional-india",
        category: "regional",
        title: "🇮🇳 IndianList",
        description: "Indian subcontinent language filters",
        url: "https://easylist-downloads.adblockplus.org/indianlist.txt",
        home: "https://github.com/mediumkreation/IndianList",
        rules: "~5K",
        enabled: false
    },
    {
        id: "regional-poland",
        category: "regional",
        title: "🇵🇱 Oficjalne Polskie Filtry",
        description: "Polish language ad blocking filters",
        url: "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
        home: "https://github.com/MajkiIT/polish-ads-filter",
        rules: "~10K",
        enabled: false
    },
    {
        id: "regional-vietnam",
        category: "regional",
        title: "🇻🇳 ABPVN List",
        description: "Vietnamese language ad blocking filters",
        url: "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_ublock.txt",
        home: "https://abpvn.com/",
        rules: "~4K",
        enabled: false
    },
    {
        id: "regional-turkey",
        category: "regional",
        title: "🇹🇷 AdGuard Turkish",
        description: "Turkish language ad blocking filters",
        url: "https://filters.adtidy.org/extension/ublock/filters/13.txt",
        home: "https://github.com/AdguardTeam/AdguardFilters",
        rules: "~5K",
        enabled: false
    },
    {
        id: "regional-nordic",
        category: "regional",
        title: "🇳🇴🇩🇰 Dandelion Sprout's Nordic Filters",
        description: "Norwegian, Danish, Icelandic filters",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt",
        home: "https://github.com/DandelionSprout/adfilt",
        rules: "~15K",
        enabled: false
    },
    {
        id: "regional-swedish",
        category: "regional",
        title: "🇸🇪 Frellwit's Swedish Filter",
        description: "Swedish language ad blocking filters",
        url: "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt",
        home: "https://github.com/lassekongo83/Frellwits-filter-lists",
        rules: "~8K",
        enabled: false
    },
    {
        id: "regional-persian",
        category: "regional",
        title: "🇮🇷 PersianBlocker",
        description: "Persian/Farsi language ad blocking filters",
        url: "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlocker.txt",
        home: "https://github.com/MasterKia/PersianBlocker",
        rules: "~6K",
        enabled: false
    },
    {
        id: "blp-abuse",
        category: "security",
        title: "BlocklistProject – Abuse",
        description: "Deceptive and abusive sites blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/abuse.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~5K",
        enabled: false
    },
    {
        id: "blp-malware",
        category: "security",
        title: "BlocklistProject – Malware",
        description: "Malware hosts and distribution sites",
        url: "https://blocklistproject.github.io/Lists/adguard/malware.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~15K",
        enabled: false
    },
    {
        id: "blp-phishing",
        category: "security",
        title: "BlocklistProject – Phishing",
        description: "Dedicated phishing domain blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/phishing.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~190K",
        enabled: false
    },
    {
        id: "blp-fraud",
        category: "security",
        title: "BlocklistProject – Fraud",
        description: "Fraud and scam domain blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/fraud.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~20K",
        enabled: false
    },
    {
        id: "blp-ransomware",
        category: "security",
        title: "BlocklistProject – Ransomware",
        description: "Ransomware C2 and distribution domains",
        url: "https://blocklistproject.github.io/Lists/adguard/ransomware.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~2K",
        enabled: false
    },
    {
        id: "blp-scam",
        category: "security",
        title: "BlocklistProject – Scam",
        description: "Scam and fraud domain blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/scam.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~8K",
        enabled: false
    },
    {
        id: "blp-crypto",
        category: "security",
        title: "BlocklistProject – Crypto",
        description: "Cryptojacking and crypto scam domains",
        url: "https://blocklistproject.github.io/Lists/adguard/crypto.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~3K",
        enabled: false
    },
    {
        id: "blp-tracking",
        category: "privacy",
        title: "BlocklistProject – Tracking",
        description: "Tracking and analytics domain blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/tracking.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~10K",
        enabled: false
    },
    {
        id: "blp-redirect",
        category: "security",
        title: "BlocklistProject – Redirect",
        description: "Malicious redirect domain blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/redirect.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~5K",
        enabled: false
    },
    {
        id: "blp-gambling",
        category: "security",
        title: "BlocklistProject – Gambling",
        description: "Gambling site blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/gambling.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~15K",
        enabled: false
    },
    {
        id: "blp-piracy",
        category: "security",
        title: "BlocklistProject – Piracy",
        description: "Piracy and illegal download site blocklist",
        url: "https://blocklistproject.github.io/Lists/adguard/piracy.txt",
        home: "https://github.com/blocklistproject/Lists",
        rules: "~10K",
        enabled: false
    },
    {
        id: "phishindex",
        category: "security",
        title: "PhishIndex – Malicious Domains",
        description: "Phishing, malware, and IP logger domains (updated every 2 hours)",
        url: "https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/blocklist.txt",
        home: "https://github.com/PhishIndex/phishindex-blocklist",
        rules: "~50K",
        enabled: false
    },
    {
        id: "phishing-army",
        category: "security",
        title: "Phishing Army – Extended",
        description: "Large continuously updated phishing blocklist",
        url: "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        home: "https://phishing.army/",
        rules: "~157K",
        enabled: false
    },
    {
        id: "tempest-phishing",
        category: "security",
        title: "Tempest – Phishing",
        description: "Enterprise-grade phishing blocklist (<0.01% false positive rate)",
        url: "https://raw.githubusercontent.com/Tempest-Solutions-Company/pihole_blocklists/main/phishing.txt",
        home: "https://github.com/Tempest-Solutions-Company/pihole_blocklists",
        rules: "~891K",
        enabled: false
    },
    {
        id: "tempest-malware",
        category: "security",
        title: "Tempest – Malware",
        description: "Malware hosting and distribution domains",
        url: "https://raw.githubusercontent.com/Tempest-Solutions-Company/pihole_blocklists/main/malware.txt",
        home: "https://github.com/Tempest-Solutions-Company/pihole_blocklists",
        rules: "~27K",
        enabled: false
    },
    {
        id: "tempest-c2",
        category: "security",
        title: "Tempest – C2 Servers",
        description: "Command and control server blocklist",
        url: "https://raw.githubusercontent.com/Tempest-Solutions-Company/pihole_blocklists/main/c2_servers.txt",
        home: "https://github.com/Tempest-Solutions-Company/pihole_blocklists",
        rules: "~57K",
        enabled: false
    },
    {
        id: "tempest-banking",
        category: "security",
        title: "Tempest – Banking Trojans",
        description: "Banking trojan and financial malware domains",
        url: "https://raw.githubusercontent.com/Tempest-Solutions-Company/pihole_blocklists/main/banking_trojan.txt",
        home: "https://github.com/Tempest-Solutions-Company/pihole_blocklists",
        rules: "~8K",
        enabled: false
    },
    {
        id: "threatfox",
        category: "security",
        title: "ThreatFox (abuse.ch)",
        description: "Threat intelligence IOC domain feed from abuse.ch",
        url: "https://threatfox.abuse.ch/downloads/hostfile/",
        home: "https://threatfox.abuse.ch/",
        rules: "~56K",
        enabled: false
    },
    {
        id: "1hosts-lite",
        category: "security",
        title: "1Hosts – Lite",
        description: "Lightweight DNS blocklist with minimal breakage",
        url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
        home: "https://github.com/badmojr/1Hosts",
        rules: "~192K",
        enabled: false
    },
    {
        id: "1hosts-xtra",
        category: "security",
        title: "1Hosts – Xtra",
        description: "Expanded 1Hosts blocklist, advanced filtering",
        url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/adblock.txt",
        home: "https://github.com/badmojr/1Hosts",
        rules: "~1.1M",
        enabled: false
    },
    {
        id: "adaway",
        category: "ads",
        title: "AdAway Hosts",
        description: "Popular mobile and DNS ad blocking hosts file",
        url: "https://adaway.org/hosts.txt",
        home: "https://adaway.org/",
        rules: "~6.5K",
        enabled: false
    },
    {
        id: "mvps",
        category: "ads",
        title: "MVPS Hosts File",
        description: "Long-standing high-quality hosts file for ad blocking",
        url: "https://winhelp2002.mvps.org/hosts.txt",
        home: "https://winhelp2002.mvps.org/",
        rules: "~14K",
        enabled: false
    },
    {
        id: "kadhosts",
        category: "security",
        title: "KADhosts",
        description: "Fraud, adware, and scam websites blocklist",
        url: "https://kadantiscam.netlify.com/scam_domains.txt",
        home: "https://github.com/azet12/KADhosts",
        rules: "~10K",
        enabled: false
    },
    {
        id: "disconnect-ads",
        category: "ads",
        title: "Disconnect – Simple Ads",
        description: "Conservative DNS ad block list from Disconnect",
        url: "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
        home: "https://disconnect.me/",
        rules: "~2.7K",
        enabled: false
    },
    {
        id: "disconnect-malvertising",
        category: "security",
        title: "Disconnect – Malvertising",
        description: "Malicious advertising infrastructure blocklist",
        url: "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
        home: "https://disconnect.me/",
        rules: "~2.7K",
        enabled: false
    },
    {
        id: "disconnect-tracking",
        category: "privacy",
        title: "Disconnect – Tracking",
        description: "Tracking server blocklist from Disconnect",
        url: "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        home: "https://disconnect.me/",
        rules: "~3K",
        enabled: false
    },
    {
        id: "disconnect-malware",
        category: "security",
        title: "Disconnect – Malware",
        description: "Malware domain blocklist from Disconnect",
        url: "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
        home: "https://disconnect.me/",
        rules: "~2K",
        enabled: false
    },
    {
        id: "rpi-malware",
        category: "security",
        title: "RPiList – Malware",
        description: "Regional malware tracking domains (aggressive)",
        url: "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADomains.txt",
        home: "https://github.com/PolishFiltersTeam",
        rules: "~943K",
        enabled: false
    },
    {
        id: "unchecky-ads",
        category: "ads",
        title: "UncheckyAds",
        description: "Windows installer ad source sites",
        url: "https://hosts.my-pc.online/files/ad_servers.txt",
        home: "https://github.com/FadeMind/hosts.extras",
        rules: "~2K",
        enabled: false
    },
    {
        id: "add-spam",
        category: "security",
        title: "StevenBlack – Spam",
        description: "Spam sites from hostsfile.org data",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts",
        home: "https://github.com/StevenBlack/hosts",
        rules: "~12K",
        enabled: false
    },
    {
        id: "add-risk",
        category: "security",
        title: "StevenBlack – Risk",
        description: "Risk content sites from hostsfile.org data",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts",
        home: "https://github.com/StevenBlack/hosts",
        rules: "~40K",
        enabled: false
    },
    {
        id: "badd-boyz",
        category: "security",
        title: "Mitchell Krog – Badd Boyz Hosts",
        description: "Sketchy domains and bad referrers blocklist",
        url: "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
        home: "https://github.com/mitchellkrogza/Badd-Boyz-Hosts",
        rules: "~8K",
        enabled: false
    },
    {
        id: "tiuxo-ads",
        category: "ads",
        title: "Tiuxo Hostlist – Ads",
        description: "Categorized hosts files for DNS-based content blocking",
        url: "https://raw.githubusercontent.com/tiuxo/hosts/master/ads",
        home: "https://github.com/tiuxo/hosts",
        rules: "~15K",
        enabled: false
    },
    {
        id: "hagezi-proplus",
        category: "security",
        title: "HaGeZi Multi PRO++",
        description: "Maximum protection, aggressive blocking",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~232K",
        enabled: false
    },
    {
        id: "hagezi-ultimate",
        category: "security",
        title: "HaGeZi Multi Ultimate",
        description: "Aggressive protection, strictest blocking",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~303K",
        enabled: false
    },
    {
        id: "hagezi-dyndns",
        category: "security",
        title: "HaGeZi – Dynamic DNS",
        description: "Blocks dynamic DNS services used in phishing",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~5K",
        enabled: false
    },
    {
        id: "hagezi-tlds",
        category: "security",
        title: "HaGeZi – Most Abused TLDs",
        description: "Blocks known malicious top-level domains",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tlds.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~3K",
        enabled: false
    },
    {
        id: "hagezi-hoster",
        category: "security",
        title: "HaGeZi – Badware Hoster",
        description: "Blocks hosters that also serve badware",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~2K",
        enabled: false
    },
    {
        id: "hagezi-bypass",
        category: "security",
        title: "HaGeZi – DoH/VPN/TOR/Proxy Bypass",
        description: "Prevents DNS bypass methods",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~1K",
        enabled: false
    },
    {
        id: "hagezi-gambling",
        category: "security",
        title: "HaGeZi – Gambling",
        description: "Gambling content blocklist",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~50K",
        enabled: false
    },
    {
        id: "hagezi-nsfw",
        category: "security",
        title: "HaGeZi – NSFW",
        description: "Adult content blocklist",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~100K",
        enabled: false
    },
    {
        id: "hagezi-nrd",
        category: "security",
        title: "HaGeZi – Newly Registered Domains",
        description: "NRDs commonly used for phishing and malware",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd.txt",
        home: "https://github.com/hagezi/dns-blocklists",
        rules: "~200K",
        enabled: false
    }
];

const BLOCKLIST_TEMPLATES = [
    {
        id: "template-essential",
        name: "Essential Protection",
        description: "Recommended baseline for most users. Blocks ads, trackers, and malware with minimal breakage.",
        lists: ["ubo-filters-ads", "easylist", "ubo-privacy", "easyprivacy", "ubo-badware", "urlhaus", "peter-lowe"]
    },
    {
        id: "template-privacy",
        name: "Privacy Hardening",
        description: "Maximum privacy protection. Blocks all known trackers, telemetry, and URL tracking parameters.",
        lists: ["ubo-filters-ads", "easylist", "ubo-privacy", "easyprivacy", "adguard-tracking", "adguard-url-tracking", "fanboy-antifacebook", "block-lan", "peter-lowe", "blp-tracking"]
    },
    {
        id: "template-security",
        name: "Security Focus",
        description: "Prioritizes malware, phishing, and badware protection. Best for security-conscious users.",
        lists: ["ubo-badware", "urlhaus", "phishing-filter", "stevenblack-unified", "hagezi-tif", "oisd-small", "blp-malware", "blp-phishing", "threatfox"]
    },
    {
        id: "template-enterprise",
        name: "Enterprise Security",
        description: "Maximum threat protection with C2, banking trojan, and phishing defense. For high-risk environments.",
        lists: ["tempest-phishing", "tempest-malware", "tempest-c2", "tempest-banking", "phishindex", "phishing-army", "blp-ransomware", "blp-fraud", "blp-scam", "blp-redirect", "hagezi-tif"]
    },
    {
        id: "template-aggressive",
        name: "Maximum Blocking",
        description: "Aggressive blocking with comprehensive coverage. May cause some site breakage.",
        lists: ["ubo-filters-ads", "easylist", "adguard-ads", "ubo-privacy", "easyprivacy", "adguard-tracking", "urlhaus", "phishing-filter", "stevenblack-unified", "hagezi-pro", "hagezi-tif", "oisd-big", "1hosts-lite"]
    },
    {
        id: "template-ultimate",
        name: "Nuclear Option",
        description: "Everything blocked. HaGeZi Ultimate + all security feeds. Expect site breakage.",
        lists: ["hagezi-ultimate", "hagezi-tif", "hagezi-nrd", "hagezi-dyndns", "hagezi-hoster", "hagezi-tlds", "tempest-phishing", "tempest-malware", "tempest-c2", "phishindex", "1hosts-xtra", "oisd-big"]
    },
    {
        id: "template-clean-web",
        name: "Clean Web Experience",
        description: "Focuses on removing annoyances: cookie banners, popups, social widgets, newsletter prompts.",
        lists: ["easylist-cookies", "adguard-cookies", "ubo-annoyances", "easylist-social", "adguard-social", "easylist-newsletters", "easylist-notifications", "adguard-popup-overlays", "adguard-mobile-app-banners", "easylist-ai", "easylist-chat"]
    },
    {
        id: "template-lightweight",
        name: "Lightweight",
        description: "Minimal resource usage. Good for older devices or low-memory environments.",
        lists: ["easylist", "ubo-privacy", "peter-lowe"]
    },
    {
        id: "template-parental",
        name: "Parental Controls",
        description: "Blocks gambling, NSFW content, and social media. Family-friendly browsing.",
        lists: ["hagezi-gambling", "hagezi-nsfw", "blp-gambling", "easylist-social", "adguard-social", "blp-piracy"]
    },
    {
        id: "template-anti-big-tech",
        name: "Anti Big Tech",
        description: "Blocks Facebook, Twitter/X, TikTok tracking and services. Maximum privacy from tech giants.",
        lists: ["fanboy-antifacebook", "blp-tracking", "adguard-tracking", "ubo-privacy", "disconnect-tracking", "easyprivacy"]
    }
];

const CATEGORY_META = {
    ads: { label: "Ad Blocking", icon: "\ud83d\udeab", color: "#ef4444" },
    privacy: { label: "Privacy", icon: "\ud83d\udd12", color: "#3b82f6" },
    security: { label: "Security", icon: "\ud83d\udee1\ufe0f", color: "#22c55e" },
    annoyances: { label: "Annoyances", icon: "\ud83e\udd2c", color: "#f59e0b" },
    unbreak: { label: "Unbreak", icon: "\ud83d\udd27", color: "#8b5cf6" },
    regional: { label: "Regional", icon: "\ud83c\udf0d", color: "#06b6d4" }
};
