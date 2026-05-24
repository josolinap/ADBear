# Ad Bear (IP-Watch)

Ad Bear is a comprehensive network monitoring and DNS filtering extension for Firefox. It provides real-time visibility into your browser's network connections, including GeoIP information, risk assessment, and DNS query logging.

## Features

- **Real-time Connection Tracking**: Monitor all active TCP/UDP connections initiated by the browser.
- **DNS Monitor**: View and log all DNS queries with detailed statistics.
- **DNS Filtering**: Block ads, trackers, and malicious domains using customizable blocklists.
- **Topology Map**: Visualize your network connections in an interactive graph.
- **Risk Assessment**: Identify high-risk connections based on port fingerprints and threat intelligence.
- **History & Alerts**: Keep track of connection history and receive alerts for suspicious activity.

## Installation

This extension is designed for Firefox and utilizes Manifest V3 features. To install it temporarily for development:

1. Open Firefox and navigate to `about:debugging`.
2. Click on "This Firefox".
3. Click "Load Temporary Add-on...".
4. Select the `manifest.json` file from this directory.

## Architecture

- **Background Script**: Handles persistent network listeners, DNS resolution, and blocklist enforcement.
- **Sidebar**: The main dashboard for monitoring and configuration.
- **Popup**: A lightweight interface for quick stats and toggling DNS filtering.
- **Native Messaging (Optional)**: Can be paired with a native host for enhanced capabilities like process identification and detailed GeoIP.

## Privacy

Ad Bear is designed with privacy in mind. All monitoring data is stored locally in your browser and is never uploaded to any external servers, except for optional blocklist updates and public IP lookups (via `api.ipify.org`).

## License

This project is licensed under the MIT License.
