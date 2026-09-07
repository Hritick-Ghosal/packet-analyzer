# Multi-Threaded DPI Engine (Deep Packet Inspection)

A high-performance, multi-threaded Deep Packet Inspection (DPI) engine built using Node.js, Express, and WebSockets. The system ingests network capture files (`.pcap`), decodes packet layers, performs protocol inspection (specifically TLS Server Name Indication extraction), and streams analytical telemetry to a web dashboard.

---

## 📌 Architecture & Features

- **Deep Packet Inspection (DPI):** Parses raw PCAP streams to inspect protocol layers (Ethernet, IPv4/IPv6, TCP/UDP) and extracts Layer 7 application metadata.
- **TLS SNI Extraction:** Inspects TLS Client Hello handshakes to extract target Server Name Indication (SNI) hostnames without decrypting payload data.
- **Worker Thread Concurrency:** Utilizes Node.js worker threads (`worker.js`) to process large packet streams across multiple CPU cores without blocking event execution.
- **Live Telemetry & Dashboard:** Serves an interactive monitoring interface over Express and streams real-time parsing updates via WebSockets (`ws`).
- **Synthetic Traffic Generator:** Generates custom test capture files (`test_dpi.pcap`) with simulated TLS sessions for offline testing and benchmarking.

---

## 📂 Project Structure

```text
Packet Analyzer/
├── public/               # Frontend user interface assets (HTML, CSS, client scripts)
├── generate_pcap.js      # Utility script to generate simulated PCAP test traffic
├── index.js              # Core CLI entry point & orchestrator for packet processing
├── packetParser.js       # Binary packet decoder (Ethernet, IP, TCP/UDP layers)
├── server.js             # Express web server & WebSocket real-time broadcast engine
├── setup_dpi.js          # DPI rule engine initialization and configuration script
├── sniExtractor.js       # Specialized parser for TLS Client Hello handshakes (SNI)
├── types.js              # Type definitions, constants, and packet protocol enums
├── worker.js             # Background worker script for multi-threaded packet jobs
├── package.json          # Project metadata, dependencies, and execution scripts
├── test_dpi.pcap         # Generated sample packet capture file
└── output.pcap           # Processed/filtered capture output