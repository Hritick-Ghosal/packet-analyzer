import fs from 'fs';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import express from 'express';
import { WebSocketServer } from 'ws';
import { Worker, MessageChannel } from 'worker_threads';
import { parsePacket } from './packetParser.js';
import { hash5Tuple } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const inputFile = process.argv[2] || 'test_dpi.pcap';
const outputFile = process.argv[3] || 'filtered.pcap';
const PORT = process.env.PORT || 3000;

const NUM_LBS = 2;
const NUM_FPS = 4;

const rules = {
  blockedApps: ['YouTube'],
  blockedDomains: ['facebook'],
  blockedIPs: ['192.168.1.50']
};

// Helper: Ensure the PCAP file exists on cloud platforms (e.g., Render)
function ensurePcapFileExists() {
  if (!fs.existsSync(inputFile)) {
    console.log(`[DPI Engine] "${inputFile}" not found. Generating test PCAP traffic...`);
    try {
      execSync('node generate_pcap.js', { stdio: 'inherit' });
      console.log(`[DPI Engine] Successfully generated "${inputFile}".`);
    } catch (err) {
      console.error('[DPI Engine] Failed to generate sample PCAP:', err.message);
    }
  }
}

// Initial check on boot
ensurePcapFileExists();

// In-memory state to hydrate newly connected/refreshed browsers
const serverState = {
  total: 0,
  forwarded: 0,
  dropped: 0,
  history: []
};

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);

  // Send historical snapshot immediately on connect/refresh
  ws.send(JSON.stringify({ type: 'INIT_STATE', state: serverState }));

  ws.on('message', async (raw) => {
    try {
      const data = JSON.parse(raw);
      if (data.cmd === 'START_ANALYSIS') {
        runPipeline();
      }
    } catch {}
  });

  ws.on('close', () => {
    clients.delete(ws);
  });

  ws.on('error', () => {
    clients.delete(ws);
  });
});

function broadcast(data) {
  const payload = JSON.stringify(data);
  for (const client of clients) {
    if (client.readyState === 1) client.send(payload);
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let isRunning = false;

async function runPipeline() {
  if (isRunning) return;
  isRunning = true;

  // Guarantee the input file exists before opening stream
  ensurePcapFileExists();

  if (!fs.existsSync(inputFile)) {
    console.error(`[Reader Error] Input file "${inputFile}" still does not exist.`);
    broadcast({ type: 'STATUS', status: 'COMPLETED' });
    isRunning = false;
    return;
  }

  // Reset state
  serverState.total = 0;
  serverState.forwarded = 0;
  serverState.dropped = 0;
  serverState.history = [];
  broadcast({ type: 'RESET' });

  const inFd = fs.openSync(inputFile, 'r');
  const outFd = fs.openSync(outputFile, 'w');

  const globalHeader = Buffer.alloc(24);
  fs.readSync(inFd, globalHeader, 0, 24, null);
  fs.writeSync(outFd, globalHeader, 0, 24);
  const isLittleEndian = globalHeader.readUInt32LE(0) === 0xa1b2c3d4;

  const lbs = [];
  const fps = [];

  for (let i = 0; i < NUM_LBS; i++) {
    lbs.push(new Worker('./worker.js', { workerData: { type: 'LB', id: i, rules } }));
  }
  for (let i = 0; i < NUM_FPS; i++) {
    fps.push(new Worker('./worker.js', { workerData: { type: 'FP', id: i, rules } }));
  }

  lbs.forEach((lb) => {
    fps.forEach((fp, fpIdx) => {
      const { port1, port2 } = new MessageChannel();
      lb.postMessage({ cmd: 'INIT_FP_PORT', fpIndex: fpIdx, port: port1 }, [port1]);
      fp.postMessage({ cmd: 'CONNECT_LB', port: port2 }, [port2]);
    });
  });

  fps.forEach((fp) => {
    const { port1, port2 } = new MessageChannel();
    fp.postMessage({ cmd: 'INIT_WRITER_PORT', port: port1 }, [port1]);

    port2.on('message', ({ headerBuf, packetData }) => {
      fs.writeSync(outFd, Buffer.from(headerBuf));
      fs.writeSync(outFd, Buffer.from(packetData));
    });

    fp.on('message', (msg) => {
      if (msg.cmd === 'LIVE_EVENT') {
        serverState.total++;
        if (msg.event.status === 'FORWARD') serverState.forwarded++;
        else serverState.dropped++;

        serverState.history.unshift(msg.event);
        if (serverState.history.length > 50) serverState.history.pop();

        broadcast({ type: 'PACKET_EVENT', event: msg.event });
      }
    });
  });

  console.log(`[Reader] Streaming packets from ${inputFile}...`);
  const pktHeaderBuf = Buffer.alloc(16);

  while (true) {
    const bytesRead = fs.readSync(inFd, pktHeaderBuf, 0, 16, null);
    if (bytesRead < 16) break;

    const inclLen = isLittleEndian
      ? pktHeaderBuf.readUInt32LE(8)
      : pktHeaderBuf.readUInt32BE(8);

    const packetData = Buffer.alloc(inclLen);
    fs.readSync(inFd, packetData, 0, inclLen, null);

    const parsed = parsePacket(packetData);
    const headerCopy = Buffer.from(pktHeaderBuf);

    if (parsed) {
      const hash = hash5Tuple(parsed.tuple);
      const lbIdx = hash % NUM_LBS;

      lbs[lbIdx].postMessage({
        cmd: 'PACKET',
        hash,
        tuple: parsed.tuple,
        payloadOffset: parsed.payloadOffset,
        headerBuf: headerCopy,
        packetData
      }, [packetData.buffer]);
    } else {
      fs.writeSync(outFd, headerCopy);
      fs.writeSync(outFd, packetData);
      serverState.total++;
      serverState.forwarded++;
    }

    // Pacing delay (100ms) so you can clearly see packets animate in UI
    await sleep(100);
  }

  fs.closeSync(inFd);
  lbs.forEach((lb) => lb.postMessage({ cmd: 'FLUSH' }));

  // Wait for worker pipelines to clear
  await sleep(1000);

  fs.closeSync(outFd);
  lbs.forEach((lb) => lb.terminate());
  fps.forEach((fp) => fp.terminate());

  isRunning = false;
  console.log('[Pipeline] Complete.');
  broadcast({ type: 'STATUS', status: 'COMPLETED' });
}

server.listen(PORT, () => {
  console.log(`\n[UI Server] Running at: http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser and click "Run Inspection".\n`);
});