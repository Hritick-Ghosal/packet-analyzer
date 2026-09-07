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

const inputFile = path.resolve(__dirname, process.argv[2] || 'test_dpi.pcap');
const outputFile = path.resolve(__dirname, process.argv[3] || 'filtered.pcap');
const PORT = process.env.PORT || 3000;

const NUM_LBS = 2;
const NUM_FPS = 4;

const rules = {
  blockedApps: ['YouTube'],
  blockedDomains: ['facebook'],
  blockedIPs: ['192.168.1.50']
};

function ensurePcapFileExists() {
  if (!fs.existsSync(inputFile)) {
    console.log(`[DPI Engine] PCAP not found at "${inputFile}". Generating test traffic...`);
    try {
      execSync(`node "${path.join(__dirname, 'generate_pcap.js')}"`, { stdio: 'inherit', cwd: __dirname });
    } catch (err) {
      console.error('[DPI Engine Error] Failed to generate sample PCAP:', err.message);
    }
  }
}

// Ensure test_dpi.pcap is created on startup
ensurePcapFileExists();

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
  console.log(`[WS] Client connected. Total active: ${clients.size}`);

  ws.send(JSON.stringify({ type: 'INIT_STATE', state: serverState }));

  ws.on('message', async (raw) => {
    try {
      const data = JSON.parse(raw);
      if (data.cmd === 'START_ANALYSIS') {
        runPipeline();
      }
    } catch {}
  });

  ws.on('close', () => clients.delete(ws));
  ws.on('error', () => clients.delete(ws));
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

  ensurePcapFileExists();

  if (!fs.existsSync(inputFile)) {
    console.error(`[Reader Error] Input file "${inputFile}" does not exist.`);
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
  const workerFile = path.join(__dirname, 'worker.js');

  for (let i = 0; i < NUM_LBS; i++) {
    const lb = new Worker(workerFile, { workerData: { type: 'LB', id: i, rules } });
    lb.on('error', (err) => console.error(`[LB ${i} Error]:`, err));
    lbs.push(lb);
  }
  for (let i = 0; i < NUM_FPS; i++) {
    const fp = new Worker(workerFile, { workerData: { type: 'FP', id: i, rules } });
    fp.on('error', (err) => console.error(`[FP ${i} Error]:`, err));
    fps.push(fp);
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

    // 120ms pacing delay for visible UI animation
    await sleep(120);
  }

  fs.closeSync(inFd);
  lbs.forEach((lb) => lb.postMessage({ cmd: 'FLUSH' }));

  // Wait for worker queues to drain
  await sleep(1000);

  fs.closeSync(outFd);
  lbs.forEach((lb) => lb.terminate());
  fps.forEach((fp) => fp.terminate());

  isRunning = false;
  console.log('[Pipeline] Complete.');
  broadcast({ type: 'STATUS', status: 'COMPLETED' });
}

server.listen(PORT, () => {
  console.log(`\n[UI Server] Running at: http://localhost:${PORT}\n`);
});