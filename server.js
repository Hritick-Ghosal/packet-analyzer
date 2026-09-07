// server.js
import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { fork } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Serve static frontend assets from public/
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Track active WebSocket connections
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`[WebSocket] Client connected. Total active: ${clients.size}`);

  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[WebSocket] Client disconnected. Total active: ${clients.size}`);
  });

  ws.on('error', (err) => {
    console.error('[WebSocket Error]:', err.message);
    clients.delete(ws);
  });
});

// Broadcast packet events to all connected browser clients
export function broadcastPacketEvent(data) {
  const msg = JSON.stringify(data);
  for (const client of clients) {
    if (client.readyState === 1) { // 1 === WebSocket.OPEN
      client.send(msg);
    }
  }
}

// Track running analysis to prevent concurrent clashes
let isAnalyzing = false;

// API route to trigger packet inspection from the web dashboard
app.post('/api/run-inspection', (req, res) => {
  if (isAnalyzing) {
    return res.status(409).json({ error: 'An inspection is already running. Please wait.' });
  }

  const pcapFile = path.join(__dirname, 'test_dpi.pcap');

  // Helper function to execute the DPI engine
  const startEngine = () => {
    isAnalyzing = true;

    broadcastPacketEvent({
      type: 'STATUS',
      status: 'STARTING',
      message: 'Inspection started...'
    });

    const child = fork(path.join(__dirname, 'index.js'), ['test_dpi.pcap', 'output.pcap']);

    child.on('message', (packetData) => {
      broadcastPacketEvent({
        type: 'PACKET_DATA',
        payload: packetData
      });
    });

    child.on('close', (code) => {
      isAnalyzing = false;
      broadcastPacketEvent({
        type: 'STATUS',
        status: 'COMPLETED',
        code: code,
        message: 'Inspection completed.'
      });
      console.log(`[DPI Engine] Process exited with code ${code}`);
    });

    child.on('error', (err) => {
      isAnalyzing = false;
      broadcastPacketEvent({
        type: 'STATUS',
        status: 'ERROR',
        error: err.message
      });
      console.error('[DPI Engine Error]:', err);
    });

    return res.json({ status: 'success', message: 'DPI analysis started.' });
  };

  // If sample PCAP file does not exist on the server, generate it first
  if (!fs.existsSync(pcapFile)) {
    console.log('[DPI Engine] test_dpi.pcap not found. Generating sample traffic...');
    const genProcess = fork(path.join(__dirname, 'generate_pcap.js'));
    
    genProcess.on('close', (code) => {
      if (code === 0) {
        startEngine();
      } else {
        return res.status(500).json({ error: 'Failed to generate sample PCAP file.' });
      }
    });
  } else {
    startEngine();
  }
});

// Cloud-ready dynamic port configuration
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`[Dashboard UI] Running at http://localhost:${PORT}`);
});

export default app;