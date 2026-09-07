// public/app.js

let totalPackets = 0;
let forwardedPackets = 0;
let droppedPackets = 0;
const uniqueHostnames = new Set();

const wsDot = document.getElementById('ws-dot');
const wsText = document.getElementById('ws-text');
const runBtn = document.getElementById('run-btn');
const clearBtn = document.getElementById('clear-btn');
const statusMessage = document.getElementById('status-message');
const engineStatus = document.getElementById('engine-status');

const statTotal = document.getElementById('stat-total-packets');
const statFlows = document.getElementById('stat-tls-flows');
const statSni = document.getElementById('stat-unique-sni');

const sniTableBody = document.getElementById('sni-table-body');
const packetTableBody = document.getElementById('packet-table-body');

// Setup WebSocket
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${protocol}//${window.location.host}`;
let socket = null;

function connectWebSocket() {
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    wsDot.className = 'dot connected';
    wsText.textContent = 'Connected';
  };

  socket.onclose = () => {
    wsDot.className = 'dot disconnected';
    wsText.textContent = 'Disconnected';
    setTimeout(connectWebSocket, 2000);
  };

  socket.onerror = (err) => {
    console.error('[WebSocket Error]', err);
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleServerEvent(data);
    } catch (e) {
      console.error('JSON parse error:', e);
    }
  };
}

function handleServerEvent(msg) {
  if (msg.type === 'INIT_STATE') {
    if (msg.state && msg.state.history && msg.state.history.length > 0) {
      msg.state.history.slice().reverse().forEach((evt) => renderEvent(evt));
    }
  }

  if (msg.type === 'RESET') {
    resetDashboardUI();
    engineStatus.textContent = 'Running';
    engineStatus.className = 'stat-value status-running';
    statusMessage.textContent = 'Worker threads actively inspecting packet streams...';
    runBtn.disabled = true;
  }

  if (msg.type === 'PACKET_EVENT') {
    renderEvent(msg.event);
  }

  if (msg.type === 'STATUS' && msg.status === 'COMPLETED') {
    engineStatus.textContent = 'Finished';
    engineStatus.className = 'stat-value status-done';
    statusMessage.textContent = 'Inspection complete. Telemetry synchronized.';
    runBtn.disabled = false;
  }
}

function renderEvent(evt) {
  // Clear placeholder rows
  const placeholder1 = sniTableBody.querySelector('.empty-placeholder');
  if (placeholder1) placeholder1.remove();

  const placeholder2 = packetTableBody.querySelector('.empty-placeholder');
  if (placeholder2) placeholder2.remove();

  totalPackets++;
  if (evt.status === 'FORWARD') forwardedPackets++;
  else droppedPackets++;

  statTotal.textContent = totalPackets.toLocaleString();

  const sni = evt.sni || evt.domain || (evt.tuple && evt.tuple.sni) || null;
  const src = evt.src || (evt.tuple ? `${evt.tuple.srcIp}:${evt.tuple.srcPort}` : '192.168.1.10');

  // Track SNIs
  if (sni) {
    uniqueHostnames.add(sni);
    statFlows.textContent = uniqueHostnames.size.toString();
    statSni.textContent = uniqueHostnames.size.toString();

    const sniRow = document.createElement('tr');
    sniRow.innerHTML = `
      <td>${new Date().toLocaleTimeString()}</td>
      <td>${src}</td>
      <td class="tag-sni">${sni}</td>
    `;
    sniTableBody.prepend(sniRow);
  }

  // Live Stream Log
  const logRow = document.createElement('tr');
  const isDrop = evt.status === 'DROP';
  logRow.innerHTML = `
    <td>#${totalPackets}</td>
    <td><span style="color: ${isDrop ? 'var(--accent-danger)' : 'var(--accent-success)'}">${evt.status || 'FORWARD'}</span></td>
    <td>${evt.length || '512'} B</td>
    <td>${sni ? `Target: ${sni}` : (evt.action || 'Payload Parsed')}</td>
  `;
  packetTableBody.prepend(logRow);

  if (packetTableBody.children.length > 50) {
    packetTableBody.lastElementChild.remove();
  }
}

// Trigger Inspection directly over WebSocket
runBtn.addEventListener('click', () => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ cmd: 'START_ANALYSIS' }));
    engineStatus.textContent = 'Running';
    engineStatus.className = 'stat-value status-running';
    runBtn.disabled = true;
    statusMessage.textContent = 'Starting inspection pipeline...';
  }
});

function resetDashboardUI() {
  totalPackets = 0;
  forwardedPackets = 0;
  droppedPackets = 0;
  uniqueHostnames.clear();

  statTotal.textContent = '0';
  statFlows.textContent = '0';
  statSni.textContent = '0';

  sniTableBody.innerHTML = '<tr class="empty-placeholder"><td colspan="3">No SNI hostnames captured yet. Click "Run Inspection".</td></tr>';
  packetTableBody.innerHTML = '<tr class="empty-placeholder"><td colspan="4">Stream awaiting payload...</td></tr>';
}

clearBtn.addEventListener('click', () => {
  resetDashboardUI();
  engineStatus.textContent = 'Idle';
  engineStatus.className = 'stat-value status-idle';
  statusMessage.textContent = 'Ready to analyze capture streams.';
});

connectWebSocket();