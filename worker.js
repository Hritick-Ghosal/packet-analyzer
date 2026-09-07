import { parentPort, workerData } from 'worker_threads';
import { extractSNI } from './sniExtractor.js';
import { classifyApp, AppType } from './types.js';

const { type, id, rules } = workerData;

if (type === 'LB') {
  const fpPorts = [];

  parentPort.on('message', (msg) => {
    if (msg.cmd === 'INIT_FP_PORT') {
      fpPorts[msg.fpIndex] = msg.port;
    } else if (msg.cmd === 'PACKET') {
      const fpIdx = msg.hash % fpPorts.length;
      fpPorts[fpIdx].postMessage(msg, [msg.packetData.buffer]);
    } else if (msg.cmd === 'FLUSH') {
      fpPorts.forEach((p) => p.postMessage({ cmd: 'FLUSH' }));
    }
  });

} else if (type === 'FP') {
  const flows = new Map();
  let writerPort = null;
  const stats = { processed: 0, dropped: 0, forwarded: 0, apps: {} };

  parentPort.on('message', (msg) => {
    if (msg.cmd === 'INIT_WRITER_PORT') {
      writerPort = msg.port;
    } else if (msg.cmd === 'CONNECT_LB') {
      msg.port.on('message', (packetMsg) => {
        if (packetMsg.cmd === 'FLUSH') {
          parentPort.postMessage({ cmd: 'STATS', stats, id });
          return;
        }
        processPacket(packetMsg);
      });
    }
  });

  function processPacket(msg) {
    stats.processed++;
    const { tuple, payloadOffset, packetData, headerBuf } = msg;
    const flowKey = `${tuple.srcIp}:${tuple.srcPort}->${tuple.dstIp}:${tuple.dstPort}/${tuple.protocol}`;

    let flow = flows.get(flowKey);
    if (!flow) {
      flow = { blocked: false, app: AppType.UNKNOWN, sni: null };
      flows.set(flowKey, flow);
    }

    if (tuple.dstPort === 443 && payloadOffset && packetData.length > payloadOffset) {
      const payload = Buffer.from(packetData.buffer, packetData.byteOffset + payloadOffset);
      const sni = extractSNI(payload);

      if (sni) {
        flow.sni = sni;
        flow.app = classifyApp(sni);
        if (rules.blockedApps.includes(flow.app)) flow.blocked = true;
        if (rules.blockedDomains.some((d) => sni.toLowerCase().includes(d.toLowerCase()))) {
          flow.blocked = true;
        }
      }
    }

    if (rules.blockedIPs.includes(tuple.srcIp)) {
      flow.blocked = true;
    }

    stats.apps[flow.app] = (stats.apps[flow.app] || 0) + 1;
    const status = flow.blocked ? 'DROP' : 'FORWARD';

    // Emit live event to main thread
    parentPort.postMessage({
      cmd: 'LIVE_EVENT',
      event: {
        srcIp: tuple.srcIp,
        srcPort: tuple.srcPort,
        dstIp: tuple.dstIp,
        dstPort: tuple.dstPort,
        app: flow.app,
        sni: flow.sni,
        status,
        length: packetData.length
      }
    });

    if (flow.blocked) {
      stats.dropped++;
    } else {
      stats.forwarded++;
      if (writerPort) {
        writerPort.postMessage({ headerBuf, packetData }, [packetData.buffer]);
      }
    }
  }
}