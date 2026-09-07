import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const outputPath = path.join(__dirname, 'test_dpi.pcap');

// PCAP Global Header (24 bytes)
const globalHeader = Buffer.alloc(24);
globalHeader.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
globalHeader.writeUInt16LE(2, 4);          // Major version
globalHeader.writeUInt16LE(4, 6);          // Minor version
globalHeader.writeInt32LE(0, 8);           // Timezone
globalHeader.writeUInt32LE(0, 12);         // Sigfigs
globalHeader.writeUInt32LE(65535, 16);     // Snaplen
globalHeader.writeUInt32LE(1, 20);         // Link layer: Ethernet

function buildEthernetIPv4TCPFrame(srcIp, dstIp, srcPort, dstPort, payload) {
  // Ethernet Header (14 bytes)
  const ethHeader = Buffer.alloc(14);
  ethHeader.write('001122334455', 0, 6, 'hex'); // Dest MAC
  ethHeader.write('66778899aabb', 6, 6, 'hex'); // Source MAC
  ethHeader.writeUInt16BE(0x0800, 12);           // IPv4 EtherType

  // IPv4 Header (20 bytes)
  const ipHeader = Buffer.alloc(20);
  ipHeader.writeUInt8(0x45, 0); // Version 4, IHL 5
  ipHeader.writeUInt8(0, 1);    // DSCP/ECN
  const totalLen = 20 + 20 + payload.length;
  ipHeader.writeUInt16BE(totalLen, 2);
  ipHeader.writeUInt16BE(0x1234, 4); // ID
  ipHeader.writeUInt16BE(0x4000, 6); // Flags (DF)
  ipHeader.writeUInt8(64, 8);        // TTL
  ipHeader.writeUInt8(6, 9);         // Protocol: TCP
  ipHeader.writeUInt16BE(0, 10);     // Checksum placeholder

  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    ipHeader.writeUInt8(srcParts[i], 12 + i);
    ipHeader.writeUInt8(dstParts[i], 16 + i);
  }

  // TCP Header (20 bytes)
  const tcpHeader = Buffer.alloc(20);
  tcpHeader.writeUInt16BE(srcPort, 0);
  tcpHeader.writeUInt16BE(dstPort, 2);
  tcpHeader.writeUInt32BE(1000, 4); // Seq
  tcpHeader.writeUInt32BE(0, 8);    // Ack
  tcpHeader.writeUInt8(0x50, 12);   // Data offset: 5 (20 bytes)
  tcpHeader.writeUInt8(0x18, 13);   // Flags: PSH, ACK
  tcpHeader.writeUInt16BE(64240, 14); // Window size
  tcpHeader.writeUInt16BE(0, 16);     // Checksum placeholder
  tcpHeader.writeUInt16BE(0, 18);     // Urgent pointer

  return Buffer.concat([ethHeader, ipHeader, tcpHeader, payload]);
}

function buildTLSClientHello(serverName) {
  const sniBuf = Buffer.from(serverName, 'utf8');
  
  // Extension: Server Name Indication (SNI)
  const sniListLen = sniBuf.length + 3;
  const extDataLen = sniListLen + 2;
  const sniExt = Buffer.alloc(4 + extDataLen);
  sniExt.writeUInt16BE(0x0000, 0); // Extension type: Server Name
  sniExt.writeUInt16BE(extDataLen, 2);
  sniExt.writeUInt16BE(sniListLen, 4);
  sniExt.writeUInt8(0x00, 6); // Name type: host_name
  sniExt.writeUInt16BE(sniBuf.length, 7);
  sniBuf.copy(sniExt, 9);

  // Client Hello
  const handshakeLen = 34 + 1 + 2 + 1 + 2 + sniExt.length;
  const handshake = Buffer.alloc(4 + handshakeLen);
  handshake.writeUInt8(0x01, 0); // Client Hello
  handshake.writeUIntBE(handshakeLen, 1, 3);
  handshake.writeUInt16BE(0x0303, 4); // TLS 1.2
  // Random (32 bytes)
  Buffer.alloc(32).copy(handshake, 6);
  handshake.writeUInt8(0, 38); // Session ID length: 0
  handshake.writeUInt16BE(2, 39); // Cipher Suites length: 2
  handshake.writeUInt16BE(0xc02f, 41); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  handshake.writeUInt8(1, 43); // Compression methods length: 1
  handshake.writeUInt8(0, 44); // null compression
  handshake.writeUInt16BE(sniExt.length, 45); // Extensions length
  sniExt.copy(handshake, 47);

  // TLS Record Header (5 bytes)
  const record = Buffer.alloc(5 + handshake.length);
  record.writeUInt8(0x16, 0); // Handshake
  record.writeUInt16BE(0x0301, 1); // TLS 1.0 (Record layer standard for Client Hello)
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);

  return record;
}

const testDomains = [
  { domain: 'www.youtube.com', srcIp: '192.168.1.10', srcPort: 54100, dstIp: '142.250.190.46' },
  { domain: 'www.facebook.com', srcIp: '192.168.1.10', srcPort: 54102, dstIp: '157.240.22.35' },
  { domain: 'github.com', srcIp: '192.168.1.50', srcPort: 54104, dstIp: '140.82.121.4' }, // Blocked IP
  { domain: 'www.google.com', srcIp: '192.168.1.20', srcPort: 54106, dstIp: '142.250.190.78' },
  { domain: 'twitter.com', srcIp: '192.168.1.30', srcPort: 54108, dstIp: '104.244.42.1' }
];

const outFd = fs.openSync(outputPath, 'w');
fs.writeSync(outFd, globalHeader, 0, 24);

let timestampSec = 1710000000;
for (const test of testDomains) {
  const tlsPayload = buildTLSClientHello(test.domain);
  const frame = buildEthernetIPv4TCPFrame(test.srcIp, test.dstIp, test.srcPort, 443, tlsPayload);

  // PCAP Packet Header (16 bytes)
  const pktHeader = Buffer.alloc(16);
  pktHeader.writeUInt32LE(timestampSec++, 0);
  pktHeader.writeUInt32LE(0, 4);
  pktHeader.writeUInt32LE(frame.length, 8);  // Captured length
  pktHeader.writeUInt32LE(frame.length, 12); // Original length

  fs.writeSync(outFd, pktHeader);
  fs.writeSync(outFd, frame);
}

fs.closeSync(outFd);
console.log(`[PCAP Generator] Generated test_dpi.pcap with ${testDomains.length} test TLS flows.`);