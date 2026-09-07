// generate_pcap.js
import fs from 'fs';

function createGlobalHeader() {
  const buf = Buffer.alloc(24);
  buf.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
  buf.writeUInt16LE(2, 4);          // Major version
  buf.writeUInt16LE(4, 6);          // Minor version
  buf.writeInt32LE(0, 8);           // Timezone offset
  buf.writeUInt32LE(0, 12);         // Timestamp accuracy
  buf.writeUInt32LE(65535, 16);     // Snaplen
  buf.writeUInt32LE(1, 20);         // Link-layer type (1 = Ethernet)
  return buf;
}

function createPktHeader(len) {
  const buf = Buffer.alloc(16);
  const now = Math.floor(Date.now() / 1000);
  buf.writeUInt32LE(now, 0); // Timestamp seconds
  buf.writeUInt32LE(0, 4);   // Microseconds
  buf.writeUInt32LE(len, 8); // Captured length
  buf.writeUInt32LE(len, 12);// Original length
  return buf;
}

function createTlsClientHello(domain) {
  const sniBytes = Buffer.from(domain, 'utf8');
  
  // SNI Extension
  const extData = Buffer.alloc(5 + sniBytes.length);
  extData.writeUInt16BE(sniBytes.length + 3, 0); // SNI list length
  extData.writeUInt8(0, 2);                      // Hostname type
  extData.writeUInt16BE(sniBytes.length, 3);     // Server name length
  sniBytes.copy(extData, 5);

  const extension = Buffer.alloc(4 + extData.length);
  extension.writeUInt16BE(0x0000, 0);            // Extension type (SNI)
  extension.writeUInt16BE(extData.length, 2);    // Extension data length
  extData.copy(extension, 4);

  // Extensions wrapper
  const extWrapper = Buffer.alloc(2 + extension.length);
  extWrapper.writeUInt16BE(extension.length, 0);
  extension.copy(extWrapper, 2);

  // Client Hello Body
  const clientHello = Buffer.concat([
    Buffer.from([0x03, 0x03]),      // Client TLS 1.2
    Buffer.alloc(32, 0xAA),         // Random bytes
    Buffer.from([0x00]),            // Session ID length = 0
    Buffer.from([0x00, 0x02, 0x00, 0x2f]), // Cipher suites length (2) + suite
    Buffer.from([0x01, 0x00]),      // Compression methods length (1) + null compression
    extWrapper
  ]);

  // Handshake wrapper
  const handshake = Buffer.alloc(4 + clientHello.length);
  handshake.writeUInt8(0x01, 0);    // Handshake Type: Client Hello
  handshake.writeUIntBE(clientHello.length, 1, 3); // 3-byte length
  clientHello.copy(handshake, 4);

  // TLS Record Header
  const record = Buffer.alloc(5 + handshake.length);
  record.writeUInt8(0x16, 0);       // Content Type: Handshake
  record.writeUInt16BE(0x0301, 1);  // TLS 1.0 record version
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);

  return record;
}

function buildPacket(srcIp, dstIp, srcPort, dstPort, payload = Buffer.alloc(0)) {
  // 1. Ethernet Header (14 bytes)
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12); // IPv4

  // 2. IPv4 Header (20 bytes)
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);        // Version 4, IHL 5
  ip.writeUInt16BE(20 + 20 + payload.length, 2); // Total length
  ip.writeUInt8(64, 8);          // TTL
  ip.writeUInt8(6, 9);           // Protocol: TCP
  
  const parseIp = (str) => str.split('.').map(Number);
  Buffer.from(parseIp(srcIp)).copy(ip, 12);
  Buffer.from(parseIp(dstIp)).copy(ip, 16);

  // 3. TCP Header (20 bytes)
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt8(0x50, 12);      // Data offset: 5 (20 bytes)
  tcp.writeUInt8(0x18, 13);      // Flags: PSH, ACK

  return Buffer.concat([eth, ip, tcp, payload]);
}

const fd = fs.openSync('test_dpi.pcap', 'w');
fs.writeSync(fd, createGlobalHeader());

// Test flows
const traffic = [
  { src: '192.168.1.10', dst: '142.250.180.3', port: 51200, domain: 'www.youtube.com' },  // Blocked App
  { src: '192.168.1.11', dst: '157.240.22.35', port: 51201, domain: 'www.facebook.com' }, // Blocked Domain
  { src: '192.168.1.50', dst: '140.82.121.4', port: 51202, domain: 'github.com' },        // Blocked IP
  { src: '192.168.1.12', dst: '142.250.190.46', port: 51203, domain: 'www.google.com' },  // Allowed
  { src: '192.168.1.13', dst: '104.244.42.1', port: 51204, domain: 'twitter.com' }        // Allowed
];

traffic.forEach((item) => {
  const payload = createTlsClientHello(item.domain);
  const rawPkt = buildPacket(item.src, item.dst, item.port, 443, payload);
  fs.writeSync(fd, createPktHeader(rawPkt.length));
  fs.writeSync(fd, rawPkt);
});

fs.closeSync(fd);
console.log('Generated test_dpi.pcap with 5 test TLS flows.');