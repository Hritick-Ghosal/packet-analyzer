export function parsePacket(packetData) {
  try {
    if (packetData.length < 34) return null; // Minimum Ethernet + IPv4 length

    // Check EtherType: IPv4 (0x0800)
    const etherType = packetData.readUInt16BE(12);
    if (etherType !== 0x0800) return null;

    const ipStart = 14;
    const ihl = (packetData[ipStart] & 0x0f) * 4;
    const protocol = packetData[ipStart + 9];

    // Check TCP Protocol (6)
    if (protocol !== 6) return null;

    const srcIp = `${packetData[ipStart + 12]}.${packetData[ipStart + 13]}.${packetData[ipStart + 14]}.${packetData[ipStart + 15]}`;
    const dstIp = `${packetData[ipStart + 16]}.${packetData[ipStart + 17]}.${packetData[ipStart + 18]}.${packetData[ipStart + 19]}`;

    const tcpStart = ipStart + ihl;
    if (packetData.length < tcpStart + 20) return null;

    const srcPort = packetData.readUInt16BE(tcpStart);
    const dstPort = packetData.readUInt16BE(tcpStart + 2);
    const dataOffset = ((packetData[tcpStart + 12] >> 4) & 0x0f) * 4;

    const payloadOffset = tcpStart + dataOffset;

    return {
      tuple: { srcIp, dstIp, srcPort, dstPort, protocol: 'TCP' },
      payloadOffset
    };
  } catch {
    return null;
  }
}