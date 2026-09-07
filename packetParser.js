function ipToString(buf, offset) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

export function parsePacket(rawBuf) {
  if (rawBuf.length < 14) return null;

  const etherType = rawBuf.readUInt16BE(12);
  if (etherType !== 0x0800 || rawBuf.length < 34) return null;

  const ipHeaderLen = (rawBuf[14] & 0x0f) * 4;
  const protocol = rawBuf[23];
  const srcIp = ipToString(rawBuf, 26);
  const dstIp = ipToString(rawBuf, 30);

  if (protocol === 6) {
    const tcpOffset = 14 + ipHeaderLen;
    if (rawBuf.length < tcpOffset + 20) return null;

    const srcPort = rawBuf.readUInt16BE(tcpOffset);
    const dstPort = rawBuf.readUInt16BE(tcpOffset + 2);
    const tcpHeaderLen = ((rawBuf[tcpOffset + 12] >> 4) & 0x0f) * 4;
    const payloadOffset = tcpOffset + tcpHeaderLen;

    return {
      tuple: { srcIp, dstIp, srcPort, dstPort, protocol: "TCP" },
      payloadOffset: payloadOffset <= rawBuf.length ? payloadOffset : null
    };
  }

  if (protocol === 17) {
    const udpOffset = 14 + ipHeaderLen;
    if (rawBuf.length < udpOffset + 8) return null;

    const srcPort = rawBuf.readUInt16BE(udpOffset);
    const dstPort = rawBuf.readUInt16BE(udpOffset + 2);

    return {
      tuple: { srcIp, dstIp, srcPort, dstPort, protocol: "UDP" },
      payloadOffset: udpOffset + 8
    };
  }

  return null;
}