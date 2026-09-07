export function extractSNI(payload) {
  try {
    if (payload.length < 44 || payload[0] !== 0x16 || payload[5] !== 0x01) {
      return null;
    }

    let offset = 43;
    if (offset >= payload.length) return null;

    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;

    if (offset + 2 > payload.length) return null;
    const cipherSuitesLen = payload.readUInt16BE(offset);
    offset += 2 + cipherSuitesLen;

    if (offset + 1 > payload.length) return null;
    const compMethodsLen = payload[offset];
    offset += 1 + compMethodsLen;

    if (offset + 2 > payload.length) return null;
    const extensionsLen = payload.readUInt16BE(offset);
    offset += 2;

    const extensionsEnd = Math.min(offset + extensionsLen, payload.length);

    while (offset + 4 <= extensionsEnd) {
      const extType = payload.readUInt16BE(offset);
      const extLen = payload.readUInt16BE(offset + 2);
      offset += 4;

      if (extType === 0x0000) {
        if (offset + 5 <= extensionsEnd) {
          const sniLen = payload.readUInt16BE(offset + 3);
          const sniStart = offset + 5;
          if (sniStart + sniLen <= extensionsEnd) {
            return payload.toString("utf8", sniStart, sniStart + sniLen);
          }
        }
      }
      offset += extLen;
    }
  } catch {
    return null;
  }
  return null;
}