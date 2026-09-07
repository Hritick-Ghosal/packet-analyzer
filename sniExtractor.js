export function extractSNI(payload) {
  try {
    if (!payload || payload.length < 5) return null;

    // Check TLS Handshake (0x16)
    if (payload[0] !== 0x16) return null;

    // Handshake Type: Client Hello (0x01)
    if (payload[5] !== 0x01) return null;

    let offset = 43; // Skip Record header (5) + Type(1) + Length(3) + Version(2) + Random(32)
    if (offset >= payload.length) return null;

    // Session ID length
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;
    if (offset + 2 > payload.length) return null;

    // Cipher Suites length
    const cipherLen = payload.readUInt16BE(offset);
    offset += 2 + cipherLen;
    if (offset + 1 > payload.length) return null;

    // Compression methods length
    const compLen = payload[offset];
    offset += 1 + compLen;
    if (offset + 2 > payload.length) return null;

    // Extensions length
    const extTotalLen = payload.readUInt16BE(offset);
    offset += 2;
    const endOffset = offset + extTotalLen;

    while (offset + 4 <= endOffset && offset + 4 <= payload.length) {
      const extType = payload.readUInt16BE(offset);
      const extLen = payload.readUInt16BE(offset + 2);
      offset += 4;

      if (extType === 0x0000) { // Server Name Indication
        let sniOffset = offset;
        if (sniOffset + 2 > payload.length) return null;
        
        sniOffset += 2; // Skip server_name_list length
        if (sniOffset + 3 > payload.length) return null;
        
        const nameType = payload[sniOffset];
        const nameLen = payload.readUInt16BE(sniOffset + 1);
        sniOffset += 3;

        if (nameType === 0x00 && sniOffset + nameLen <= payload.length) {
          return payload.toString('utf8', sniOffset, sniOffset + nameLen);
        }
      }
      offset += extLen;
    }
  } catch (err) {
    return null;
  }
  return null;
}