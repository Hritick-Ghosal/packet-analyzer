export const AppType = {
  UNKNOWN: "Unknown",
  HTTPS: "HTTPS",
  HTTP: "HTTP",
  DNS: "DNS",
  YOUTUBE: "YouTube",
  FACEBOOK: "Facebook",
  GOOGLE: "Google",
  GITHUB: "GitHub"
};

export function hash5Tuple(tuple) {
  const str = `${tuple.srcIp}:${tuple.srcPort}->${tuple.dstIp}:${tuple.dstPort}/${tuple.protocol}`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0);
}

export function classifyApp(sni) {
  if (!sni) return AppType.HTTPS;
  const s = sni.toLowerCase();
  if (s.includes("youtube")) return AppType.YOUTUBE;
  if (s.includes("facebook")) return AppType.FACEBOOK;
  if (s.includes("google")) return AppType.GOOGLE;
  if (s.includes("github")) return AppType.GITHUB;
  return AppType.HTTPS;
}