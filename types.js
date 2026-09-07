export const AppType = {
  YOUTUBE: 'YouTube',
  FACEBOOK: 'Facebook',
  GITHUB: 'GitHub',
  GOOGLE: 'Google',
  TWITTER: 'Twitter',
  UNKNOWN: 'General Web'
};

export function classifyApp(sni) {
  if (!sni) return AppType.UNKNOWN;
  const s = sni.toLowerCase();
  if (s.includes('youtube')) return AppType.YOUTUBE;
  if (s.includes('facebook')) return AppType.FACEBOOK;
  if (s.includes('github')) return AppType.GITHUB;
  if (s.includes('google')) return AppType.GOOGLE;
  if (s.includes('twitter') || s.includes('x.com')) return AppType.TWITTER;
  return AppType.UNKNOWN;
}

export function hash5Tuple(tuple) {
  const str = `${tuple.srcIp}:${tuple.srcPort}->${tuple.dstIp}:${tuple.dstPort}/${tuple.protocol}`;
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}