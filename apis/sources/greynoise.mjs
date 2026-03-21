// GreyNoise Community API
// Low-privilege IP watchlist lookups for known scanner / hostile infrastructure checks.
// Community endpoint supports limited unauthenticated queries; API key increases reliability.

const BASE = 'https://api.greynoise.io/v3/community';

function loadWatchlist() {
  const raw = process.env.GREYNOISE_WATCHLIST || '';
  return raw.split(',').map(ip => ip.trim()).filter(Boolean).slice(0, 10);
}

async function lookupIp(ip, apiKey) {
  const headers = apiKey ? { key: apiKey } : {};
  const response = await fetch(`${BASE}/${encodeURIComponent(ip)}`, {
    headers,
    signal: AbortSignal.timeout(10000),
  });

  let body = {};
  try {
    body = await response.json();
  } catch {}

  if (!response.ok && response.status !== 404) {
    throw new Error(body?.message || `GreyNoise HTTP ${response.status}`);
  }

  return {
    ip,
    noise: Boolean(body?.noise),
    riot: Boolean(body?.riot),
    classification: body?.classification || (body?.noise ? 'unknown' : 'not_observed'),
    name: body?.name || 'unknown',
    lastSeen: body?.last_seen || null,
    message: body?.message || '',
  };
}

export async function briefing(apiKey = process.env.GREYNOISE_API_KEY) {
  const watchlist = loadWatchlist();
  if (!watchlist.length) {
    return {
      configured: false,
      totalChecked: 0,
      noisy: 0,
      riot: 0,
      malicious: 0,
      watchlist: [],
      signals: ['GreyNoise watchlist not configured'],
    };
  }

  const results = await Promise.allSettled(watchlist.map(ip => lookupIp(ip, apiKey)));
  const entries = results
    .filter(result => result.status === 'fulfilled')
    .map(result => result.value);

  const noisy = entries.filter(entry => entry.noise).length;
  const riot = entries.filter(entry => entry.riot).length;
  const malicious = entries.filter(entry => entry.classification === 'malicious').length;

  return {
    configured: true,
    totalChecked: entries.length,
    noisy,
    riot,
    malicious,
    watchlist: entries,
    signals: buildSignals(entries, noisy, malicious),
  };
}

function buildSignals(entries, noisy, malicious) {
  const signals = [];
  if (malicious > 0) signals.push(`${malicious} GreyNoise watchlist IPs are classified as malicious`);
  if (noisy > 0) signals.push(`${noisy} watchlist IPs observed scanning the internet in the last 90 days`);
  const mostRecent = entries.filter(entry => entry.lastSeen).sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0];
  if (mostRecent) signals.push(`Most recent GreyNoise activity: ${mostRecent.ip} last seen ${mostRecent.lastSeen}`);
  return signals;
}