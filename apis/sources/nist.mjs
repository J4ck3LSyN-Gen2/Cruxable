// NIST National Vulnerability Database — NVD API v2
// No API key required for basic use (5 req/30s). Set NIST_API_KEY env var for 50 req/30s.
// Fetches recent high + critical CVEs published in the last 7 days.
// Docs: https://nvd.nist.gov/developers/vulnerabilities

const BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function sanitizeUrl(raw) {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

async function fetchCves(params, apiKey) {
  const headers = apiKey ? { apiKey } : {};
  const url = `${BASE}?${params}`;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(18000) });
  if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
  return res.json();
}

export async function briefing(apiKey = process.env.NIST_API_KEY) {
  const now = new Date();
  const weekAgo = new Date(now - 7 * 24 * 3600 * 1000);
  // NVD expects format: 2024-01-01T00:00:00.000
  const fmt = d => d.toISOString().replace(/\.\d+Z$/, '.000').replace('Z', '');

  const baseParams = { pubStartDate: fmt(weekAgo), pubEndDate: fmt(now), resultsPerPage: '20', startIndex: '0' };

  const highParams = new URLSearchParams({ ...baseParams, cvssV3Severity: 'HIGH' });
  const critParams = new URLSearchParams({ ...baseParams, cvssV3Severity: 'CRITICAL', resultsPerPage: '15' });

  const [highRes, critRes] = await Promise.allSettled([
    fetchCves(highParams, apiKey),
    fetchCves(critParams, apiKey),
  ]);

  // Merge and deduplicate by CVE ID
  const allCves = new Map();
  for (const res of [highRes, critRes]) {
    if (res.status !== 'fulfilled') continue;
    for (const { cve } of (res.value?.vulnerabilities || [])) {
      if (!allCves.has(cve.id)) allCves.set(cve.id, cve);
    }
  }

  const cveDocs = [...allCves.values()].map(cve => {
    const m31 = cve.metrics?.cvssMetricV31?.[0];
    const m30 = cve.metrics?.cvssMetricV30?.[0];
    const metric = m31 || m30;
    const score = metric?.cvssData?.baseScore ?? null;
    const severity = metric?.cvssData?.baseSeverity ?? 'UNKNOWN';
    const desc = (cve.descriptions?.find(d => d.lang === 'en')?.value || '').trim();
    const cwes = (cve.weaknesses || []).flatMap(w => w.description.map(d => d.value)).filter(Boolean);
    const refs = (cve.references || []).slice(0, 2).map(r => sanitizeUrl(r.url)).filter(Boolean);
    const affectedProducts = (cve.configurations || [])
      .flatMap(cfg => (cfg.nodes || []))
      .flatMap(n => (n.cpeMatch || []))
      .slice(0, 3)
      .map(m => (m.criteria || '').split(':').slice(3, 5).join(' '))
      .filter(Boolean);

    return {
      id: cve.id,
      published: cve.published,
      score,
      severity,
      desc: desc.substring(0, 280),
      cwes: cwes.slice(0, 3),
      refs,
      products: affectedProducts,
    };
  }).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

  const critical = cveDocs.filter(c => c.severity === 'CRITICAL');
  const high = cveDocs.filter(c => c.severity === 'HIGH');

  return {
    total: cveDocs.length,
    criticalCount: critical.length,
    highCount: high.length,
    recent: cveDocs.slice(0, 12),
    topCve: cveDocs[0] || null,
    weekStart: weekAgo.toISOString().split('T')[0],
    signals: buildSignals(cveDocs),
  };
}

function buildSignals(cveDocs) {
  const signals = [];
  const critCount = cveDocs.filter(c => c.severity === 'CRITICAL').length;
  if (critCount >= 3) signals.push(`${critCount} CRITICAL CVEs published this week — patch prioritization warranted`);
  const rces = cveDocs.filter(c => c.desc.toLowerCase().includes('remote code execution') || c.desc.toLowerCase().includes('rce'));
  if (rces.length > 0) signals.push(`${rces.length} RCE vulnerabilities detected — ${rces[0]?.id} (score: ${rces[0]?.score})`);
  const authBypass = cveDocs.filter(c => c.desc.toLowerCase().includes('authentication bypass') || c.desc.toLowerCase().includes('privilege escalation'));
  if (authBypass.length > 0) signals.push(`${authBypass.length} auth-bypass/privilege-escalation CVEs — critical attack surface expansion`);
  return signals;
}
