// FIRST EPSS — Exploit Prediction Scoring System
// Public API: https://api.first.org/data/v1/epss
// No API key required.

import { safeFetch } from '../utils/fetch.mjs';

const BASE = 'https://api.first.org/data/v1/epss';

export async function briefing() {
  const params = new URLSearchParams({
    'epss-gt': '0.7',
    'percentile-gt': '0.95',
    limit: '20',
  });

  const response = await safeFetch(`${BASE}?${params}`, { timeout: 12000, retries: 1 });
  const data = Array.isArray(response?.data) ? response.data : [];
  const top = data
    .map(item => ({
      cve: item.cve,
      epss: Number(item.epss || 0),
      percentile: Number(item.percentile || 0),
      date: item.date || item.created || null,
    }))
    .sort((a, b) => b.epss - a.epss)
    .slice(0, 15);

  const highRiskCount = top.filter(item => item.epss >= 0.9 || item.percentile >= 0.99).length;

  return {
    total: top.length,
    highRiskCount,
    top,
    signals: buildSignals(top, highRiskCount),
  };
}

function buildSignals(top, highRiskCount) {
  const signals = [];
  if (highRiskCount > 0) signals.push(`${highRiskCount} EPSS-ranked CVEs exceed 90% exploit probability`);
  if (top[0]) signals.push(`Top EPSS candidate: ${top[0].cve} at ${(top[0].epss * 100).toFixed(1)}% exploit probability`);
  return signals;
}