// CISA — Cybersecurity and Infrastructure Security Agency
// Two feeds:
//   KEV catalog: Known Exploited Vulnerabilities (updated daily)
//   Alerts RSS:  Current cybersecurity advisories
// Both are public, no API key required.

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const ALERTS_RSS = 'https://www.cisa.gov/uscert/ncas/alerts.xml';

function sanitizeUrl(raw) {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

function parseRssAlerts(xml) {
  const alerts = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const title = (block.match(/<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/)?.[1] || '').trim();
    const rawLink = (block.match(/<link>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/link>/)?.[1] || '').trim();
    const pubDate = (block.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] || '').trim();
    const rawDesc = (block.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/)?.[1] || '').trim();
    const desc = rawDesc.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().substring(0, 200);
    if (title) {
      alerts.push({ title, url: sanitizeUrl(rawLink), date: pubDate, desc });
    }
  }
  return alerts.slice(0, 12);
}

export async function briefing() {
  const [kevRes, alertsRes] = await Promise.allSettled([
    fetch(KEV_URL, { signal: AbortSignal.timeout(14000) }).then(r => {
      if (!r.ok) throw new Error(`KEV HTTP ${r.status}`);
      return r.json();
    }),
    fetch(ALERTS_RSS, { signal: AbortSignal.timeout(12000) }).then(r => {
      if (!r.ok) throw new Error(`Alerts HTTP ${r.status}`);
      return r.text();
    }),
  ]);

  // === KEV Catalog ===
  let kevTotal = 0, kevRecent = [], topVendors = [];
  if (kevRes.status === 'fulfilled' && kevRes.value?.vulnerabilities) {
    const vulns = kevRes.value.vulnerabilities;
    kevTotal = vulns.length;

    // Last 30 days
    const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
    kevRecent = vulns
      .filter(v => new Date(v.dateAdded).getTime() > cutoff)
      .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .slice(0, 15)
      .map(v => ({
        id: v.cveID,
        vendor: v.vendorProject,
        product: v.product,
        name: (v.vulnerabilityName || '').substring(0, 80),
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        desc: (v.shortDescription || '').substring(0, 180),
        ransomware: v.knownRansomwareCampaignUse === 'Known',
      }));

    // Top vendors by total KEV count
    const byVendor = {};
    for (const v of vulns) {
      byVendor[v.vendorProject] = (byVendor[v.vendorProject] || 0) + 1;
    }
    topVendors = Object.entries(byVendor)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([vendor, count]) => ({ vendor, count }));
  }

  // === Alerts RSS ===
  const alerts = alertsRes.status === 'fulfilled' ? parseRssAlerts(alertsRes.value) : [];

  // Ransomware-linked entries
  const ransomwareCount = kevRecent.filter(k => k.ransomware).length;

  return {
    kevTotal,
    kevRecentCount: kevRecent.length,
    kevRecent,
    topVendors,
    alerts,
    alertCount: alerts.length,
    ransomwareCount,
    signals: buildSignals(kevRecent, alerts, ransomwareCount),
  };
}

function buildSignals(kevRecent, alerts, ransomwareCount) {
  const signals = [];
  if (kevRecent.length >= 5) signals.push(`${kevRecent.length} new KEVs added in last 30 days — active exploitation confirmed`);
  if (ransomwareCount > 0) signals.push(`${ransomwareCount} KEV entries linked to known ransomware campaigns`);
  if (alerts.length > 0) signals.push(`CISA issued ${alerts.length} active cybersecurity advisories — ${alerts[0]?.title?.substring(0, 60)}`);

  const msCount = kevRecent.filter(k => k.vendor?.toLowerCase().includes('microsoft')).length;
  if (msCount >= 3) signals.push(`${msCount} Microsoft KEVs this month — Windows/Office attack surface elevated`);

  return signals;
}
