// Shared fetch utility with timeout, retries, and error handling

export async function safeFetch(url, opts = {}) {
  const { timeout = 15000, retries = 1, headers = {} } = opts;
  let lastError;
  for (let i = 0; i <= retries; i++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { 
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Accept': 'application/json, text/plain, application/rss+xml, application/xml;q=0.9, */*;q=0.8',
          ...headers 
        },
      });
      clearTimeout(timer);
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
      }
      const text = await res.text();
      try { return JSON.parse(text); } catch { return { rawText: text.slice(0, 500) }; }
    } catch (e) {
      lastError = e;
      // GDELT needs 5s between requests, others are fine with shorter delays
      if (i < retries) await new Promise(r => setTimeout(r, 2000 * (i + 1)));
    }
  }
  return { error: lastError?.message || 'Unknown error', source: url };
}

export function ago(hours) {
  return new Date(Date.now() - hours * 3600000).toISOString();
}

export function today() {
  return new Date().toISOString().split('T')[0];
}

export function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().split('T')[0];
}
