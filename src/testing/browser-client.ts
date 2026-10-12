/** Minimal cookie-keeping HTTP client that behaves like the browser UI (Origin + CSRF headers). */
export class BrowserClient {
  cookies = new Map<string, string>();
  csrf: string | null = null;
  constructor(public baseUrl: string, public origin: string) {}

  async req(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<{ status: number; json: any; headers: Headers }> {
    const headers: Record<string, string> = { Accept: 'application/json', Origin: this.origin, 'Sec-Fetch-Site': 'same-origin', ...extra };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.csrf && method !== 'GET' && !('X-CSRF-Token' in extra)) headers['X-CSRF-Token'] = this.csrf;
    if (this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(this.baseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const c of res.headers.getSetCookie()) {
      const [kv, ...attrs] = c.split(';');
      const i = kv.indexOf('=');
      const k = kv.slice(0, i).trim();
      const v = kv.slice(i + 1).trim();
      if (attrs.some((a) => /max-age=0/i.test(a.trim())) || v === '') this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    const text = await res.text();
    let json: any = undefined;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = text; }
    if (json && typeof json === 'object' && typeof json.csrfToken === 'string') this.csrf = json.csrfToken;
    return { status: res.status, json, headers: res.headers };
  }
}
