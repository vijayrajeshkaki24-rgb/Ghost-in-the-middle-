const BASE = import.meta.env.VITE_API_URL || "http://localhost:5000";

async function request(path, { method = "GET", body, key, blob } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(key ? { "X-API-Key": key } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return blob ? res.blob() : res.json();
}

export const health = () => request("/api/health");
export const register = (email, url) => request("/api/register", { method: "POST", body: { email, url } });
export const verify = (email, otp) => request("/api/verify", { method: "POST", body: { email, otp } });
export const scan = (url, key) => request("/api/scan", { method: "POST", body: { url }, key });
export const report = (id, key) => request(`/api/scans/${id}/report`, { key, blob: true });
