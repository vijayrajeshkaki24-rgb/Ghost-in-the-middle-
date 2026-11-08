import { useState } from "react";
import "chart.js/auto";
import { Bar } from "react-chartjs-2";
import * as api from "./api.js";

const BAND_COLOR = { LOW: "#2ecc71", MEDIUM: "#f1c40f", HIGH: "#e67e22", CRITICAL: "#e74c3c" };

export default function App() {
  const [step, setStep] = useState("register"); // register | otp | dashboard
  const [email, setEmail] = useState("");
  const [url, setUrl] = useState("http://localhost:8080/");
  const [otp, setOtp] = useState("");
  const [key, setKey] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const run = async (fn) => {
    setBusy(true); setError("");
    try { await fn(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };

  const doRegister = () => run(async () => { await api.register(email, url); setStep("otp"); });
  const doVerify = () => run(async () => { const r = await api.verify(email, otp); setKey(r.api_key); setStep("dashboard"); });
  const doScan = () => run(async () => setResult(await api.scan(url, key)));
  const doReport = () => run(async () => {
    const blob = await api.report(result.id, key);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = `acase_${result.id}.pdf`; a.click();
  });

  return (
    <div className="wrap">
      <header><h1>👻 ACASE</h1><p>Automated Cookie and Session Evaluation – AiTM exposure scanner</p></header>
      {error && <div className="error">{error}</div>}

      {step === "register" && (
        <section className="card narrow">
          <h2>Register target</h2>
          <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" /></label>
          <label>Target URL<input value={url} onChange={(e) => setUrl(e.target.value)} /></label>
          <p className="muted">Scan only systems you own or are authorised to test.</p>
          <button disabled={busy || !email || !url} onClick={doRegister}>Send OTP</button>
        </section>
      )}

      {step === "otp" && (
        <section className="card narrow">
          <h2>Verify OTP</h2>
          <p className="muted">Enter the 6-digit code sent to {email} (valid 2 minutes).</p>
          <input value={otp} maxLength={6} onChange={(e) => setOtp(e.target.value)} placeholder="123456" />
          <button disabled={busy || otp.length !== 6} onClick={doVerify}>Verify</button>
        </section>
      )}

      {step === "dashboard" && (
        <>
          <section className="card row">
            <input value={url} onChange={(e) => setUrl(e.target.value)} />
            <button disabled={busy} onClick={doScan}>{busy ? "Scanning…" : "Run scan"}</button>
            {result && <button className="secondary" disabled={busy} onClick={doReport}>Download PDF</button>}
          </section>
          {result && <Results r={result} />}
        </>
      )}
    </div>
  );
}

function Results({ r }) {
  const mods = Object.entries(r.modules);
  const chart = {
    labels: mods.map(([m]) => m),
    datasets: [{ label: "Failed-check weight", data: mods.map(([, v]) => v.score),
                 backgroundColor: ["#3498db", "#9b59b6", "#1abc9c"] }],
  };
  return (
    <>
      <section className="cards">
        <div className="card stat" style={{ borderColor: BAND_COLOR[r.band] }}>
          <span>Risk score</span><b>{r.risk_score}</b><em style={{ color: BAND_COLOR[r.band] }}>{r.band}</em>
        </div>
        <div className="card stat"><span>Checks failed</span><b>{r.checks_failed}/{r.checks_run}</b></div>
        <div className="card stat"><span>Weighted index</span><b>{r.weighted_index}</b></div>
        <div className="card stat"><span>Scan time</span><b>{r.scan_seconds}s</b></div>
      </section>
      <p className="muted">{r.action}</p>

      <section className="card"><Bar data={chart} options={{ plugins: { legend: { display: false } } }} /></section>

      <section className="card">
        <h2>Findings</h2>
        <table>
          <thead><tr><th>Module</th><th>Check</th><th>Weight</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>
            {r.findings.map((f) => (
              <tr key={f.id} className={f.failed ? "bad" : ""}>
                <td>{f.module}</td><td>{f.title}</td><td>{f.weight}</td>
                <td>{f.failed ? "FAIL" : "pass"}</td><td>{f.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>AI recommendations <small>({r.recommendations.source})</small></h2>
        <pre>{r.recommendations.text}</pre>
      </section>
    </>
  );
}
