import { useState } from "react";

const API = "https://cloud-security-scanner.onrender.com";
export default function ScanForm({ onResult }) {
  const [mode, setMode] = useState("single"); // "single" | "bulk"
  const [url, setUrl] = useState("");
  const [bulkUrls, setBulkUrls] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    setError("");
    setLoading(true);
    onResult(null);

    try {
      let resp;
      if (mode === "single") {
        resp = await fetch(`${API}/api/v1/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url.trim() }),
        });
      } else {
        const urls = bulkUrls
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean);
        resp = await fetch(`${API}/api/v1/bulk-scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ urls }),
        });
      }

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }

      const data = await resp.json();
      onResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const exampleUrls = [
    "https://httpbin.org/get",
    "https://jsonplaceholder.typicode.com/posts",
    "https://api.github.com",
  ];

  return (
    <div className="card fade-in" style={{ marginBottom: 24 }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontFamily: "var(--mono)", fontSize: 20, fontWeight: 700, marginBottom: 6 }}>
          API Security Scanner
        </h1>
        <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
          Scan API endpoints for security vulnerabilities, misconfigurations, and data exposure risks.
        </p>
      </div>

      {/* Mode toggle */}
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        {["single", "bulk"].map((m) => (
          <button
            key={m}
            className={`btn ${mode === m ? "btn-primary" : "btn-ghost"}`}
            style={{ padding: "6px 16px", fontSize: 13 }}
            onClick={() => setMode(m)}
          >
            {m === "single" ? "⚡ Single URL" : "📋 Bulk Scan"}
          </button>
        ))}
      </div>

      {/* Input */}
      {mode === "single" ? (
        <div style={{ display: "flex", gap: 10 }}>
          <input
            className="input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://api.example.com/v1/endpoint"
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
          />
          <button
            className="btn btn-primary"
            onClick={handleScan}
            disabled={loading || !url.trim()}
            style={{ whiteSpace: "nowrap" }}
          >
            {loading ? <span className="spinner" /> : "Scan →"}
          </button>
        </div>
      ) : (
        <div>
          <textarea
            className="input"
            value={bulkUrls}
            onChange={(e) => setBulkUrls(e.target.value)}
            placeholder={"https://api.example.com/v1/users\nhttps://api.example.com/v1/admin\nhttps://api.example.com/v1/config"}
            rows={5}
            style={{ resize: "vertical", marginBottom: 10 }}
          />
          <button
            className="btn btn-primary"
            onClick={handleScan}
            disabled={loading || !bulkUrls.trim()}
          >
            {loading ? <><span className="spinner" /> Scanning...</> : "Bulk Scan →"}
          </button>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          marginTop: 12, padding: "10px 14px", background: "rgba(248,81,73,0.1)",
          border: "1px solid rgba(248,81,73,0.3)", borderRadius: "var(--radius)",
          color: "var(--red)", fontSize: 13, fontFamily: "var(--mono)",
        }}>
          ✗ {error}
        </div>
      )}

      {/* Example URLs */}
      <div style={{ marginTop: 16 }}>
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>Try an example:</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {exampleUrls.map((u) => (
            <button
              key={u}
              className="btn-ghost"
              style={{
                background: "none", border: "1px solid var(--border)", borderRadius: 4,
                padding: "3px 10px", fontSize: 11, fontFamily: "var(--mono)",
                color: "var(--text-muted)", cursor: "pointer",
              }}
              onClick={() => { setMode("single"); setUrl(u); }}
            >
              {u.replace("https://", "")}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
