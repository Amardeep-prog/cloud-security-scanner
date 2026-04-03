import { useState, useEffect, useCallback } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

function getGradeStyle(grade) {
  const colors = {
    "A+": "var(--green)", "A": "var(--accent)", "B": "var(--yellow)",
    "C": "var(--orange)", "D": "var(--red)", "F": "var(--critical)",
  };
  return colors[grade] || "var(--text-muted)";
}

export default function History({ onSelect, setTab }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState(null);

  const PAGE_SIZE = 10;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const resp = await fetch(
        `${API}/api/v1/history?page=${page}&page_size=${PAGE_SIZE}`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  const handleView = async (scanId) => {
    try {
      const resp = await fetch(`${API}/api/v1/report/${scanId}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      onSelect(data);
      setTab("scan");
    } catch (e) {
      alert(`Failed to load report: ${e.message}`);
    }
  };

  const handleDelete = async (scanId) => {
    if (!confirm("Delete this report?")) return;
    setDeleting(scanId);
    try {
      await fetch(`${API}/api/v1/report/${scanId}`, { method: "DELETE" });
      setItems((prev) => prev.filter((i) => i.scan_id !== scanId));
      setTotal((t) => t - 1);
    } catch (e) {
      alert(`Delete failed: ${e.message}`);
    } finally {
      setDeleting(null);
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="fade-in">
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <h2 style={{ fontFamily: "var(--mono)", fontSize: 16 }}>Scan History</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 12, marginTop: 2 }}>
              {total} total scans
            </p>
          </div>
          <button className="btn btn-ghost" onClick={load} style={{ fontSize: 12, padding: "6px 12px" }}>
            ↺ Refresh
          </button>
        </div>

        {error && (
          <div style={{
            padding: "10px 14px", background: "rgba(248,81,73,0.1)",
            border: "1px solid rgba(248,81,73,0.3)", borderRadius: "var(--radius)",
            color: "var(--red)", fontSize: 13, marginBottom: 16,
          }}>
            ✗ {error}
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
            Loading...
          </div>
        ) : items.length === 0 ? (
          <div style={{ textAlign: "center", padding: 40 }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>📭</div>
            <p style={{ color: "var(--text-muted)" }}>No scans yet. Run your first scan!</p>
          </div>
        ) : (
          <div>
            {/* Table Header */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 80px 60px 60px auto",
              gap: 12, padding: "8px 12px",
              fontSize: 11, color: "var(--text-dim)",
              fontFamily: "var(--mono)", textTransform: "uppercase",
              borderBottom: "1px solid var(--border)", marginBottom: 4,
            }}>
              <span>URL / Scan ID</span>
              <span>Score</span>
              <span>Grade</span>
              <span>Issues</span>
              <span>Actions</span>
            </div>

            {/* Rows */}
            {items.map((item) => (
              <div key={item.scan_id} style={{
                display: "grid",
                gridTemplateColumns: "1fr 80px 60px 60px auto",
                gap: 12, padding: "12px",
                borderBottom: "1px solid var(--border)",
                alignItems: "center",
                transition: "background 0.1s",
              }}
                onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-raised)"}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
              >
                {/* URL + timestamp */}
                <div>
                  <div style={{
                    fontFamily: "var(--mono)", fontSize: 12, color: "var(--accent)",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    maxWidth: 360,
                  }}>
                    {item.url}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
                    {item.scan_id.slice(0, 8)} · {new Date(item.timestamp).toLocaleString()}
                  </div>
                </div>

                {/* Score */}
                <div style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
                  {item.score != null ? item.score.toFixed(1) : "—"}
                </div>

                {/* Grade */}
                <div style={{
                  fontFamily: "var(--mono)", fontSize: 15, fontWeight: 700,
                  color: getGradeStyle(item.grade),
                }}>
                  {item.grade || "—"}
                </div>

                {/* Issue count */}
                <div>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
                    {item.issue_count}
                  </span>
                  {item.critical_count > 0 && (
                    <span style={{ marginLeft: 4, fontSize: 10, color: "var(--critical)", fontFamily: "var(--mono)" }}>
                      ({item.critical_count}!)
                    </span>
                  )}
                </div>

                {/* Actions */}
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: 11, padding: "4px 10px" }}
                    onClick={() => handleView(item.scan_id)}
                  >
                    View
                  </button>
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: 11, padding: "4px 10px", color: "var(--red)" }}
                    onClick={() => handleDelete(item.scan_id)}
                    disabled={deleting === item.scan_id}
                  >
                    {deleting === item.scan_id ? "…" : "Delete"}
                  </button>
                </div>
              </div>
            ))}

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 16 }}>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 12, padding: "6px 14px" }}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  ← Prev
                </button>
                <span style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                  {page} / {totalPages}
                </span>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 12, padding: "6px 14px" }}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
