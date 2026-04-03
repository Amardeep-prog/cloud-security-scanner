import { useState } from "react";

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

function getGradeClass(grade) {
  const map = { "A+": "Aplus", A: "A", B: "B", C: "C", D: "D", F: "F" };
  return `grade-${map[grade] || "F"}`;
}

function getScoreColor(score) {
  if (score <= 5)  return "var(--green)";
  if (score <= 15) return "var(--accent)";
  if (score <= 30) return "var(--yellow)";
  if (score <= 50) return "var(--orange)";
  return "var(--red)";
}

// ─── Issue Card ───────────────────────────────────────────────────────────────
function IssueCard({ issue }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{
      background: "var(--bg-raised)", border: "1px solid var(--border)",
      borderRadius: "var(--radius)", marginBottom: 8, overflow: "hidden",
    }}>
      <div
        style={{ padding: "12px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}
        onClick={() => setOpen(!open)}
      >
        <span className={`badge badge-${issue.severity?.toLowerCase()}`}>
          {issue.severity}
        </span>
        <span style={{ flex: 1, fontWeight: 500 }}>{issue.title || issue.issue}</span>
        <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
          {issue.id || "-"}
        </span>
        <span style={{ color: "var(--text-muted)", fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: "1px solid var(--border)" }}>
          <div style={{ marginTop: 12 }}>
            {/* Category tag */}
            {issue.category && (
              <div style={{ marginBottom: 8 }}>
                <span style={{
                  fontSize: 11, background: "var(--bg-card)", border: "1px solid var(--border)",
                  borderRadius: 4, padding: "2px 8px", color: "var(--text-dim)",
                }}>
                  {issue.category}
                </span>
              </div>
            )}

            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 10 }}>
              {issue.description || "No description provided"}
            </p>

            {issue.evidence && (
              <div style={{
                background: "var(--bg-card)", border: "1px solid var(--border)",
                borderRadius: 4, padding: "8px 12px", fontFamily: "var(--mono)",
                fontSize: 12, color: "var(--orange)", marginBottom: 10, wordBreak: "break-all",
              }}>
                🔍 {issue.evidence}
              </div>
            )}

            <div style={{
              background: "rgba(63,185,80,0.05)", border: "1px solid rgba(63,185,80,0.2)",
              borderRadius: 4, padding: "8px 12px", fontSize: 13, color: "var(--green)",
            }}>
              💡 {issue.recommendation || "No recommendation provided"}
            </div>

            {issue.confidence && (
              <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-dim)" }}>
                Confidence: {issue.confidence}
              </div>
            )}

            {(issue.cwe_id || issue.owasp_ref) && (
              <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                {issue.cwe_id && (
                  <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
                    {issue.cwe_id}
                  </span>
                )}
                {issue.owasp_ref && (
                  <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{issue.owasp_ref}</span>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Cloud Section ────────────────────────────────────────────────────────────
function CloudSection({ cloud }) {
  if (!cloud) return null;
  const isUnknown = cloud.provider === "Unknown" && cloud.service === "Unknown";
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <h2 style={{ marginBottom: 12 }}>☁️ Cloud Analysis</h2>
      {isUnknown ? (
        <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
          No cloud provider detected for this endpoint.
        </p>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "auto auto", gap: "6px 24px", fontSize: 13 }}>
          {[
            ["Provider", cloud.provider],
            ["Service",  cloud.service],
            ["Region",   cloud.region   || "—"],
            ["Bucket",   cloud.bucket   || "—"],
            ["Account",  cloud.account  || "—"],
          ].map(([k, v]) => (
            <>
              <span key={k} style={{ color: "var(--text-dim)" }}>{k}</span>
              <span key={`${k}-v`} style={{ fontFamily: "var(--mono)" }}>{v}</span>
            </>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Subdomains Section ───────────────────────────────────────────────────────
function SubdomainsSection({ subdomains }) {
  const [expanded, setExpanded] = useState(false);
  if (!subdomains || subdomains.length === 0) return null;

  const visible = expanded ? subdomains : subdomains.slice(0, 5);
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h2>🌐 Discovered Subdomains ({subdomains.length})</h2>
        {subdomains.length > 5 && (
          <button onClick={() => setExpanded(!expanded)} style={{ fontSize: 12 }}>
            {expanded ? "Show less" : `Show all ${subdomains.length}`}
          </button>
        )}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {visible.map((s) => (
          <span key={s} style={{
            fontFamily: "var(--mono)", fontSize: 12,
            background: "var(--bg-raised)", border: "1px solid var(--border)",
            borderRadius: 4, padding: "4px 10px", color: "var(--accent)",
          }}>
            {s}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Redirect Chain Section ───────────────────────────────────────────────────
function RedirectChain({ chain }) {
  if (!chain || chain.length === 0) return null;
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <h2 style={{ marginBottom: 12 }}>🔀 Redirect Chain ({chain.length})</h2>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {chain.map((url, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
            <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", minWidth: 20 }}>
              {i + 1}
            </span>
            <span style={{ fontFamily: "var(--mono)", color: "var(--text-muted)", wordBreak: "break-all" }}>
              {url}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main ScanResult ──────────────────────────────────────────────────────────
export default function ScanResult({ report }) {
  const [filter, setFilter] = useState("all");

  const isBulk = report.bulk_scan_id !== undefined;
  if (isBulk) return <BulkResult report={report} />;

  const score  = report.score;
  const issues = report.issues || [];

  const filteredIssues = filter === "all"
    ? issues
    : issues.filter((i) => i.severity === filter);

  const sorted = [...filteredIssues].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <div className="fade-in">

      {/* ── Summary Card ── */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 20, flexWrap: "wrap" }}>
          {score && (
            <div className={`grade-circle ${getGradeClass(score.grade)}`}>
              {score.grade}
            </div>
          )}

          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              {report.scan_id}
            </div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 14, color: "var(--accent)", marginBottom: 8, wordBreak: "break-all" }}>
              {report.url}
            </div>

            {/* Cloud provider pill */}
            {report.cloud && report.cloud.provider !== "Unknown" && (
              <div style={{ marginBottom: 8 }}>
                <span style={{
                  fontSize: 12, background: "rgba(88,166,255,0.1)",
                  border: "1px solid rgba(88,166,255,0.3)", borderRadius: 20,
                  padding: "2px 10px", color: "var(--accent)",
                }}>
                  ☁️ {report.cloud.provider} — {report.cloud.service}
                </span>
              </div>
            )}

            {score && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span>Risk Score</span>
                  <span style={{ fontFamily: "var(--mono)", color: getScoreColor(score.total) }}>
                    {score.total} / 100
                  </span>
                </div>
                <div className="score-bar-bg">
                  <div
                    className="score-bar-fill"
                    style={{ width: `${score.total}%`, background: getScoreColor(score.total) }}
                  />
                </div>
              </div>
            )}

            {score && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {score.critical_count > 0 && <span className="badge badge-critical">{score.critical_count} Critical</span>}
                {score.high_count     > 0 && <span className="badge badge-high">{score.high_count} High</span>}
                {score.medium_count   > 0 && <span className="badge badge-medium">{score.medium_count} Medium</span>}
                {score.low_count      > 0 && <span className="badge badge-low">{score.low_count} Low</span>}
                {score.info_count     > 0 && <span className="badge badge-info">{score.info_count} Info</span>}
              </div>
            )}
          </div>

          {/* Meta grid */}
          <div style={{ display: "grid", gridTemplateColumns: "auto auto", gap: "4px 16px", fontSize: 12 }}>
            {[
              ["Status",     report.status_code || "—"],
              ["Duration",   report.duration_ms ? `${report.duration_ms}ms` : "—"],
              ["Server",     report.server || "—"],
              ["TLS",        report.tls_version || "—"],
              ["Issues",     issues.length],
              ["Subdomains", report.subdomains?.length || 0],
            ].map(([k, v]) => (
              <>
                <span key={k} style={{ color: "var(--text-dim)" }}>{k}</span>
                <span key={`${k}-v`} style={{ fontFamily: "var(--mono)" }}>{v}</span>
              </>
            ))}
          </div>
        </div>

        {report.presigned_url && (
          <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
            <a href={report.presigned_url} className="btn btn-ghost" download>
              ↓ Download Full Report (JSON)
            </a>
          </div>
        )}
      </div>

      {/* ✅ NEW: Cloud Analysis Section */}
      <CloudSection cloud={report.cloud} />

      {/* ✅ NEW: Subdomains Section */}
      <SubdomainsSection subdomains={report.subdomains} />

      {/* ✅ NEW: Redirect Chain Section */}
      <RedirectChain chain={report.redirect_chain} />

      {/* ── Findings ── */}
      {issues.length > 0 && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
            <h2>Findings ({issues.length})</h2>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["all", ...SEV_ORDER].map((s) => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  style={{ opacity: filter === s ? 1 : 0.5, fontWeight: filter === s ? 700 : 400 }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          {sorted.map((issue) => (
            <IssueCard key={issue.id || issue.issue} issue={issue} />
          ))}
        </div>
      )}

      {issues.length === 0 && (
        <div className="card" style={{ textAlign: "center", color: "var(--text-muted)", padding: 40 }}>
          ✅ No issues detected for this endpoint.
        </div>
      )}
    </div>
  );
}

// ─── Bulk Result ──────────────────────────────────────────────────────────────
function BulkResult({ report }) {
  return (
    <div className="fade-in">
      <div className="card">
        <h2 style={{ marginBottom: 16 }}>Bulk Scan Results</h2>
        {report.reports?.map((r) => (
          <ScanResult key={r.scan_id} report={r} />
        ))}
      </div>
    </div>
  );
}