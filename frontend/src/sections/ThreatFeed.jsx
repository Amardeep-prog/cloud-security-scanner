import { motion } from "framer-motion";
import { useEffect, useState } from "react";

const API =
  import.meta.env.VITE_API_URL ||
  "http://localhost:8000";

export default function ThreatFeed() {
  const [threatFeed, setThreatFeed] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadThreats();

    const interval = setInterval(
      loadThreats,
      30000
    );

    return () => clearInterval(interval);
  }, []);

  async function loadThreats() {
    try {
      const response = await fetch(
        `${API}/api/v1/history?page=1&page_size=100`
      );

      const data = await response.json();

      const threats = [];

      (data.items || []).forEach((item) => {
        if ((item.critical_count || 0) > 0) {
          threats.push({
            id: item.scan_id?.slice(0, 8),
            severity: "CRITICAL",
            target: item.url,
            status: `${item.critical_count} Critical Findings`,
          });
        } else if (
          item.grade === "D" ||
          item.grade === "F"
        ) {
          threats.push({
            id: item.scan_id?.slice(0, 8),
            severity: "HIGH",
            target: item.url,
            status: "High Risk Asset",
          });
        }
      });

      threats.sort((a, b) => {
        if (a.severity === "CRITICAL") return -1;
        if (b.severity === "CRITICAL") return 1;
        return 0;
      });

      setThreatFeed(threats);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  const criticalThreats = threatFeed.filter(
    (t) => t.severity === "CRITICAL"
  ).length;

  const cloudAlerts = threatFeed.length;

  const exposedAssets = new Set(
    threatFeed.map((t) => t.target)
  ).size;

  return (
    <section className="threat-intel-page">

      <div className="section-label">
        [002]
      </div>

      <h1 className="threat-main-title">
        THREAT
        <br />
        INTELLIGENCE
      </h1>

      <p className="threat-subtitle">
        Real-time visibility into cloud vulnerabilities,
        attack paths, exposed assets and emerging threats.
      </p>

      <div className="threat-stats-grid">

        <div className="intel-stat-card">
          <span>{criticalThreats}</span>
          <small>Critical Threats</small>
        </div>

        <div className="intel-stat-card">
          <span>{cloudAlerts}</span>
          <small>Cloud Alerts</small>
        </div>

        <div className="intel-stat-card">
          <span>{exposedAssets}</span>
          <small>Exposed Assets</small>
        </div>

        <div className="intel-stat-card">
          <span>
            {loading ? "..." : threatFeed.length}
          </span>
          <small>Live Findings</small>
        </div>

      </div>

      <motion.div
        className="intel-feed-panel"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
      >

        <div className="intel-feed-header">

          <h2>LIVE THREAT FEED</h2>

          <span className="threat-count">
            {threatFeed.length} Active • Updated{" "}
            {new Date().toLocaleTimeString()}
          </span>

        </div>

        {loading && (
          <div className="empty-state">
            Loading Threat Intelligence...
          </div>
        )}

        {!loading &&
          threatFeed.length === 0 && (
            <div className="empty-state">
              No active threats detected.
            </div>
          )}

        {!loading &&
          threatFeed.length > 0 && (

        <table className="intel-table">

          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Target</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>

            {threatFeed.map((item) => (
              <tr key={item.id}>

                <td>{item.id}</td>

                <td>
                  <span
                    className={`severity-badge severity-${item.severity.toLowerCase()}`}
                  >
                    {item.severity}
                  </span>
                </td>

                <td>
                  <a
                    href={item.target}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {item.target}
                  </a>
                </td>

                <td>{item.status}</td>

              </tr>
            ))}

          </tbody>

        </table>

        )}

      </motion.div>

    </section>
  );
}