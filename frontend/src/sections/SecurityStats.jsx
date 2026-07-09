export default function SecurityStats() {
  const stats = [
    {
      value: "10K+",
      label: "Assets Analyzed",
    },
    {
      value: "2.5K+",
      label: "Threats Identified",
    },
    {
      value: "99.9%",
      label: "Detection Accuracy",
    },
    {
      value: "24/7",
      label: "Monitoring Ready",
    },
  ];

  return (
    <section className="stats-section">
      <div className="section-label">[003]</div>

      <h2 className="section-title">
        SECURITY
        <br />
        OVERVIEW
      </h2>

      <div className="stats-grid">
        {stats.map((stat) => (
          <div key={stat.label} className="stat-card">
            <div className="stat-value">
              {stat.value}
            </div>

            <div className="stat-label">
              {stat.label}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}