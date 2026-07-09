export default function ScannerShell({ children }) {
  return (
    <section className="scanner-shell">

      <div className="section-label">
        [003]
      </div>

      <div className="scanner-header">

        <div>
          <p className="scanner-kicker">
            CLOUD SECURITY OPERATIONS
          </p>

          <h2 className="scanner-title">
            MISSION CONTROL
          </h2>
        </div>

        <div className="scanner-status">
          <span className="status-dot"></span>
          Threat Engine Active
        </div>

      </div>

      <div className="scanner-container">
        {children}
      </div>

    </section>
  );
}