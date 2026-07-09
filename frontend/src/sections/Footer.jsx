export default function Footer() {
  return (
    <footer className="footer">

      <div className="footer-top">

        <div>
          <div className="footer-logo">
            CloudSecScanner
          </div>

          <p className="footer-text">
            Advanced Cloud Security Intelligence Platform
            focused on attack surface discovery,
            cloud misconfiguration detection,
            API security assessment and risk analysis.
          </p>
        </div>

        <div className="footer-links">

          <a href="/">
            Home
          </a>

          <a href="/scan">
            Scanner
          </a>

          <a href="/threats">
            Threat Intel
          </a>

          <a href="/reports">
            Reports
          </a>

          <a href="/dashboard">
            Dashboard
          </a>

        </div>

      </div>

      <div className="footer-bottom">
        © 2026 CloudSecScanner • Built by Amardeep Maroli
      </div>

    </footer>
  );
}