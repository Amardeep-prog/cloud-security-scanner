import { motion } from "framer-motion";
import { FaShieldAlt } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
export default function Hero() {
    const navigate = useNavigate();
  const scrollToScanner = () => {
    const scanner = document.getElementById("scanner-section");
    if (scanner) {
      scanner.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <section className="hero">
        

      {/* Giant Background Word */}
      <div className="hero-bg-word">
        CLOUD
      </div>

      {/* Grid */}
      <div className="hero-grid"></div>
      <div className="hero-dot-matrix"></div>

      {/* Dot Matrix Pattern */}
      <div className="hero-dots"></div>

<div className="hero-noise"></div>
      {/* Glow Effects */}
      <div className="hero-glow hero-glow-1"></div>
      <div className="hero-glow hero-glow-2"></div>

      <motion.div
        className="hero-content"
        initial={{ opacity: 0, y: 60 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
      >
        <div className="hero-layout">

          {/* LEFT SIDE */}
          <div className="hero-left">

            <div className="hero-index">
              [001]
            </div>
            <div className="hero-topline">

  <div>[001]</div>

  <div className="hero-line"></div>

  <div>[002]</div>

</div>
<div className="hero-dot-matrix hero-dot-1"></div>
<div className="hero-dot-matrix hero-dot-2"></div>
<div className="hero-dot-matrix hero-dot-3"></div>

            <div className="hero-badge">
              <FaShieldAlt />
              <span>Cloud Security Intelligence Platform</span>
            </div>

            <h1 className="hero-title">
              DISCOVER
              <br />
              EXPOSURES
            </h1>

            <h2 className="hero-subtitle">
              BEFORE THEY
              <br />
              BECOME BREACHES
            </h2>

            <p className="hero-description">
              Identify exposed assets, insecure APIs,
              cloud misconfigurations, attack paths,
              and security weaknesses before they
              become real-world incidents.
            </p>

            <div className="hero-buttons">

  <button
  className="hero-split-btn"
  onClick={() => navigate("/scan")}
>
    <span className="hero-arrow-box">
      🛡
    </span>

    <span className="hero-btn-text">
      START SECURITY SCAN
    </span>
  </button>

  <button
    className="hero-btn-secondary"
    onClick={() =>
      window.location.href = "/dashboard"
    }
  >
    📊 VIEW DASHBOARD
  </button>

</div>

          </div>

          {/* RIGHT SIDE */}
          <div className="hero-right">

            <div className="attack-graph">

              <div className="graph-node internet">
                Internet
              </div>

              <div className="graph-node gateway">
                API Gateway
              </div>

              <div className="graph-node ec2">
                EC2
              </div>

              <div className="graph-node lambda">
                Lambda
              </div>

              <div className="graph-node rds">
                RDS
              </div>

              <div className="graph-node s3">
                S3
              </div>

              <div className="graph-node iam">
                IAM
              </div>

              <svg
                className="attack-lines"
                viewBox="0 0 520 520"
              >
                <line x1="260" y1="40" x2="260" y2="135" />
                <line x1="260" y1="155" x2="140" y2="260" />
                <line x1="260" y1="155" x2="380" y2="260" />
                <line x1="140" y1="280" x2="160" y2="400" />
                <line x1="380" y1="280" x2="360" y2="400" />
                <line x1="260" y1="155" x2="260" y2="470" />
              </svg>

              <div className="pulse"></div>

            </div>

          </div>

        </div>
      </motion.div>
    </section>
  );
}