import { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanResult from "./components/ScanResult";
import History from "./components/History";
import "./styles/index.css";

export default function App() {
  const [activeTab, setActiveTab] = useState("scan");
  const [scanResult, setScanResult] = useState(null);

  return (
    <div className="app">
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-icon">⬡</span>
            <span className="logo-text">CloudSec<span className="accent">Scanner</span></span>
          </div>
          <nav className="nav">
            {["scan", "history"].map((tab) => (
              <button
                key={tab}
                className={`nav-btn ${activeTab === tab ? "active" : ""}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab === "scan" ? "⚡ Scanner" : "📋 History"}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="main">
        {activeTab === "scan" && (
          <div className="scan-page">
            <ScanForm onResult={setScanResult} />
            {scanResult && <ScanResult report={scanResult} />}
          </div>
        )}
        {activeTab === "history" && <History onSelect={setScanResult} setTab={setActiveTab} />}
      </main>
    </div>
  );
}
