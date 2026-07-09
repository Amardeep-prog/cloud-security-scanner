import { Routes, Route, NavLink } from "react-router-dom";

import Home from "./pages/Home";
import Scanner from "./pages/Scanner";
import Reports from "./pages/Reports";
import Threats from "./pages/Threats";
import Dashboard from "./pages/Dashboard";
import ReportViewer from "./components/ReportViewer";

import "./styles/index.css";

export default function App() {
  return (
    <div className="app">

      <header className="header">
        <div className="header-inner">

          <div className="logo">
            <span className="logo-icon">⬡</span>

            <span className="logo-text">
              CloudSec<span className="accent">Scanner</span>
            </span>
          </div>

          <nav className="nav">

            <NavLink
              to="/"
              className={({ isActive }) =>
                `nav-btn ${isActive ? "active" : ""}`
              }
            >
              Home
            </NavLink>

            <NavLink
              to="/scan"
              className={({ isActive }) =>
                `nav-btn ${isActive ? "active" : ""}`
              }
            >
              Scanner
            </NavLink>

            <NavLink
              to="/threats"
              className={({ isActive }) =>
                `nav-btn ${isActive ? "active" : ""}`
              }
            >
              Threat Intel
            </NavLink>

            <NavLink
              to="/reports"
              className={({ isActive }) =>
                `nav-btn ${isActive ? "active" : ""}`
              }
            >
              Reports
            </NavLink>

            <NavLink
              to="/dashboard"
              className={({ isActive }) =>
                `nav-btn ${isActive ? "active" : ""}`
              }
            >
              Dashboard
            </NavLink>

          </nav>
        </div>
      </header>

      <Routes>
<Route
  path="/report/:scanId"
  element={<ReportViewer />}
/>
        <Route path="/" element={<Home />} />

        <Route path="/scan" element={<Scanner />} />

        <Route path="/threats" element={<Threats />} />

        <Route path="/reports" element={<Reports />} />

        <Route path="/dashboard" element={<Dashboard />} />

      </Routes>

    </div>
  );
}