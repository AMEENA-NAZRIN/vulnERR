import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useTheme } from "../App";
import "./Navbar.css";

function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useTheme();

  const navLinks = [
    { path: "/dashboard", label: "DASHBOARD" },
    { path: "/profile", label: "PROFILE" },
    { path: "/uploadanalyse", label: "ANALYSE" },
  ];

  return (
    <nav className="navbar">
      <div className="navbar-brand" onClick={() => navigate("/dashboard")}>
        <span className="brand-icon">⬡</span>
        <span className="brand-text">VULN<span className="brand-accent">ERR</span></span>
      </div>

      <div className="navbar-links">
        {navLinks.map(link => (
          <button
            key={link.path}
            className={`nav-link ${location.pathname === link.path ? "active" : ""}`}
            onClick={() => navigate(link.path)}
          >
            {link.label}
          </button>
        ))}
      </div>

      <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme">
        {isDark ? "☀" : "☾"}
      </button>
    </nav>
  );
}

export default Navbar;
