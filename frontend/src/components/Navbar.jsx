import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useTheme } from "../App";
import "./Navbar.css";
import { logoutUser } from "../auth";


function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useTheme();

  
  const navLinks = [
    { path: "/dashboard", label: "DASHBOARD" },
    { path: "/profile", label: "PROFILE" },
    { path: "/uploadanalyse", label: "ANALYSE" },
  ];

  const handleLogout = () => {
    logoutUser();
    navigate("/");
  };

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

      <div className="navbar-right">
        <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme">
          {isDark ? "☀" : "☾"}
        </button>
        <button className="nav-logout" onClick={handleLogout} title="Logout">
          <span className="logout-icon">⏻</span>
          LOGOUT
        </button>
      </div>
    </nav>
  );
}

export default Navbar;
