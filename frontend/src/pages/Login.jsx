import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser } from "../auth";
import "./Auth.css";

function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch("http://127.0.0.1:5000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        // Save login info in localStorage
        loginUser(data.user_id, data.username);
        navigate("/dashboard");
      } else {
        setError(data.error || "Invalid credentials");
      }
    } catch (err) {
      setError("Server connection failed");
    }

    setLoading(false);
  };

  const handleKey = (e) => {
    if (e.key === "Enter") handleLogin();
  };

  return (
    <div className="auth-bg">
      <div className="auth-grid" />
      <div className="auth-glow" />

      <div className="auth-card">
        <div className="auth-header">
          <h1 className="auth-title">VULNERR</h1>
        </div>

        <div className="auth-divider"><span>AUTHENTICATE</span></div>

        <div className="auth-form">
          <div className="field-group">
            <label className="field-label">USER_ID</label>
            <input
              className="auth-input"
              placeholder="Enter username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={handleKey}
              autoComplete="username"
            />
          </div>

          <div className="field-group">
            <label className="field-label">PASSWORD</label>
            <input
              className="auth-input"
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={handleKey}
              autoComplete="current-password"
            />
          </div>

          {error && <div className="auth-error">⚠ {error}</div>}

          <button
            className="auth-btn primary"
            onClick={handleLogin}
            disabled={loading}
          >
            {loading
              ? <span className="btn-loading">VERIFYING<span className="dots" /></span>
              : "ACCESS SYSTEM"}
          </button>

          <button
            className="auth-btn ghost"
            onClick={() => navigate("/signup")}
          >
            CREATE NEW IDENTITY
          </button>
        </div>
      </div>
    </div>
  );
}

export default Login;