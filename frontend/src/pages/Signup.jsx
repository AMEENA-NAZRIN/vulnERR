import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Auth.css";

function Signup() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSignup = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch("http://127.0.0.1:5000/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });

      const data = await response.json();

      if (response.ok) {
        alert("User registered successfully");
        navigate("/");
      } else {
        setError(data.error || "Signup failed");
      }
    } catch (err) {
      console.error("Signup error:", err);
      setError("Server connection failed");
    }

    setLoading(false);
  };

  return (
    <div className="auth-bg">
      <div className="auth-grid" />
      <div className="auth-glow" style={{ left: "60%", top: "30%" }} />

      <div className="auth-card">
        <div className="auth-header">
          <h1 className="auth-title">VULNERR</h1>
          <p className="auth-subtitle">NEW IDENTITY REGISTRATION</p>
        </div>

        <div className="auth-divider"><span>REGISTER</span></div>

        <div className="auth-form">
          <div className="field-group">
            <label className="field-label">USER_ID</label>
            <input
              className="auth-input"
              placeholder="Choose username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <div className="field-group">
            <label className="field-label">EMAIL_ADDR</label>
            <input
              className="auth-input"
              placeholder="your@email.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="field-group">
            <label className="field-label">PASSKEY</label>
            <input
              className="auth-input"
              type="password"
              placeholder="Create password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && <div className="auth-error">⚠ {error}</div>}

          <button
            className="auth-btn primary"
            onClick={handleSignup}
            disabled={loading}
          >
            {loading
              ? <span className="btn-loading">REGISTERING<span className="dots" /></span>
              : "REGISTER IDENTITY"}
          </button>

          <button
            className="auth-btn ghost"
            onClick={() => navigate("/")}
          >
            BACK TO LOGIN
          </button>
        </div>
      </div>
    </div>
  );
}

export default Signup;