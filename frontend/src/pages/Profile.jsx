import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import "./Profile.css";

function Profile() {
  const userId = localStorage.getItem("user_id");
  const navigate = useNavigate();

  const [user, setUser]               = useState(null);
  const [editMode, setEditMode]       = useState(false);
  const [loading, setLoading]         = useState(true);
  const [saving, setSaving]           = useState(false);
  const [avatarPreview, setAvatarPreview] = useState(null);
  const [toast, setToast]             = useState(null);
  const fileInputRef                  = useRef();

  // ── fetch user on mount ────────────────────────────────────────────────────
  useEffect(() => {
    if (!userId) {
      navigate("/");
      return;
    }
    const fetchUser = async () => {
      try {
        const res  = await fetch(`http://127.0.0.1:5000/user/${userId}`);
        const data = await res.json();
        setUser({ ...data, password: "" }); // never prefill password
        if (data.avatar) setAvatarPreview(data.avatar);
      } catch (err) {
        console.error("Error fetching user:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, [userId, navigate]);

  // ── toast helper ──────────────────────────────────────────────────────────
  const showToast = (msg, type = "info") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  // ── input change ──────────────────────────────────────────────────────────
  const handleChange = (e) => {
    const { name, value } = e.target;
    setUser((prev) => ({ ...prev, [name]: value }));
  };

  // ── avatar change ─────────────────────────────────────────────────────────
  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setAvatarPreview(ev.target.result);
    reader.readAsDataURL(file);
  };

  // ── cancel edit ───────────────────────────────────────────────────────────
  const handleCancel = () => {
    setEditMode(false);
    setUser((prev) => ({ ...prev, password: "" }));
  };

  // ── save to backend ───────────────────────────────────────────────────────
  const handleSave = async () => {
    if (!user) return;
    setSaving(true);

    try {
      const payload = {
        username: user.username,
        email:    user.email,
      };

      // only send password if user actually typed one
      if (user.password && user.password.trim() !== "") {
        payload.password = user.password;
      }

      // send avatar as base64 if changed
      if (avatarPreview) {
        payload.avatar = avatarPreview;
      }

      const res = await fetch(`http://127.0.0.1:5000/user/${userId}`, {
        method:  "PUT",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });

      if (!res.ok) {
        showToast("Failed to save changes.", "error");
      } else {
        const updated = await res.json();
        setUser({ ...updated, password: "" });
        if (updated.avatar) setAvatarPreview(updated.avatar);
        setEditMode(false);
        showToast("Profile updated successfully.", "success");
      }
    } catch (err) {
      console.error("Error saving profile:", err);
      showToast("Connection error.", "error");
    } finally {
      setSaving(false);
    }
  };

  // ── logout ────────────────────────────────────────────────────────────────
  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  // ── loading state ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <>
        <Navbar />
        <div className="pf-page">
          <div className="pf-empty">
            <span className="pf-spinner" />
            <span>LOADING PROFILE...</span>
          </div>
        </div>
      </>
    );
  }

  // ── user not found ────────────────────────────────────────────────────────
  if (!user) {
    return (
      <>
        <Navbar />
        <div className="pf-page">
          <div className="pf-empty">
            <span className="pf-empty-icon">⬡</span>
            <span>USER NOT FOUND</span>
          </div>
        </div>
      </>
    );
  }

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <>
      <Navbar />
      <div className="pf-page">

        {/* Toast */}
        {toast && (
          <div className={`ua-toast ${toast.type} show`} style={{
            position: "fixed", bottom: 24, right: 24,
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: 12, letterSpacing: 1,
            padding: "12px 20px", borderRadius: 4,
            border: "1px solid",
            zIndex: 9999,
            background: toast.type === "success" ? "rgba(0,40,20,0.95)"
                      : toast.type === "error"   ? "rgba(40,0,10,0.95)"
                      : "rgba(5,5,16,0.95)",
            color:  toast.type === "success" ? "#00ff88"
                  : toast.type === "error"   ? "#ff4444"
                  : "#00ffff",
            borderColor: toast.type === "success" ? "rgba(0,255,136,0.3)"
                       : toast.type === "error"   ? "rgba(255,68,68,0.3)"
                       : "rgba(0,255,255,0.25)",
          }}>
            {toast.msg}
          </div>
        )}

        {/* Header */}
        <div className="pf-header">
          <div>
            <p className="pf-header-meta">ACCOUNT SETTINGS</p>
            <h1 className="pf-header-title">PROFILE</h1>
          </div>
          <button className="pf-logout-btn" onClick={handleLogout}>
            ⏻ LOGOUT
          </button>
        </div>

        <div className="pf-body">

          {/* ── Avatar Column ── */}
          <div className="pf-avatar-section">
            <div
              className="pf-avatar"
              onClick={() => editMode && fileInputRef.current.click()}
              style={{ cursor: editMode ? "pointer" : "default" }}
            >
              {avatarPreview ? (
                <img src={avatarPreview} alt="avatar" className="pf-avatar-img" />
              ) : (
                <span>{user.username?.[0]?.toUpperCase() || "U"}</span>
              )}
              {editMode && (
                <div className="pf-avatar-overlay">⬆ UPLOAD</div>
              )}
            </div>

            {/* hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              style={{ display: "none" }}
              onChange={handleAvatarChange}
            />

            <div className="pf-avatar-name">{user.username}</div>
            <div className="pf-avatar-sub">OPERATOR</div>
          </div>

          {/* ── Form Column ── */}
          <div className="pf-form-section">
            <div className="pf-section-label">USER DETAILS</div>

            <div className="pf-fields">
              <div className="pf-field">
                <label className="pf-label">USERNAME</label>
                <input
                  className="pf-input"
                  name="username"
                  value={user.username || ""}
                  onChange={handleChange}
                  disabled={!editMode}
                />
              </div>

              <div className="pf-field">
                <label className="pf-label">EMAIL ADDRESS</label>
                <input
                  className="pf-input"
                  name="email"
                  type="email"
                  value={user.email || ""}
                  onChange={handleChange}
                  disabled={!editMode}
                />
              </div>

              {/* password field only visible in edit mode */}
              {editMode && (
                <div className="pf-field">
                  <label className="pf-label">NEW PASSWORD</label>
                  <input
                    className="pf-input"
                    name="password"
                    type="password"
                    placeholder="Leave blank to keep current"
                    value={user.password || ""}
                    onChange={handleChange}
                  />
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="pf-actions">
              {editMode ? (
                <>
                  <button
                    className="pf-btn primary"
                    onClick={handleSave}
                    disabled={saving}
                  >
                    {saving && <span className="pf-spinner-sm" />}
                    {saving ? "SAVING..." : "⬆ SAVE CHANGES"}
                  </button>
                  <button className="pf-btn secondary" onClick={handleCancel}>
                    CANCEL
                  </button>
                </>
              ) : (
                <button
                  className="pf-btn primary"
                  onClick={() => setEditMode(true)}
                >
                  ✎ EDIT PROFILE
                </button>
              )}
            </div>
          </div>

        </div>
      </div>
    </>
  );
}

export default Profile;