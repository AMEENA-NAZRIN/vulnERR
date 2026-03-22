import React, { useState, useEffect, useRef, useNavigate } from "react";
import Navbar from "../components/Navbar";
import { TextField, Button, Box, CircularProgress } from "@mui/material";
import "./Profile.css";

function Profile() {
  const userId = localStorage.getItem("user_id");
  const navigate = useNavigate();

  const [user, setUser] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [avatarPreview, setAvatarPreview] = useState(null);
  const fileInputRef = useRef();

  const usageOptions = [
    { value: "personal", label: "PERSONAL PROJECT" },
    { value: "college", label: "COLLEGE / ACADEMIC" },
    { value: "work", label: "WORK / PROFESSIONAL" },
  ];

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/user/${userId}`);
        const data = await res.json();
        setUser({ ...data, usage: data.usage || "" });
      } catch (error) {
        console.error("Error fetching user:", error);
      } finally {
        setLoading(false);
      }
    };

    if (userId) fetchUser();
  }, [userId]);

  //  Show loading spinner while fetching
  if (loading) {
    return (
      <>
        <Navbar />
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress />
        </Box>
      </>
    );
  }

  //  If user not found
  if (!user) {
    return (
      <>
        <Navbar />
        <div style={{ textAlign: "center", marginTop: "50px" }}>
          User not found.
        </div>
      </>
    );
  }

  // Input change handler
  const handleChange = (e) => {
    const { name, value } = e.target;
    setUser({ ...user, [name]: value });
  };

  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setAvatarPreview(ev.target.result);
    reader.readAsDataURL(file);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await fetch(`http://127.0.0.1:5000/user/${userId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(user),
      });
      setEditMode(false);
    } catch (error) {
      console.error("Error updating profile:", error);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <>
        <Navbar />
        <div className="pf-page">
          <div className="pf-empty">
            <span className="pf-spinner" />
            <p>LOADING PROFILE...</p>
          </div>
        </div>
      </>
    );
  }

  if (!user) {
    return (
      <>
        <Navbar />
        <div className="pf-page">
          <div className="pf-empty">
            <span className="pf-empty-icon">⬡</span>
            <p>USER NOT FOUND</p>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <div className="pf-page">

        {/* Header */}
        <div className="pf-header">
          <div>
            <p className="pf-header-meta">ACCOUNT SETTINGS</p>
            <h1 className="pf-header-title">PROFILE</h1>
          </div>
        </div>

        <div className="pf-body">

          {/* Avatar Section */}
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

          {/* Form Section */}
          <div className="pf-form-section">

            {/* User Details */}
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
                  value={user.email || ""}
                  onChange={handleChange}
                  disabled={!editMode}
                />
              </div>

              {editMode && (
                <div className="pf-field">
                  <label className="pf-label">NEW PASSWORD</label>
                  <input
                    className="pf-input"
                    name="password"
                    type="password"
                    placeholder="Leave blank to keep current"
                    onChange={handleChange}
                    disabled={!editMode}
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
                    {saving ? <span className="pf-spinner-sm" /> : null}
                    {saving ? "SAVING..." : "⬆ SAVE CHANGES"}
                  </button>
                  <button
                    className="pf-btn secondary"
                    onClick={() => setEditMode(false)}
                  >
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