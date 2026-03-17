import React, { useState, useEffect } from "react";
import Navbar from "../components/Navbar";
import { TextField, Button, Box, CircularProgress } from "@mui/material";
import "./Profile.css";

function Profile() {
  const userId = localStorage.getItem("user_id");

  const [user, setUser] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [loading, setLoading] = useState(true);

  // Fetch logged-in user from backend
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/user/${userId}`);
        const data = await res.json();
        setUser(data);
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

  //  Save profile changes to backend
  const handleSave = async () => {
    try {
      await fetch(`http://127.0.0.1:5000/user/${userId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(user),
      });

      setEditMode(false);
    } catch (error) {
      console.error("Error updating profile:", error);
    }
  };

  return (
    <>
      <Navbar />
      <div className="profile-page">
        {/* Header with avatar */}
        <div className="profile-header">
          <div className="profile-avatar">
            <span>{user.username?.[0]?.toUpperCase() || "U"}</span>
          </div>
          <div className="profile-info">
            <p className="profile-meta">USER PROFILE</p>
            
          </div>
        </div>

        {/* Form */}
        <Box
          component="form"
          sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 3 }}
          noValidate
          autoComplete="off"
        >
          
          <TextField
            label="Username"
            name="username"
            value={user.username}
            onChange={handleChange}
            disabled={!editMode}
          />
          <TextField
            label="Email"
            name="email"
            value={user.email}
            onChange={handleChange}
            disabled={!editMode}
          />

          {editMode ? (
            <Box sx={{ display: "flex", gap: 1 }}>
              <Button variant="contained" onClick={handleSave}>
                Save
              </Button>
              <Button variant="outlined" onClick={() => setEditMode(false)}>
                Cancel
              </Button>
            </Box>
          ) : (
            <Button variant="contained" onClick={() => setEditMode(true)}>
              Edit Profile
            </Button>
          )}
        </Box>
      </div>
    </>
  );
}

export default Profile;