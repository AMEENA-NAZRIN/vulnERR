import React, { useState, useEffect } from "react";
import Navbar from "../components/Navbar";
import {
  Box, Grid, Card, Typography, Button,
  Modal, TextField, Chip, Divider, CircularProgress
} from "@mui/material";

function Dashboard() {
  const username = localStorage.getItem("username");
  const userId = localStorage.getItem("user_id");

  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [openModal, setOpenModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectDesc, setNewProjectDesc] = useState("");

  useEffect(() => {
    const fetchProjects = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/dashboard/${userId}`);
        const data = await res.json();
        const formatted = data.map((item) => ({
          id: item.id,
          name: item.filename,
          vulnerabilities: item.vulnerabilities_found ?? "N/A",
          uploadedAt: item.uploaded_at,
        }));
        setProjects(formatted);
      } catch (error) {
        console.error("Error fetching dashboard data:", error);
      }
    };
    if (userId) fetchProjects();
  }, [userId]);

  // Fetch full file + report when card is clicked
  const handleCardClick = async (projectId) => {
    setLoadingDetail(true);
    setSelectedProject(null);
    try {
      const res = await fetch(`http://127.0.0.1:5000/report/${projectId}`);
      const data = await res.json();
      setSelectedProject(data);
    } catch (error) {
      console.error("Error fetching report details:", error);
    } finally {
      setLoadingDetail(false);
    }
  };

  return (
    <>
      <Navbar />
      <Box sx={{ maxWidth: 1200, margin: "2rem auto", padding: "1rem" }}>

        {/* Header */}
        <Box sx={{ display: "flex", justifyContent: "space-between", mb: 3 }}>
          <Typography variant="h4">Welcome, {username}!</Typography>
        </Box>

        {/* Project Cards */}
        <Grid container spacing={4}>
          {projects.map((project) => (
            <Grid item xs={12} sm={6} key={project.id}>
              <Card
                sx={{
                  cursor: "pointer",
                  height: 150,
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                  p: 3,
                  borderRadius: 3,
                  boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
                  transition: "transform 0.2s, box-shadow 0.2s",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: "0 8px 20px rgba(0,0,0,0.25)",
                  },
                }}
                onClick={() => handleCardClick(project.id)}
              >
                <Typography variant="h5" gutterBottom>{project.name}</Typography>
                <Typography variant="body1" color="text.secondary">
                  Vulnerabilities Found: {project.vulnerabilities}
                </Typography>
                <Typography variant="caption" color="text.disabled">
                  {new Date(project.uploadedAt).toLocaleString()}
                </Typography>
              </Card>
            </Grid>
          ))}
        </Grid>

        {/* Detail Panel */}
        {loadingDetail && (
          <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
            <CircularProgress />
          </Box>
        )}

      {selectedProject && !loadingDetail && (
  <Box sx={{ mt: 4, p: 3, border: "1px solid #ccc", borderRadius: 2 }}>

    {/* File Info */}
    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      <Typography variant="h5">{selectedProject.filename}</Typography>
      <Chip
        label={`${selectedProject.vulnerabilities_found ?? 0} Vulnerabilities`}
        color={selectedProject.vulnerabilities_found > 0 ? "error" : "success"}
      />
    </Box>

    <Typography variant="caption" color="text.secondary">
      Uploaded: {new Date(selectedProject.uploaded_at).toLocaleString()}
    </Typography>

    <Divider sx={{ my: 2 }} />

    {/* Source Code */}
    <Typography variant="h6" gutterBottom>Source Code</Typography>
    <Box
      component="pre"
      sx={{
        p: 2,
        bgcolor: "#1e1e1e",
        color: "#d4d4d4",
        borderRadius: 1,
        overflowX: "auto",
        fontSize: "0.85rem",
        maxHeight: 400,
        overflowY: "auto",
      }}
    >
      {selectedProject.code}
    </Box>

    <Divider sx={{ my: 2 }} />

    {/* Inline PDF Report */}
    <Typography variant="h6" gutterBottom>Analysis Report</Typography>
    {selectedProject.report_pdf ? (
      <Box
        component="iframe"
        src={`data:application/pdf;base64,${selectedProject.report_pdf}`}
        sx={{
          width: "100%",
          height: 600,
          border: "none",
          borderRadius: 1,
        }}
        title="Analysis Report"
      />
    ) : (
      <Typography color="text.secondary">No report available for this file.</Typography>
    )}

  </Box>
)}
      </Box>

      {/* Modal */}
      <Modal open={openModal} onClose={() => setOpenModal(false)}>
        <Box sx={{
          position: "absolute", top: "50%", left: "50%",
          transform: "translate(-50%, -50%)", width: 400,
          bgcolor: "background.paper", boxShadow: 24, p: 4, borderRadius: 2,
        }}>
          <Typography variant="h6" mb={2}>Create New Project</Typography>
          <TextField fullWidth label="Project Name" value={newProjectName}
            onChange={(e) => setNewProjectName(e.target.value)} sx={{ mb: 2 }} />
          <TextField fullWidth label="Description" value={newProjectDesc}
            onChange={(e) => setNewProjectDesc(e.target.value)} sx={{ mb: 2 }} />
          <Box sx={{ display: "flex", justifyContent: "flex-end" }}>
            <Button onClick={() => setOpenModal(false)} sx={{ mr: 1 }}>Cancel</Button>
            <Button variant="contained" onClick={() => setOpenModal(false)}>Add Project</Button>
          </Box>
        </Box>
      </Modal>
    </>
  );
}

export default Dashboard;