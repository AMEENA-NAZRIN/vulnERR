import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import "./Dashboard.css";
import {
  Box, Grid, Card, Typography, Chip, Divider,
  CircularProgress, Collapse, IconButton
} from "@mui/material";
import FolderIcon from "@mui/icons-material/Folder";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";

function Dashboard() {
  const username = localStorage.getItem("username");
  const userId = localStorage.getItem("user_id");

  const [items, setItems] = useState([]);
  const [loadingList, setLoadingList] = useState(true);

  // Which batch folders are open
  const [openBatches, setOpenBatches] = useState({});
  // Which file detail panels are open (keyed by file id)
  const [openFiles, setOpenFiles] = useState({});
  // Loaded report detail per file id
  const [fileDetails, setFileDetails] = useState({});
  const [loadingFile, setLoadingFile] = useState({});

  // Ensure page scroll is always enabled - fix any CSS that locks scroll
  useEffect(() => {
    const els = [document.body, document.documentElement, document.getElementById("root")];
    els.forEach(el => {
      if (el) {
        el.style.overflow = "auto";
        el.style.height = "auto";
        el.style.maxHeight = "none";
        el.style.position = "static";
      }
    });
    return () => {
      els.forEach(el => {
        if (el) {
          el.style.overflow = "";
          el.style.height = "";
          el.style.maxHeight = "";
          el.style.position = "";
        }
      });
    };
  }, []);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/dashboard/${userId}`);
        const data = await res.json();
        setItems(data);
      } catch (err) {
        console.error("Error fetching dashboard:", err);
      } finally {
        setLoadingList(false);
      }
    };
    if (userId) fetchDashboard();
  }, [userId]);

  const toggleBatch = (batchId) => {
    setOpenBatches((prev) => ({ ...prev, [batchId]: !prev[batchId] }));
  };

  const fileRefs = React.useRef({});

  const toggleFile = async (fileId) => {
    const isOpen = openFiles[fileId];
    setOpenFiles((prev) => ({ ...prev, [fileId]: !isOpen }));

    // Fetch details only once
    if (!isOpen && !fileDetails[fileId]) {
      setLoadingFile((prev) => ({ ...prev, [fileId]: true }));
      try {
        const res = await fetch(`http://127.0.0.1:5000/report/${fileId}`);
        const data = await res.json();
        setFileDetails((prev) => ({ ...prev, [fileId]: data }));
      } catch (err) {
        console.error("Error fetching file report:", err);
      } finally {
        setLoadingFile((prev) => ({ ...prev, [fileId]: false }));
      }
    }

    // Scroll the card into view after state update
    if (!isOpen) {
      setTimeout(() => {
        fileRefs.current[fileId]?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 100);
    }
  };

  const downloadPdf = (fileId, filename) => {
    const detail = fileDetails[fileId];
    if (!detail?.report_pdf) return;
    const byteChars = atob(detail.report_pdf);
    const byteNums = Array.from(byteChars).map((c) => c.charCodeAt(0));
    const blob = new Blob([new Uint8Array(byteNums)], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${filename}_report.pdf`;
    a.click();
  };

  /* ---- STYLES ---- */
  const cardStyle = {
    borderRadius: 3,
    boxShadow: "0 2px 8px rgba(0,0,0,0.10)",
    transition: "transform 0.15s, box-shadow 0.15s",
    "&:hover": { transform: "translateY(-3px)", boxShadow: "0 6px 18px rgba(0,0,0,0.18)" },
    overflow: "hidden",
  };

  const vulnChip = (count) => (
    <Chip
      icon={count > 0 ? <BugReportIcon /> : <CheckCircleIcon />}
      label={`${count ?? 0} vuln${count !== 1 ? "s" : ""}`}
      size="small"
      color={count > 0 ? "error" : "success"}
      variant="outlined"
    />
  );

  /* ---- FILE DETAIL PANEL ---- */
  const FileDetailPanel = ({ fileId, filename }) => {
    const detail = fileDetails[fileId];
    const loading = loadingFile[fileId];

    if (loading) return (
      <Box sx={{ display: "flex", justifyContent: "center", p: 3 }}>
        <CircularProgress size={28} />
      </Box>
    );

    if (!detail) return null;

    return (
      <Box sx={{ p: 2, bgcolor: "#f9f9f9", borderTop: "1px solid #eee" }}>

        {/* Source code */}
        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>Source Code</Typography>
        <Box component="pre" className="dashboard-code-box" sx={{
          p: 2, bgcolor: "#1e1e1e", color: "#d4d4d4",
          borderRadius: 1, fontSize: "0.8rem", mb: 2
        }}>
          {detail.code}
        </Box>

        <Divider sx={{ mb: 2 }} />

        {/* PDF report */}
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Analysis Report</Typography>
          {detail.report_pdf && (
            <Chip
              label="⬇ Download PDF"
              onClick={() => downloadPdf(fileId, filename)}
              clickable
              color="primary"
              size="small"
              variant="outlined"
            />
          )}
        </Box>

        {detail.report_pdf ? (
          <Box component="iframe"
            className="dashboard-pdf-frame"
            src={`data:application/pdf;base64,${detail.report_pdf}`}
            sx={{}}
            title="Analysis Report"
          />
        ) : (
          <Typography color="text.secondary" variant="body2">No report available.</Typography>
        )}
      </Box>
    );
  };

  /* ---- FILE ROW (used inside batch folders and as standalone cards) ---- */
  const FileRow = ({ file, standalone = false }) => {
    const isOpen = openFiles[file.id];
    const vulns = file.vulnerabilities_found ?? 0;

    return (
      <Card
        ref={(el) => { fileRefs.current[file.id] = el; }}
        sx={{ ...cardStyle, mb: standalone ? 0 : 1 }}
      >
        <Box
          sx={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            p: 2, cursor: "pointer",
            bgcolor: standalone ? "white" : "#fafafa"
          }}
          onClick={() => toggleFile(file.id)}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <InsertDriveFileIcon sx={{ color: vulns > 0 ? "#d32f2f" : "#388e3c" }} />
            <Box>
              <Typography variant={standalone ? "h6" : "body1"} fontWeight={600}>
                {file.filename}
              </Typography>
              <Typography variant="caption" color="text.disabled">
                {file.uploaded_at ? new Date(file.uploaded_at).toLocaleString() : ""}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {vulnChip(vulns)}
            <IconButton size="small">
              {isOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>
        </Box>

        <Collapse in={isOpen}>
          <FileDetailPanel fileId={file.id} filename={file.filename} />
        </Collapse>
      </Card>
    );
  };

  /* ---- BATCH FOLDER CARD ---- */
  const BatchCard = ({ batch }) => {
    const isOpen = openBatches[batch.batch_id];

    return (
      <Card sx={{ ...cardStyle }}>
        {/* Folder header */}
        <Box
          sx={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            p: 2.5, cursor: "pointer",
            bgcolor: isOpen ? "#e3f2fd" : "white"
          }}
          onClick={() => toggleBatch(batch.batch_id)}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <FolderIcon sx={{ color: "#1976d2", fontSize: 32 }} />
            <Box>
              <Typography variant="h6" fontWeight={600}>
                {batch.zip_filename || `ZIP Batch`}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {batch.file_count} file{batch.file_count !== 1 ? "s" : ""} &nbsp;·&nbsp;
                {batch.uploaded_at ? new Date(batch.uploaded_at).toLocaleString() : ""}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {vulnChip(batch.total_vulnerabilities)}
            <IconButton size="small">
              {isOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>
        </Box>

        {/* Files inside folder */}
        <Collapse in={isOpen}>
          <Box sx={{ p: 2, bgcolor: "#f5f5f5" }}>
            {batch.files.map((f) => (
              <FileRow key={f.id} file={f} standalone={false} />
            ))}
          </Box>
        </Collapse>
      </Card>
    );
  };

  /* ---- RENDER ---- */
  return (
    <>
      <Navbar />
      <Box sx={{ maxWidth: 1200, margin: "2rem auto", padding: "1rem" }}>

        <Typography variant="h4" sx={{ mb: 3 }}>Welcome, {username}!</Typography>

        {loadingList ? (
          <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
            <CircularProgress />
          </Box>
        ) : items.length === 0 ? (
          <Typography color="text.secondary">No files analysed yet. Go to Analyse to get started.</Typography>
        ) : (
          <Grid container spacing={3}>
            {items.map((item, idx) => (
              <Grid item xs={12} key={idx}>
                {item.type === "batch"
                  ? <BatchCard batch={item} />
                  : <FileRow file={item} standalone />
                }
              </Grid>
            ))}
          </Grid>
        )}

      </Box>
    </>
  );
}

export default Dashboard;