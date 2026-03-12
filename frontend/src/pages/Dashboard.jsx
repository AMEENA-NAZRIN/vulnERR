import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import "./Dashboard.css";

function Dashboard() {
  const username = localStorage.getItem("username");
  const userId = localStorage.getItem("user_id");
  const navigate = useNavigate();

  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [loadingProjects, setLoadingProjects] = useState(true);

  useEffect(() => {
    const fetchProjects = async () => {
      setLoadingProjects(true);
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
      } finally {
        setLoadingProjects(false);
      }
    };
    if (userId) fetchProjects();
  }, [userId]);

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
      <div className="db-page">

        {/* Header */}
        <div className="db-header">
          <div>
            <p className="db-header-meta">SECURITY OVERVIEW</p>
            <h1 className="db-header-title">DASHBOARD</h1>
          </div>
          <div className="db-welcome">
            <span className="db-welcome-label">OPERATOR</span>
            <span className="db-welcome-name">{username}</span>
          </div>
        </div>

        {/* Project Cards */}
        <div className="db-section-label">SCAN HISTORY</div>

        {loadingProjects ? (
          <div className="db-empty">
            <span className="db-spinner" />
            <p>LOADING RECORDS...</p>
          </div>
        ) : projects.length === 0 ? (
          <div className="db-empty">
            <span className="db-empty-icon">⬡</span>
            <p>NO FILES ANALYSED YET</p>
            <span className="db-empty-sub">
              Go to{" "}
              <span className="db-link" onClick={() => navigate("/uploadanalyse")}>
                Analyse
              </span>
              {" "}to upload a file and run a scan
            </span>
          </div>
        ) : (
          <div className="db-grid">
            {projects.map((project) => (
              <div
                key={project.id}
                className={`db-card ${selectedProject?.id === project.id ? "active" : ""}`}
                onClick={() => handleCardClick(project.id)}
              >
                <div className="db-card-top">
                  <span className="db-card-icon">◈</span>
                  <span className={`db-card-badge ${project.vulnerabilities > 0 ? "vuln" : "safe"}`}>
                    {project.vulnerabilities > 0 ? `${project.vulnerabilities} VULN` : "CLEAN"}
                  </span>
                </div>
                <div className="db-card-name">{project.name}</div>
                <div className="db-card-date">
                  {new Date(project.uploadedAt).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Loading detail */}
        {loadingDetail && (
          <div className="db-empty" style={{ marginTop: "2rem" }}>
            <span className="db-spinner" />
            <p>LOADING REPORT...</p>
          </div>
        )}

        {/* Detail Panel */}
        {selectedProject && !loadingDetail && (
          <div className="db-detail">

            <div className="db-detail-header">
              <div>
                <div className="db-section-label">SELECTED FILE</div>
                <div className="db-detail-filename">{selectedProject.filename}</div>
                <div className="db-detail-date">
                  Uploaded: {new Date(selectedProject.uploaded_at).toLocaleString()}
                </div>
              </div>
              <span className={`db-detail-badge ${selectedProject.vulnerabilities_found > 0 ? "vuln" : "safe"}`}>
                {selectedProject.vulnerabilities_found > 0
                  ? `${selectedProject.vulnerabilities_found} VULNERABILITIES`
                  : "NO VULNERABILITIES"}
              </span>
            </div>

            <div className="db-divider" />

            <div className="db-section-label">SOURCE CODE</div>
            <pre className="db-code">{selectedProject.code}</pre>

            <div className="db-divider" />

            <div className="db-section-label">ANALYSIS REPORT</div>
            {selectedProject.report_pdf ? (
              <iframe
                className="db-pdf"
                src={`data:application/pdf;base64,${selectedProject.report_pdf}`}
                title="Analysis Report"
              />
            ) : (
              <div className="db-no-report">
                <span>⬡</span>
                <p>NO REPORT AVAILABLE FOR THIS FILE</p>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

export default Dashboard;