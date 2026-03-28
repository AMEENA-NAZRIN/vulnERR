import React, { useState, useRef } from "react";
import Navbar from "../components/Navbar";
import "./UploadAnalyse.css";
import { marked } from "marked";

const ALLOWED_EXTENSIONS = [".py", ".js", ".java", ".cpp", ".c", ".zip"];

function UploadAnalyse() {
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [result, setResult] = useState(null);
  const [suggestions, setSuggestions] = useState("");
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [batchResults, setBatchResults] = useState([]);
  const [fileId, setFileId] = useState(null);

  const [openIndex, setOpenIndex] = useState(null);
  const [openFile, setOpenFile] = useState(null);
  const [openVuln, setOpenVuln] = useState(null);

  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const fileInputRef = useRef();

  // -------- FILE PROCESSING --------
  const processFile = (selectedFile) => {
    if (!selectedFile) return;

    const isAllowed = ALLOWED_EXTENSIONS.some((ext) =>
      selectedFile.name.endsWith(ext)
    );
    if (!isAllowed) {
      showToast(`Unsupported file type. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}`, "warn");
      return;
    }

    setFile(selectedFile);
    setResult(null);
    setSuggestions("");
    setVulnerabilities([]);
    setBatchResults([]);
    setFileId(null);

    if (!selectedFile.name.endsWith(".zip")) {
      const reader = new FileReader();
      reader.onload = (e) => setPreview(e.target.result.substring(0, 2000));
      reader.readAsText(selectedFile);
    } else {
      setPreview("");
    }
  };

  const handleFile = (e) => processFile(e.target.files[0]);
  const handleDrop = (e) => { e.preventDefault(); setDragOver(false); processFile(e.dataTransfer.files[0]); };

  // -------- TOAST --------
  const showToast = (message, type = "info") => {
    const toast = document.createElement("div");
    toast.className = `ua-toast ${type}`;
    toast.innerText = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add("show"), 50);
    setTimeout(() => { toast.classList.remove("show"); setTimeout(() => toast.remove(), 300); }, 3000);
  };

  // -------- PARSE AI HTML --------
  const parseSuggestions = (html) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    const vulns = [];
    const headings = doc.querySelectorAll("h3");
    headings.forEach((h3) => {
      let content = "";
      let node = h3.nextSibling;
      while (node && !(node.nodeType === 1 && node.tagName === "H3")) {
        if (node.nodeType === 3) content += `<p>${node.textContent}</p>`;
        if (node.nodeType === 1) content += node.outerHTML;
        node = node.nextSibling;
      }
      vulns.push({ title: h3.innerText, content });
    });
    setVulnerabilities(vulns);
  };

  // -------- ANALYZE --------
  const analyze = async () => {
    if (!file) { showToast("Select a file first.", "warn"); return; }

    setLoading(true);
    setResult(null);
    setSuggestions("");
    setVulnerabilities([]);
    setBatchResults([]);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_id", localStorage.getItem("user_id"));

    try {
      const response = await fetch("http://127.0.0.1:5000/upload", { method: "POST", body: formData });
      const data = await response.json();
      console.log("SERVER RESPONSE:", data);

      /* ---------- ZIP / BATCH ---------- */
      if (data.batch) {
        setBatchResults(data.files);
        setResult({
          status: "Batch Scan Complete",
          severity: "MULTIPLE",
          message: `${data.files.length} files analyzed`
        });
        setLoading(false);
        showToast("Batch analysis complete", "success");
        return;
      }

      /* ---------- SINGLE FILE ---------- */
      if (data.file_id) setFileId(data.file_id);

      setResult({ status: data.status, severity: data.severity, message: data.message });

      if (data.ai_suggestions) {
        let cleaned = data.ai_suggestions.replace(/```[a-zA-Z]*\n?/g, "").replace(/```/g, "");
        const htmlContent = marked.parse(cleaned);
        setSuggestions(htmlContent);
        parseSuggestions(htmlContent);
      }
      showToast("Analysis complete.", "success");

    } catch (err) {
      console.error(err);
      showToast("Error during analysis.", "error");
    }
    setLoading(false);
  };

  // -------- DOWNLOAD SINGLE FILE REPORT --------
  const downloadReport = async () => {
    if (!fileId) { showToast("Please analyse a file first.", "warn"); return; }

    const formData = new FormData();
    formData.append("file_id", fileId);
    formData.append("user_id", localStorage.getItem("user_id"));

    try {
      const response = await fetch("http://127.0.0.1:5000/download-report", { method: "POST", body: formData });
      if (!response.ok) { showToast("Error generating report.", "error"); return; }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${file.name}_report.pdf`;
      a.click();
      showToast("Report downloaded.", "success");
    } catch {
      showToast("Error generating report.", "error");
    }
  };

  // -------- DOWNLOAD INDIVIDUAL BATCH FILE REPORT --------
  const downloadFileReport = async (filename, fileId) => {
    const formData = new FormData();
    formData.append("filename", filename);
    formData.append("user_id", localStorage.getItem("user_id"));
    if (fileId) formData.append("file_id", fileId);

    try {
      const response = await fetch("http://127.0.0.1:5000/download-file-report", { method: "POST", body: formData });
      if (!response.ok) { showToast("Failed to download report.", "error"); return; }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${filename}_report.pdf`;
      a.click();
      showToast("File report downloaded", "success");
    } catch {
      showToast("Error downloading report.", "error");
    }
  };

  // -------- DOWNLOAD FULL BATCH REPORT --------
  const downloadBatchReport = async () => {
    // Collect all file_ids from the current batch results
    const fileIds = batchResults
      .map((f) => f.file_id)
      .filter(Boolean)
      .join(",");

    if (!fileIds) {
      showToast("No file IDs found. Please re-analyse the ZIP.", "warn");
      return;
    }

    const formData = new FormData();
    formData.append("file_ids", fileIds);
    formData.append("user_id", localStorage.getItem("user_id"));

    try {
      const response = await fetch("http://127.0.0.1:5000/download-batch-report", { method: "POST", body: formData });
      if (!response.ok) { showToast("Failed to download batch report.", "error"); return; }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "VulnERR_Batch_Report.pdf";
      a.click();
      showToast("Batch report downloaded", "success");
    } catch {
      showToast("Error downloading batch report.", "error");
    }
  };

  const severityColor = {
    CRITICAL: "#ff0055", HIGH: "#ff4444", MED: "#ffaa00",
    MEDIUM: "#ffaa00", LOW: "#00ff88", NONE: "#00ffff",
  };

  const isBatch = file && file.name.endsWith(".zip");

  return (
    <>
      <Navbar />
      <div className="ua-page">

        <div className="ua-header">
          <p className="ua-header-meta">VULNERABILITY SCANNER</p>
          <h1 className="ua-header-title">{isBatch ? "BATCH ANALYSIS" : "FILE ANALYSIS"}</h1>
        </div>

        <div className="ua-grid">

          {/* LEFT SIDE */}
          <div className="ua-left">

            <div
              className={`ua-dropzone ${dragOver ? "drag-over" : ""} ${file ? "has-file" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current.click()}
            >
              <input ref={fileInputRef} type="file" accept=".py,.js,.java,.cpp,.c,.zip" onChange={handleFile} style={{ display: "none" }} />
              <div className="dz-icon">{file ? "◈" : "⬆"}</div>
              <div className="dz-text">
                {file ? (
                  <>
                    <span className="dz-filename">{file.name}</span>
                    <span className="dz-filesize">{(file.size / 1024).toFixed(1)} KB</span>
                  </>
                ) : (
                  <>
                    <span className="dz-main">DROP FILE HERE</span>
                    <span className="dz-sub">or click to browse (.py, .js, .java, .cpp, .c, .zip)</span>
                  </>
                )}
              </div>
            </div>

            <div className="ua-actions">
              <button className="ua-btn primary" onClick={analyze} disabled={loading}>
                {loading ? (<><span className="btn-spinner" />SCANNING...</>) : ("⚡ ANALYSE")}
              </button>

              {/* Single file download */}
              {!isBatch && (
                <button className="ua-btn secondary" onClick={downloadReport} disabled={!fileId}>
                  ⬇ DOWNLOAD PDF
                </button>
              )}

              {/* Batch full report download */}
              {batchResults.length > 0 && (
                <button className="ua-btn secondary" onClick={downloadBatchReport}>
                  ⬇ FULL BATCH REPORT
                </button>
              )}
            </div>

            {result && (
              <div className="ua-result-card" style={{ "--sev-color": severityColor[result.severity] || "#00ffff" }}>
                <div className="rc-header">
                  <span className="rc-label">SCAN RESULT</span>
                  <span className="rc-severity">{result.severity}</span>
                </div>
                <div className="rc-status">{result.status}</div>
                <p className="rc-message">{result.message}</p>
              </div>
            )}
          </div>

          {/* RIGHT SIDE */}
          <div className="ua-right">

            {/* Single file: preview */}
            {preview && !isBatch && (
              <div className="ua-panel">
                <div className="panel-label">FILE PREVIEW</div>
                <pre className="ua-pre">{preview}</pre>
              </div>
            )}

            {/* Single file: AI suggestions */}
            {vulnerabilities.length > 0 && (
              <div className="ua-panel suggestions">
                <div className="panel-label">AI SUGGESTIONS</div>
                <div className="ua-suggestions-content">
                  {vulnerabilities.map((v, i) => (
                    <div key={i} className="vuln-card">
                      <div className="vuln-header" onClick={() => setOpenIndex(openIndex === i ? null : i)}>
                        <div className="vuln-title-wrap">
                          <span className="vuln-icon">⚠</span>
                          <span className="vuln-title-text">{v.title}</span>
                        </div>
                        <span className="vuln-toggle">{openIndex === i ? "▲" : "▼"}</span>
                      </div>
                      {openIndex === i && (
                        <div className="vuln-body" dangerouslySetInnerHTML={{ __html: v.content }} />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Batch results */}
            {batchResults.length > 0 && (
              <div className="ua-panel suggestions">
                <div className="panel-label">BATCH RESULTS</div>
                <div className="ua-suggestions-content">
                  {batchResults.map((f, index) => (
                    <div key={index} className="vuln-card">

                      <div className="vuln-header" onClick={() => setOpenFile(openFile === index ? null : index)}>
                        <div className="vuln-title-wrap">
                          <span className="vuln-icon">📂</span>
                          <span className="vuln-title-text">{f.filename}</span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <button
                            className="ua-btn secondary"
                            style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                            onClick={(e) => { e.stopPropagation(); downloadFileReport(f.filename, f.file_id); }}
                          >
                            ⬇ Report
                          </button>
                          <span className="vuln-toggle">{openFile === index ? "▲" : "▼"}</span>
                        </div>
                      </div>

                      {openFile === index && (
                        <div className="vuln-body">
                          {!f.vulnerabilities || f.vulnerabilities.length === 0 ? (
                            <p>No vulnerabilities detected</p>
                          ) : (
                            f.vulnerabilities.map((v, i) => (
                              <div key={i} className="vuln-card">
                                <div
                                  className="vuln-header"
                                  onClick={() => setOpenVuln(openVuln === `${index}-${i}` ? null : `${index}-${i}`)}
                                >
                                  <div className="vuln-title-wrap">
                                    <span className="vuln-icon">⚠</span>
                                    <span className="vuln-title-text">{v.title}</span>
                                  </div>
                                  <span className="vuln-toggle">{openVuln === `${index}-${i}` ? "▲" : "▼"}</span>
                                </div>
                                {openVuln === `${index}-${i}` && (
                                  <div className="vuln-body" dangerouslySetInnerHTML={{ __html: v.fix }} />
                                )}
                              </div>
                            ))
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!preview && vulnerabilities.length === 0 && batchResults.length === 0 && (
              <div className="ua-empty">
                <span className="empty-icon">⬡</span>
                <p>Upload a file to begin analysis</p>
              </div>
            )}

          </div>
        </div>
      </div>
    </>
  );
}

export default UploadAnalyse;
