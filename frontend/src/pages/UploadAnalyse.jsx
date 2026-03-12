import React, { useState, useRef } from "react";
import Navbar from "../components/Navbar";
import "./UploadAnalyse.css";
import { marked } from "marked";

function UploadAnalyse() {
const [file, setFile] = useState(null);
const [preview, setPreview] = useState("");
const [result, setResult] = useState(null);
const [suggestions, setSuggestions] = useState("");
const [vulnerabilities, setVulnerabilities] = useState([]);
const [openIndex, setOpenIndex] = useState(null);
const [loading, setLoading] = useState(false);
const [dragOver, setDragOver] = useState(false);

const fileInputRef = useRef();

// -------- FILE PROCESSING --------
const processFile = (selectedFile) => {
if (!selectedFile) return;

setFile(selectedFile);
setResult(null);
setSuggestions("");
setVulnerabilities([]);

const reader = new FileReader();
reader.onload = (e) => setPreview(e.target.result.substring(0, 2000));
reader.readAsText(selectedFile);

};

const handleFile = (e) => processFile(e.target.files[0]);

const handleDrop = (e) => {
e.preventDefault();
setDragOver(false);
processFile(e.dataTransfer.files[0]);
};

// -------- TOAST --------
const showToast = (message, type = "info") => {
const toast = document.createElement("div");
toast.className = `ua-toast ${type}`;
toast.innerText = message;

document.body.appendChild(toast);

setTimeout(() => toast.classList.add("show"), 50);

setTimeout(() => {
  toast.classList.remove("show");
  setTimeout(() => toast.remove(), 300);
}, 3000);

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

      if (node.nodeType === 3) {
        content += `<p>${node.textContent}</p>`;
      }

      if (node.nodeType === 1) {
        content += node.outerHTML;
      }

      node = node.nextSibling;
    }

    vulns.push({
      title: h3.innerText,
      content: content
    });
  });

  setVulnerabilities(vulns);
};

// -------- ANALYZE --------
const analyze = async () => {
if (!file) {
showToast("Select a file first.", "warn");
return;
}

setLoading(true);
setResult(null);
setSuggestions("");
setVulnerabilities([]);

const formData = new FormData();
formData.append("file", file);
formData.append("user_id", localStorage.getItem("user_id"));

try {
  const response = await fetch("http://127.0.0.1:5000/upload", {
    method: "POST",
    body: formData,
  });

  const data = await response.json();

  setResult({
    status: data.status,
    severity: data.severity,
    message: data.message,
  });

  if (data.ai_suggestions) {

  // remove markdown code fences
  let cleaned = data.ai_suggestions.replace(/```[a-zA-Z]*\n?/g, "")
                                    .replace(/```/g, "");

  // convert markdown → html
  const htmlContent = marked.parse(cleaned);

  setSuggestions(htmlContent);
  parseSuggestions(htmlContent);
}
  showToast("Analysis complete.", "success");
} catch {
  showToast("Error during analysis.", "error");
}

setLoading(false);

};

// -------- DOWNLOAD REPORT --------
const downloadReport = async () => {
if (!file) {
showToast("Select a file first.", "warn");
return;
}

const formData = new FormData();
formData.append("file", file);
formData.append("user_id", localStorage.getItem("user_id"));

try {
  const response = await fetch("http://127.0.0.1:5000/download-report", {
    method: "POST",
    body: formData,
  });

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "VulnERR_Report.pdf";
  a.click();

  showToast("Report downloaded.", "success");
} catch {
  showToast("Error generating report.", "error");
}


};

const severityColor = {
CRITICAL: "#ff0055",
HIGH: "#ff4444",
MED: "#ffaa00",
MEDIUM: "#ffaa00",
LOW: "#00ff88",
NONE: "#00ffff",
};

return (
<>
<Navbar />
  <div className="ua-page">

    <div className="ua-header">
      <p className="ua-header-meta">VULNERABILITY SCANNER</p>
      <h1 className="ua-header-title">FILE ANALYSIS</h1>
    </div>

    <div className="ua-grid">

      {/* LEFT SIDE */}
      <div className="ua-left">

        <div
          className={`ua-dropzone ${dragOver ? "drag-over" : ""} ${
            file ? "has-file" : ""
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFile}
            style={{ display: "none" }}
          />

          <div className="dz-icon">{file ? "◈" : "⬆"}</div>

          <div className="dz-text">
            {file ? (
              <>
                <span className="dz-filename">{file.name}</span>
                <span className="dz-filesize">
                  {(file.size / 1024).toFixed(1)} KB
                </span>
              </>
            ) : (
              <>
                <span className="dz-main">DROP FILE HERE</span>
                <span className="dz-sub">or click to browse</span>
              </>
            )}
          </div>
        </div>

        <div className="ua-actions">
          <button
            className="ua-btn primary"
            onClick={analyze}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="btn-spinner" />
                SCANNING...
              </>
            ) : (
              "⚡ ANALYSE"
            )}
          </button>

          <button className="ua-btn secondary" onClick={downloadReport}>
            ⬇ DOWNLOAD PDF
          </button>
        </div>

        {result && (
          <div
            className="ua-result-card"
            style={{
              "--sev-color": severityColor[result.severity] || "#00ffff",
            }}
          >
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

        {preview && (
          <div className="ua-panel">
            <div className="panel-label">FILE PREVIEW</div>
            <pre className="ua-pre">{preview}</pre>
          </div>
        )}

        {vulnerabilities.length > 0 && (
          <div className="ua-panel suggestions">
            <div className="panel-label">AI SUGGESTIONS</div>

            <div className="ua-suggestions-content">

              {vulnerabilities.map((v, i) => (
  <div key={i} className="vuln-card">

    <div
      className="vuln-header"
      onClick={() => setOpenIndex(openIndex === i ? null : i)}
    >
      <div className="vuln-title-wrap">
        <span className="vuln-icon">⚠</span>
        <span className="vuln-title-text">{v.title}</span>
      </div>

      <span className="vuln-toggle">
        {openIndex === i ? "▲" : "▼"}
      </span>
    </div>

    {openIndex === i && (
      <div
        className="vuln-body"
        dangerouslySetInnerHTML={{ __html: v.content }}
      />
    )}

  </div>
))}

            </div>
          </div>
        )}

        {!preview && vulnerabilities.length === 0 && (
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
