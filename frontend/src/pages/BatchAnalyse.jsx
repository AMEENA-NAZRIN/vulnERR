import React, { useState } from "react";
import Navbar from "../components/Navbar";

function BatchAnalyse() {

  const [file, setFile] = useState(null)

  const uploadZip = async () => {

    if (!file) {
      alert("Upload a ZIP file")
      return
    }

    const formData = new FormData()
    formData.append("file", file)
    formData.append("user_id", localStorage.getItem("user_id"))

    try {

      const response = await fetch(
        "http://127.0.0.1:5000/batch-upload",
        {
          method: "POST",
          body: formData
        }
      )

      if (!response.ok) {
        alert("Batch scan failed")
        return
      }

      const blob = await response.blob()

      const url = window.URL.createObjectURL(blob)

      const a = document.createElement("a")
      a.href = url
      a.download = "VulnERR_Batch_Report.pdf"
      a.click()

    } catch (err) {
      alert("Server error")
    }
  }

  return (
    <>
      <Navbar />

      <div style={{padding:"40px"}}>

        <h2>Batch ZIP Analysis</h2>

        <input
          type="file"
          accept=".zip"
          onChange={(e)=>setFile(e.target.files[0])}
        />

        <br/><br/>

        <button onClick={uploadZip}>
          Scan Project ZIP
        </button>

      </div>
    </>
  )
}

export default BatchAnalyse