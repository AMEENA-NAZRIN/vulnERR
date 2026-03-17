import React, { useMemo, useState, createContext, useContext, useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import UploadAnalyse from "./pages/UploadAnalyse";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import Profile from "./pages/Profile";
import "./App.css";
import BatchAnalyse from "./pages/BatchAnalyse"

export const ThemeContext = createContext();

export function useTheme() {
  return useContext(ThemeContext);
}

function App() {
  const [isDark, setIsDark] = useState(() => {
    return localStorage.getItem("theme") !== "light";
  });

  useEffect(() => {
    if (isDark) {
      document.body.classList.remove("light-mode");
      document.body.classList.add("dark-mode");
    } else {
      document.body.classList.remove("dark-mode");
      document.body.classList.add("light-mode");
    }
    localStorage.setItem("theme", isDark ? "dark" : "light");
  }, [isDark]);

  const toggleTheme = () => setIsDark(prev => !prev);

  return (
    <ThemeContext.Provider value={{ isDark, toggleTheme }}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/uploadanalyse" element={<UploadAnalyse />} />
          <Route path="/batch-upload" element={<BatchAnalyse />} />
        </Routes>
      </BrowserRouter>
    </ThemeContext.Provider>
  );
}

export default App;
