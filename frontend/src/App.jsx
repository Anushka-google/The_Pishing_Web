import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import HeroBanner from './components/HeroBanner';
import StatsOverview from './components/StatsOverview';
import UrlAnalyzer from './components/UrlAnalyzer';
import ResultCard from './components/ResultCard';
import FeatureAnalysis from './components/FeatureAnalysis';
import EmailAnalyzerTab from './components/EmailAnalyzerTab';
import TelemetryTab from './components/TelemetryTab';
import HistoryTable from './components/HistoryTable';

const API_BASE = import.meta.env.VITE_API_URL !== undefined 
  ? import.meta.env.VITE_API_URL 
  : (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
      ? 'http://127.0.0.1:8000' 
      : '');

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [systemHealth, setSystemHealth] = useState(false);
  const [modelVersion, setModelVersion] = useState('v1');
  const [enhancedMode, setEnhancedMode] = useState(true);

  // Loading and error states
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Email Analyzer states
  const [emailResult, setEmailResult] = useState(null);
  const [isEmailLoading, setIsEmailLoading] = useState(false);
  const [emailError, setEmailError] = useState(null);

  useEffect(() => {
    checkHealth();
    fetchStats();
    fetchHistory();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setSystemHealth(data.status === 'healthy');
        if (data.model_version) {
          setModelVersion(data.model_version);
        }
      } else {
        setSystemHealth(false);
      }
    } catch {
      setSystemHealth(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('Failed to fetch stats:', err);
    }
  };

  const fetchHistory = async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch(`${API_BASE}/history?limit=30`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.records || []);
      }
    } catch (err) {
      console.warn('Failed to fetch history:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // URL Analysis (Standard or Phase 29 Multi-Signal Enhanced Mode)
  const handleAnalyze = async (url) => {
    setIsLoading(true);
    setError(null);

    try {
      if (enhancedMode) {
        // Phase 29 Multi-Signal Enhanced Inspection
        const res = await fetch(`${API_BASE}/analyze/enhanced`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            enable_reputation: true,
            enable_dns: true,
            enable_whois: true
          })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Enhanced URL analysis request failed.');
        }

        // Also fetch base prediction with SHAP explanations for deep feature inspector
        let baseWithExplanation = null;
        try {
          const predRes = await fetch(`${API_BASE}/predict?include_explanation=true`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
          });
          if (predRes.ok) {
            baseWithExplanation = await predRes.json();
          }
        } catch {
          // Fallback to base
        }

        // Fuse both responses
        setResult({
          ...data,
          probability: data.ml_probability,
          fused_probability: data.fused_probability,
          risk_level: data.final_risk_level,
          action: data.final_action,
          explanation: baseWithExplanation?.explanation || null,
          features: baseWithExplanation?.features || null,
          metadata: baseWithExplanation?.metadata || {
            model_name: 'RandomForest + MultiSignal',
            model_version: modelVersion,
            total_latency_ms: data.execution_time_ms
          }
        });
      } else {
        // Standard Zero-Leakage ML Model & SHAP
        const res = await fetch(`${API_BASE}/predict?include_explanation=true`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });

        const data = await res.json();
        if (!res.ok) {
          if (data.details && Array.isArray(data.details)) {
            throw new Error(data.details[0]?.message || 'Invalid URL entered.');
          }
          throw new Error(data.detail || 'Analysis request failed.');
        }

        setResult(data);
      }

      // Refresh platform metrics and history
      fetchStats();
      fetchHistory();
    } catch (err) {
      setError(err.message || 'Network error connecting to detection backend.');
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  // Phase 29.4 Email Phishing Analysis
  const handleAnalyzeEmail = async (emailPayload) => {
    setIsEmailLoading(true);
    setEmailError(null);

    try {
      const res = await fetch(`${API_BASE}/analyze/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload)
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Email phishing analysis failed.');
      }

      setEmailResult(data);
      fetchStats();
      fetchHistory();
    } catch (err) {
      setEmailError(err.message || 'Network error analyzing email payload.');
      setEmailResult(null);
    } finally {
      setIsEmailLoading(false);
    }
  };

  const handleSelectFromHistory = (url) => {
    setActiveTab('scanner');
    handleAnalyze(url);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#050811' }}>
      {/* Cybersecurity Sticky Command Bar */}
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        systemHealth={systemHealth}
        modelVersion={modelVersion}
      />

      {/* Main Command Center Surface */}
      <main style={{ flex: 1, padding: '2rem 0' }}>
        <div className="container">
          {/* TAB 1: URL THREAT SCANNER */}
          {activeTab === 'scanner' && (
            <>
              <HeroBanner
                totalScans={stats?.total_scans || 0}
                modelVersion={modelVersion}
              />

              <StatsOverview stats={stats} />

              <UrlAnalyzer
                onAnalyze={handleAnalyze}
                isLoading={isLoading}
                error={error}
                enhancedMode={enhancedMode}
                onToggleEnhanced={() => setEnhancedMode(!enhancedMode)}
              />

              {result && (
                <>
                  <ResultCard result={result} />
                  <FeatureAnalysis
                    explanation={result.explanation}
                    rawFeatures={result.features}
                  />
                </>
              )}

              <HistoryTable
                history={history}
                onRefresh={fetchHistory}
                onSelectUrl={handleSelectFromHistory}
                isLoading={isRefreshing}
              />
            </>
          )}

          {/* TAB 2: EMAIL PHISHING INSPECTOR (PHASE 29.4) */}
          {activeTab === 'email' && (
            <EmailAnalyzerTab
              onAnalyzeEmail={handleAnalyzeEmail}
              isLoading={isEmailLoading}
              error={emailError}
              result={emailResult}
            />
          )}

          {/* TAB 3: SOC TELEMETRY & DRIFT MONITORING (PHASE 25 & 27) */}
          {activeTab === 'telemetry' && (
            <TelemetryTab apiBase={API_BASE} />
          )}

          {/* TAB 4: HISTORICAL AUDIT LOG */}
          {activeTab === 'history' && (
            <HistoryTable
              history={history}
              onRefresh={fetchHistory}
              onSelectUrl={handleSelectFromHistory}
              isLoading={isRefreshing}
            />
          )}
        </div>
      </main>

      {/* SOC Command Center Footer */}
      <footer style={{
        borderTop: '1px solid #162238',
        background: 'rgba(5, 8, 17, 0.95)',
        padding: '1.25rem 0',
        textAlign: 'center',
        fontSize: '0.75rem',
        color: '#64748b'
      }}>
        <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <span>Phishing Detection & Risk Intelligence Platform — Zero-Leakage Architecture</span>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', color: '#94a3b8' }}>
            ENGINE STATUS: {systemHealth ? 'OPERATIONAL' : 'OFFLINE'} • CALIBRATION: PLATT SCALED
          </span>
        </div>
      </footer>
    </div>
  );
}
