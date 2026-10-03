import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import StatsOverview from './components/StatsOverview';
import UrlAnalyzer from './components/UrlAnalyzer';
import ResultCard from './components/ResultCard';
import RiskExplanation from './components/RiskExplanation';
import HistoryTable from './components/HistoryTable';

const API_BASE = import.meta.env.VITE_API_URL !== undefined 
  ? import.meta.env.VITE_API_URL 
  : (typeof window !== 'undefined' && window.location.hostname === 'localhost' && window.location.port === '5173' 
      ? 'http://localhost:8000' 
      : '');

export default function App() {
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [systemHealth, setSystemHealth] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Fetch telemetry and health on mount
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
      const res = await fetch(`${API_BASE}/history?limit=25`);
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

  const handleAnalyze = async (url) => {
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/predict?include_explanation=true`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
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
      // Refresh telemetry and history after scan
      fetchStats();
      fetchHistory();
    } catch (err) {
      setError(err.message || 'Network error connecting to detection backend.');
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar systemHealth={systemHealth} />

      <main style={{ flex: 1, padding: '2rem 0' }}>
        <div className="container">
          {/* Top Analytics */}
          <StatsOverview stats={stats} />

          {/* Main Scanner Section */}
          <UrlAnalyzer
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            error={error}
          />

          {/* Real-Time Assessment Results */}
          {result && (
            <>
              <ResultCard result={result} />
              <RiskExplanation
                explanation={result.explanation}
                rawFeatures={result.features}
              />
            </>
          )}

          {/* Audit History Log */}
          <HistoryTable
            history={history}
            onRefresh={fetchHistory}
            onSelectUrl={handleAnalyze}
            isLoading={isRefreshing}
          />
        </div>
      </main>

      <footer style={{ borderTop: '1px solid #1e293b', background: '#090e1a', padding: '1.25rem 0', textAlign: 'center', fontSize: '0.75rem', color: '#64748b' }}>
        <div className="container">
          <span>Phishing Detection & Risk Intelligence Platform — Zero-Leakage ML Engineering</span>
        </div>
      </footer>
    </div>
  );
}
