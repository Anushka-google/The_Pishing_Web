import React, { useState } from 'react';
import { Search, Loader2, AlertCircle, ArrowRight, CornerDownLeft } from 'lucide-react';

export default function UrlAnalyzer({ onAnalyze, isLoading, error }) {
  const [url, setUrl] = useState('');

  const PRESETS = [
    {
      label: 'Google Auth (Benign Hard Negative)',
      url: 'https://accounts.google.com/signin/v2/identifier',
      color: '#10b981'
    },
    {
      label: 'Tranco Top Docs (Legitimate)',
      url: 'https://docs.oracle.com/en/java/javase/index.html',
      color: '#3b82f6'
    },
    {
      label: 'PayPal Deceptive Subdomain (Phish)',
      url: 'https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284',
      color: '#ef4444'
    },
    {
      label: 'IP Host Harvest Attack (Phish)',
      url: 'http://176.77.46.141:53458/bin.sh',
      color: '#f97316'
    }
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handlePreset = (presetUrl) => {
    setUrl(presetUrl);
    onAnalyze(presetUrl);
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem', background: '#0a101f', borderColor: '#1e293b' }}>
      <div style={{ marginBottom: '1rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: '700', color: '#f8fafc', marginBottom: '0.25rem' }}>
          URL Threat Analyzer
        </h2>
        <p style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
          Inspect web destinations across 22 structural, lexical, and Shannon entropy indicators in real time.
        </p>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <input
            type="text"
            className="url-input"
            placeholder="Enter target URL (e.g. https://auth-verify.example.com/login?token=...)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isLoading}
          />
          {url && (
            <button
              type="button"
              onClick={() => setUrl('')}
              style={{
                position: 'absolute',
                right: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: '#64748b',
                cursor: 'pointer',
                fontSize: '0.8rem'
              }}
            >
              Clear
            </button>
          )}
        </div>

        <button
          type="submit"
          className="btn-primary"
          disabled={isLoading || !url.trim()}
          style={{ opacity: isLoading || !url.trim() ? 0.6 : 1 }}
        >
          {isLoading ? (
            <>
              <Loader2 size={18} className="animate-spin" />
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <Search size={18} />
              <span>Analyze URL</span>
            </>
          )}
        </button>
      </form>

      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.6rem',
          color: '#fca5a5',
          fontSize: '0.85rem',
          marginBottom: '1rem'
        }}>
          <AlertCircle size={18} color="#ef4444" />
          <span>{error}</span>
        </div>
      )}

      {/* Quick Test Presets */}
      <div>
        <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Quick Benchmark Presets:
        </span>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
          {PRESETS.map((p, i) => (
            <button
              key={i}
              type="button"
              className="btn-secondary"
              onClick={() => handlePreset(p.url)}
              disabled={isLoading}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: p.color }}></span>
              <span>{p.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
