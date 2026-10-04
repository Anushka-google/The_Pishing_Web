import React, { useState } from 'react';
import { Search, Loader2, AlertCircle, Sparkles, Shield, Globe, Layers, CornerDownLeft } from 'lucide-react';

export default function UrlAnalyzer({ onAnalyze, isLoading, error, enhancedMode, onToggleEnhanced }) {
  const [url, setUrl] = useState('');

  const PRESETS = [
    {
      category: 'BENIGN HARD-NEGATIVE',
      label: 'Google Auth Portal',
      url: 'https://accounts.google.com/signin/v2/identifier',
      color: '#10b981',
      badgeClass: 'badge-low'
    },
    {
      category: 'ESTABLISHED AUTHORITY',
      label: 'Tranco Top Docs',
      url: 'https://docs.oracle.com/en/java/javase/index.html',
      color: '#3b82f6',
      badgeClass: 'badge-blue'
    },
    {
      category: 'SUBDOMAIN EVASION',
      label: 'PayPal Cloud Attack',
      url: 'https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284',
      color: '#ef4444',
      badgeClass: 'badge-high'
    },
    {
      category: 'INFRASTRUCTURE ATTACK',
      label: 'Direct IP Harvester',
      url: 'http://176.77.46.141:53458/bin.sh',
      color: '#f97316',
      badgeClass: 'badge-medium'
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
    <div className="cyber-card cyber-corners" style={{ marginBottom: '1.75rem', background: '#0a101f', borderColor: '#162238' }}>
      {/* Header with Mode Toggle */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
            <Globe size={18} color="#00f0ff" />
            <h2 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em' }}>
              URL Threat Inspection Console
            </h2>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Scan web destinations across 22 lexical features, TreeSHAP attributions, DNS, and WHOIS domain age.
          </p>
        </div>

        {/* Enhanced Intelligence Switch */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', background: '#070b14', padding: '0.35rem 0.75rem', borderRadius: '8px', border: '1px solid #162238' }}>
          <Layers size={15} color={enhancedMode ? '#00f0ff' : '#64748b'} />
          <span style={{ fontSize: '0.75rem', fontWeight: '600', color: enhancedMode ? '#00f0ff' : '#94a3b8' }}>
            Multi-Signal Mode (+DNS, +WHOIS, +Threat Feeds)
          </span>
          <button
            type="button"
            onClick={onToggleEnhanced}
            style={{
              width: '36px',
              height: '20px',
              borderRadius: '9999px',
              background: enhancedMode ? '#00f0ff' : '#1e293b',
              border: 'none',
              cursor: 'pointer',
              position: 'relative',
              transition: 'background 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              padding: '2px'
            }}
            title="Toggle Phase 29 Multi-Signal Intelligence (Reputation + DNS + WHOIS)"
          >
            <div style={{
              width: '16px',
              height: '16px',
              borderRadius: '50%',
              background: enhancedMode ? '#050811' : '#64748b',
              transform: enhancedMode ? 'translateX(16px)' : 'translateX(0)',
              transition: 'transform 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
            }}></div>
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '280px' }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Enter target URL (e.g. https://auth-verify.company.com/login?session=...)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isLoading}
            style={{ paddingRight: '4rem' }}
          />

          <div style={{
            position: 'absolute',
            right: '12px',
            top: '50%',
            transform: 'translateY(-50%)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            {url && (
              <button
                type="button"
                onClick={() => setUrl('')}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#64748b',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  padding: '2px 6px',
                  borderRadius: '4px'
                }}
              >
                Clear
              </button>
            )}
            <span style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: '#475569', background: '#0f172a', padding: '2px 5px', borderRadius: '4px', border: '1px solid #1e293b' }}>
              ⏎
            </span>
          </div>
        </div>

        <button
          type="submit"
          className="btn-cyber-primary"
          disabled={isLoading || !url.trim()}
        >
          {isLoading ? (
            <>
              <Loader2 size={18} className="animate-spin" />
              <span>Analyzing Threat Signals...</span>
            </>
          ) : (
            <>
              <Search size={18} />
              <span>Execute Inspection</span>
            </>
          )}
        </button>
      </form>

      {/* Error Banner */}
      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          borderRadius: '8px',
          padding: '0.85rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.6rem',
          color: '#fca5a5',
          fontSize: '0.85rem',
          marginBottom: '1.25rem'
        }}>
          <AlertCircle size={18} color="#ef4444" />
          <span>{error}</span>
        </div>
      )}

      {/* Security Testing Attack Vectors */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.6rem' }}>
          <Sparkles size={14} color="#00f0ff" />
          <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Quick Verification Attack Vectors
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              className="btn-cyber-secondary"
              onClick={() => handlePreset(p.url)}
              disabled={isLoading}
              style={{
                fontSize: '0.75rem',
                padding: '0.4rem 0.75rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}
            >
              <span style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: p.color
              }}></span>
              <span style={{ color: '#e2e8f0', fontWeight: '600' }}>{p.label}</span>
              <span style={{ color: '#64748b', fontSize: '0.68rem', fontFamily: 'monospace' }}>[{p.category}]</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
