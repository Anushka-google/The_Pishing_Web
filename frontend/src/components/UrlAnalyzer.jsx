import React, { useState } from 'react';
import { Search, Loader2, AlertCircle, Sparkles, Shield, Globe, Layers, CornerDownLeft, Radar } from 'lucide-react';

export default function UrlAnalyzer({ onAnalyze, isLoading, error, enhancedMode, onToggleEnhanced }) {
  const [url, setUrl] = useState('');

  const PRESETS = [
    {
      category: 'BENIGN HARD-NEGATIVE',
      label: 'Google Auth Portal',
      url: 'https://accounts.google.com/signin/v2/identifier',
      color: '#00e676',
      badgeClass: 'badge-low'
    },
    {
      category: 'ESTABLISHED AUTHORITY',
      label: 'Tranco Top Docs',
      url: 'https://docs.oracle.com/en/java/javase/index.html',
      color: '#1677ff',
      badgeClass: 'badge-blue'
    },
    {
      category: 'SUBDOMAIN EVASION',
      label: 'PayPal Cloud Attack',
      url: 'https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284',
      color: '#ff1744',
      badgeClass: 'badge-high'
    },
    {
      category: 'INFRASTRUCTURE ATTACK',
      label: 'Direct IP Harvester',
      url: 'http://176.77.46.141:53458/bin.sh',
      color: '#f59e0b',
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
    <div
      id="url-analyzer-section"
      className="cyber-card cyber-corners"
      style={{
        marginBottom: '1.75rem',
        background: 'rgba(10, 19, 41, 0.78)',
        borderColor: '#162442',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      {/* Active Scanline Effect during inspection */}
      {isLoading && <div className="scanline" />}

      {/* Header with Mode Toggle */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
        marginBottom: '1.25rem'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.25rem' }}>
            <Globe size={19} color="#00e5ff" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em' }}>
              URL Threat Inspection Console
            </h2>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Deconstruct web destinations across 22 lexical features, TreeSHAP attributions, DNS records, and WHOIS domain age.
          </p>
        </div>

        {/* Enhanced Intelligence Switch */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.65rem',
          background: 'rgba(6, 11, 23, 0.85)',
          padding: '0.45rem 0.85rem',
          borderRadius: '10px',
          border: '1px solid #162442',
          boxShadow: enhancedMode ? '0 0 15px rgba(0, 229, 255, 0.15)' : 'none'
        }}>
          <Layers size={15} color={enhancedMode ? '#00e5ff' : '#64748b'} />
          <span style={{ fontSize: '0.78rem', fontWeight: '700', color: enhancedMode ? '#00e5ff' : '#94a3b8' }}>
            Multi-Signal Engine (+DNS, +WHOIS, +Feeds)
          </span>
          <button
            type="button"
            onClick={onToggleEnhanced}
            style={{
              width: '40px',
              height: '22px',
              borderRadius: '9999px',
              background: enhancedMode ? 'linear-gradient(135deg, #00e5ff, #1677ff)' : '#1e2d4d',
              border: 'none',
              cursor: 'pointer',
              position: 'relative',
              transition: 'all 0.22s ease',
              display: 'flex',
              alignItems: 'center',
              padding: '2px',
              boxShadow: enhancedMode ? '0 0 12px rgba(0, 229, 255, 0.5)' : 'none'
            }}
            title="Toggle Multi-Signal Intelligence (Reputation + DNS + WHOIS)"
          >
            <div style={{
              width: '18px',
              height: '18px',
              borderRadius: '50%',
              background: enhancedMode ? '#050914' : '#64748b',
              transform: enhancedMode ? 'translateX(18px)' : 'translateX(0)',
              transition: 'transform 0.22s cubic-bezier(0.16, 1, 0.3, 1)'
            }} />
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.85rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '300px' }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Enter destination URL to scan (e.g. https://auth-verify.company.com/login?session=...)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isLoading}
            style={{ paddingRight: '4.5rem', background: 'rgba(6, 11, 23, 0.9)' }}
          />

          <div style={{
            position: 'absolute',
            right: '12px',
            top: '50%',
            transform: 'translateY(-50%)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem'
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
            <span style={{ fontSize: '0.68rem', fontFamily: 'monospace', color: '#64748b', background: '#0a1329', padding: '2px 6px', borderRadius: '4px', border: '1px solid #162442' }}>
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
              <Loader2 size={19} className="animate-spin" />
              <span>Scanning Signals...</span>
            </>
          ) : (
            <>
              <Search size={19} />
              <span>Inspect Destination</span>
            </>
          )}
        </button>
      </form>

      {/* Error Banner */}
      {error && (
        <div style={{
          background: 'rgba(255, 23, 68, 0.12)',
          border: '1px solid rgba(255, 23, 68, 0.4)',
          borderRadius: '10px',
          padding: '0.9rem 1.1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.65rem',
          color: '#ff8a80',
          fontSize: '0.85rem',
          marginBottom: '1.25rem',
          boxShadow: '0 0 15px rgba(255, 23, 68, 0.15)'
        }}>
          <AlertCircle size={19} color="#ff1744" />
          <span>{error}</span>
        </div>
      )}

      {/* Quick Verification Attack Vectors */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.75rem' }}>
          <Sparkles size={14} color="#00e5ff" />
          <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Verified Attack Vector Scenarios
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.55rem' }}>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              className="btn-cyber-secondary"
              onClick={() => handlePreset(p.url)}
              disabled={isLoading}
              style={{
                fontSize: '0.76rem',
                padding: '0.45rem 0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.55rem'
              }}
            >
              <span style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: p.color,
                boxShadow: `0 0 8px ${p.color}`
              }}></span>
              <span style={{ color: '#f8fafc', fontWeight: '600' }}>{p.label}</span>
              <span style={{ color: '#64748b', fontSize: '0.68rem', fontFamily: 'monospace' }}>[{p.category}]</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
