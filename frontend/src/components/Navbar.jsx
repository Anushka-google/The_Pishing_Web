import React from 'react';
import { Shield, Activity, GitBranch, Globe, Mail, BarChart3, Clock } from 'lucide-react';

export default function Navbar({ activeTab, onTabChange, systemHealth, modelVersion = 'v1' }) {
  return (
    <header style={{
      borderBottom: '1px solid #162238',
      background: 'rgba(5, 8, 17, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0.75rem 0'
    }}>
      <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        {/* Brand / Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(0, 119, 255, 0.2))',
            border: '1px solid rgba(0, 240, 255, 0.5)',
            padding: '0.5rem',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(0, 240, 255, 0.25)'
          }}>
            <Shield size={22} color="#00f0ff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: '900', letterSpacing: '-0.03em', color: '#f8fafc' }}>
                PHISH<span style={{ color: '#00f0ff' }}>INTEL</span>
              </span>
              <span className="badge-cyber badge-cyan" style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}>
                DEFENSE {modelVersion.toUpperCase()}
              </span>
            </div>
            <p style={{ fontSize: '0.72rem', color: '#64748b', letterSpacing: '0.02em', textTransform: 'uppercase' }}>
              AI Risk Intelligence & Threat Operations
            </p>
          </div>
        </div>

        {/* Command Center Navigation Tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', background: '#090e1a', padding: '0.25rem', borderRadius: '10px', border: '1px solid #162238' }}>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => onTabChange('scanner')}
          >
            <Globe size={15} />
            <span>URL Scanner</span>
          </button>

          <button
            type="button"
            className={`nav-tab ${activeTab === 'email' ? 'active' : ''}`}
            onClick={() => onTabChange('email')}
          >
            <Mail size={15} />
            <span>Email Inspector</span>
          </button>

          <button
            type="button"
            className={`nav-tab ${activeTab === 'telemetry' ? 'active' : ''}`}
            onClick={() => onTabChange('telemetry')}
          >
            <BarChart3 size={15} />
            <span>SOC Telemetry</span>
          </button>

          <button
            type="button"
            className={`nav-tab ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => onTabChange('history')}
          >
            <Clock size={15} />
            <span>Audit Log</span>
          </button>
        </nav>

        {/* Health & Repository telemetry */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.4rem 0.8rem',
            borderRadius: '9999px',
            background: '#0c1424',
            border: '1px solid #162238',
            fontSize: '0.75rem',
            color: systemHealth ? '#34d399' : '#f87171'
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: systemHealth ? '#10b981' : '#ef4444',
              display: 'inline-block',
              boxShadow: systemHealth ? '0 0 10px #10b981' : 'none'
            }}></span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: '600' }}>
              {systemHealth ? 'ENGINE ONLINE' : 'DISCONNECTED'}
            </span>
          </div>

          <a
            href="https://github.com/Anushka-google/The_Pishing_Web"
            target="_blank"
            rel="noreferrer"
            className="btn-cyber-secondary"
            style={{ textDecoration: 'none' }}
          >
            <GitBranch size={14} />
            <span>GitHub</span>
          </a>
        </div>
      </div>
    </header>
  );
}
