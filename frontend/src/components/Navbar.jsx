import React from 'react';
import { Shield, Activity, GitBranch } from 'lucide-react';

export default function Navbar({ systemHealth }) {
  return (
    <header style={{ borderBottom: '1px solid #1e293b', background: '#090e1a', padding: '1rem 0' }}>
      <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
            padding: '0.5rem',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(59, 130, 246, 0.4)'
          }}>
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: '800', letterSpacing: '-0.02em', color: '#f8fafc' }}>
                PhishIntel
              </h1>
              <span className="badge badge-blue">AI v1.0</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              Zero-Leakage Phishing Detection & Risk Intelligence Platform
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.35rem 0.75rem',
            borderRadius: '9999px',
            background: '#0d1527',
            border: '1px solid #1e293b',
            fontSize: '0.75rem',
            color: systemHealth ? '#34d399' : '#f87171'
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: systemHealth ? '#10b981' : '#ef4444',
              display: 'inline-block',
              boxShadow: systemHealth ? '0 0 8px #10b981' : 'none'
            }}></span>
            <span>{systemHealth ? 'API & Model Online' : 'Connecting to API...'}</span>
          </div>

          <a
            href="https://github.com/Anushka-google/The_Pishing_Web"
            target="_blank"
            rel="noreferrer"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              color: '#94a3b8',
              textDecoration: 'none',
              fontSize: '0.8rem',
              padding: '0.35rem 0.65rem',
              borderRadius: '6px',
              border: '1px solid #1e293b'
            }}
          >
            <GitBranch size={14} />
            <span>GitHub</span>
          </a>
        </div>
      </div>
    </header>
  );
}
