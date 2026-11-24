import React, { useState, useEffect } from 'react';
import { Shield, Activity, Globe, Mail, BarChart3, Clock, Cpu, Radio } from 'lucide-react';

export default function Navbar({ activeTab, onTabChange, systemHealth, modelVersion = 'v1' }) {
  const [utcTime, setUtcTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(
        now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header style={{
      borderBottom: '1px solid #162442',
      background: 'rgba(5, 9, 20, 0.88)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0.85rem 0',
      boxShadow: '0 4px 30px rgba(0, 0, 0, 0.5)'
    }}>
      <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        
        {/* Brand / Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.9rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.25), rgba(22, 119, 255, 0.25))',
            border: '1px solid rgba(0, 229, 255, 0.6)',
            padding: '0.55rem',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 25px rgba(0, 229, 255, 0.35)',
            position: 'relative'
          }}>
            <Shield size={24} color="#00e5ff" />
            <span style={{
              position: 'absolute',
              top: '-3px',
              right: '-3px',
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: '#00e676',
              boxShadow: '0 0 10px #00e676'
            }} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: '900', letterSpacing: '-0.03em', color: '#f8fafc' }}>
                PHISH<span style={{ color: '#00e5ff', textShadow: '0 0 15px rgba(0, 229, 255, 0.6)' }}>INTEL</span>
              </span>
              <span className="badge-cyber badge-cyan" style={{ fontSize: '0.68rem', padding: '0.2rem 0.55rem' }}>
                DEFENSE {modelVersion.toUpperCase()}
              </span>
            </div>
            <p style={{ fontSize: '0.72rem', color: '#64748b', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              AI Risk Intelligence & SOC Operations
            </p>
          </div>
        </div>

        {/* Command Center Navigation Tabs */}
        <nav style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          background: 'rgba(10, 19, 41, 0.75)',
          padding: '0.3rem',
          borderRadius: '12px',
          border: '1px solid #162442'
        }}>
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

        {/* Live SOC UTC Clock & Health Telemetry */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* UTC Clock */}
          <div style={{
            display: 'none',
            alignItems: 'center',
            gap: '0.45rem',
            padding: '0.45rem 0.85rem',
            borderRadius: '8px',
            background: 'rgba(10, 19, 41, 0.6)',
            border: '1px solid #162442',
            fontSize: '0.75rem',
            fontFamily: 'JetBrains Mono, monospace',
            color: '#94a3b8'
          }} className="soc-clock-desktop">
            <Radio size={13} color="#00e5ff" className="animate-pulse" />
            <span>{utcTime || 'UTC SOC SYNC'}</span>
          </div>

          {/* Engine Health Pill */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem',
            padding: '0.45rem 0.85rem',
            borderRadius: '9999px',
            background: 'rgba(10, 19, 41, 0.85)',
            border: systemHealth ? '1px solid rgba(0, 230, 118, 0.4)' : '1px solid rgba(255, 23, 68, 0.4)',
            fontSize: '0.75rem',
            fontWeight: '600',
            fontFamily: 'JetBrains Mono, monospace',
            color: systemHealth ? '#00e676' : '#ff5252',
            boxShadow: systemHealth ? '0 0 15px rgba(0, 230, 118, 0.15)' : '0 0 15px rgba(255, 23, 68, 0.15)'
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: systemHealth ? '#00e676' : '#ff1744',
              boxShadow: systemHealth ? '0 0 10px #00e676' : '0 0 10px #ff1744',
              animation: 'pulseGlow 2s infinite'
            }} />
            <span>{systemHealth ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}</span>
          </div>
        </div>

      </div>
    </header>
  );
}
