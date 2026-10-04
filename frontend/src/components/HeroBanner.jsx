import React from 'react';
import { ShieldCheck, Zap, Lock, Terminal, Radio } from 'lucide-react';

export default function HeroBanner({ totalScans = 0, modelVersion = 'v1' }) {
  return (
    <div style={{
      position: 'relative',
      padding: '2.5rem 0 1.5rem',
      textAlign: 'center',
      marginBottom: '1rem'
    }}>
      {/* Top Threat Intel Ticker */}
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.6rem', padding: '0.35rem 0.9rem', borderRadius: '9999px', background: 'rgba(0, 240, 255, 0.08)', border: '1px solid rgba(0, 240, 255, 0.25)', marginBottom: '1.25rem' }}>
        <Radio size={14} color="#00f0ff" className="animate-pulse" />
        <span style={{ fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace', color: '#00f0ff', fontWeight: '600', letterSpacing: '0.05em' }}>
          ACTIVE DEFENSE RUNTIME — ZERO-LEAKAGE ML ENGINE
        </span>
      </div>

      {/* Main Headline */}
      <h1 style={{
        fontSize: 'clamp(2rem, 4vw, 3.25rem)',
        fontWeight: '900',
        letterSpacing: '-0.03em',
        lineHeight: 1.15,
        marginBottom: '0.85rem',
        color: '#f8fafc'
      }}>
        Detect. Analyze. <span style={{
          background: 'linear-gradient(135deg, #00f0ff 0%, #3b82f6 50%, #8b5cf6 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          textShadow: '0 0 30px rgba(0, 240, 255, 0.3)'
        }}>Defend.</span>
      </h1>

      <p style={{
        maxWidth: '720px',
        margin: '0 auto 1.75rem',
        fontSize: '1rem',
        color: '#94a3b8',
        lineHeight: 1.6
      }}>
        Enterprise AI risk intelligence analyzing URL lexical structures, Shannon entropy,
        reputation feeds, DNS characteristics, and WHOIS age to neutralize zero-day credential harvesting in real time.
      </p>

      {/* Quick Security Metrics Strip */}
      <div style={{
        display: 'inline-flex',
        flexWrap: 'wrap',
        justifyContent: 'center',
        gap: '1.5rem',
        padding: '0.85rem 1.5rem',
        background: 'rgba(12, 20, 36, 0.6)',
        backdropFilter: 'blur(10px)',
        borderRadius: '12px',
        border: '1px solid #162238'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
          <ShieldCheck size={16} color="#10b981" />
          <span style={{ color: '#64748b' }}>Accuracy:</span>
          <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>99.9%</strong>
        </div>

        <div style={{ width: '1px', background: '#1e293b' }}></div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
          <Zap size={16} color="#00f0ff" />
          <span style={{ color: '#64748b' }}>Feature Extraction:</span>
          <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>0.29 ms</strong>
        </div>

        <div style={{ width: '1px', background: '#1e293b' }}></div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
          <Lock size={16} color="#3b82f6" />
          <span style={{ color: '#64748b' }}>Domain Isolation:</span>
          <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>GroupShuffleSplit</strong>
        </div>

        <div style={{ width: '1px', background: '#1e293b' }}></div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
          <Terminal size={16} color="#a855f7" />
          <span style={{ color: '#64748b' }}>Scans Recorded:</span>
          <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>{totalScans.toLocaleString()}</strong>
        </div>
      </div>
    </div>
  );
}
