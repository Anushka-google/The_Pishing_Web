import React from 'react';
import { ShieldCheck, Zap, Lock, Terminal, Radio, ArrowRight, Activity, Search } from 'lucide-react';
import CyberThreatHolo3D from './CyberThreatHolo3D';

export default function HeroBanner({ totalScans = 0, modelVersion = 'v1', onAnalyzeClick, onExploreClick }) {
  const handleScrollToScanner = () => {
    if (onAnalyzeClick) {
      onAnalyzeClick();
    } else {
      const el = document.getElementById('url-analyzer-section');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  return (
    <div style={{
      position: 'relative',
      padding: '2.5rem 0 2rem',
      marginBottom: '2rem'
    }}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        alignItems: 'center',
        gap: '3rem'
      }}>
        {/* Left Column: Command Center Briefing */}
        <div>
          {/* Small Label with glowing pulse */}
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.65rem',
            padding: '0.45rem 1rem',
            borderRadius: '9999px',
            background: 'rgba(0, 217, 255, 0.08)',
            border: '1px solid rgba(0, 217, 255, 0.35)',
            marginBottom: '1.4rem',
            boxShadow: '0 0 20px rgba(0, 217, 255, 0.15)'
          }}>
            <Radio size={14} color="#00d9ff" className="animate-pulse" />
            <span style={{ fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace', color: '#00d9ff', fontWeight: '800', letterSpacing: '0.08em' }}>
              NEXT-GENERATION CYBER DEFENSE
            </span>
          </div>

          {/* Main Cinematic Heading */}
          <h1 style={{
            fontSize: 'clamp(2.4rem, 4.8vw, 3.8rem)',
            fontWeight: '900',
            letterSpacing: '-0.035em',
            lineHeight: 1.08,
            marginBottom: '1.25rem',
            color: '#f8fafc'
          }}>
            SEE THE THREAT.{' '}
            <span style={{
              background: 'linear-gradient(135deg, #00d9ff 0%, #3478ff 50%, #ff2e93 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              textShadow: '0 0 40px rgba(0, 217, 255, 0.45)'
            }}>
              BEFORE IT STRIKES.
            </span>
          </h1>

          {/* Supporting Description */}
          <p style={{
            maxWidth: '620px',
            fontSize: '1.05rem',
            color: '#94a3b8',
            lineHeight: 1.7,
            marginBottom: '2rem'
          }}>
            An intelligent phishing detection platform that analyzes suspicious URLs, examines structural patterns,
            and transforms complex threat signals into actionable security insights.
          </p>

          {/* Call-to-Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '2.5rem' }}>
            <button
              type="button"
              className="btn-cyber-primary"
              onClick={handleScrollToScanner}
            >
              <Search size={18} />
              <span>ANALYZE A URL</span>
              <ArrowRight size={16} />
            </button>

            <button
              type="button"
              className="btn-cyber-secondary"
              onClick={onExploreClick}
              style={{ padding: '0.9rem 1.6rem', fontSize: '0.88rem' }}
            >
              <Activity size={17} color="#ff2e93" />
              <span>EXPLORE THE INTELLIGENCE</span>
            </button>
          </div>

          {/* Quick Security Metrics Strip */}
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '1.1rem',
            padding: '1rem 1.5rem',
            background: 'rgba(8, 13, 25, 0.75)',
            backdropFilter: 'blur(16px)',
            borderRadius: '12px',
            border: '1px solid #162442',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.35)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.82rem' }}>
              <ShieldCheck size={17} color="#22c55e" />
              <span style={{ color: '#64748b' }}>Accuracy:</span>
              <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>99.9%</strong>
            </div>

            <div style={{ width: '1px', background: '#1e2d4d' }}></div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.82rem' }}>
              <Zap size={17} color="#00d9ff" />
              <span style={{ color: '#64748b' }}>Latency:</span>
              <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>0.29 ms</strong>
            </div>

            <div style={{ width: '1px', background: '#1e2d4d' }}></div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.82rem' }}>
              <Lock size={17} color="#3478ff" />
              <span style={{ color: '#64748b' }}>Split:</span>
              <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>GroupShuffleSplit</strong>
            </div>

            <div style={{ width: '1px', background: '#1e2d4d' }}></div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.82rem' }}>
              <Terminal size={17} color="#ff2e93" />
              <span style={{ color: '#64748b' }}>Audited:</span>
              <strong style={{ color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>{totalScans.toLocaleString()}</strong>
            </div>
          </div>
        </div>

        {/* Right Column: Signature 3D Holographic Cyber Visualizer */}
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
          <CyberThreatHolo3D onScanClick={handleScrollToScanner} onExploreClick={onExploreClick} />
        </div>
      </div>
    </div>
  );
}
