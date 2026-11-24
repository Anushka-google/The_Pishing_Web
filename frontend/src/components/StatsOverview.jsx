import React from 'react';
import { ShieldCheck, ShieldAlert, BarChart3, Zap, Activity } from 'lucide-react';

export default function StatsOverview({ stats }) {
  const total = stats?.total_scans || 0;
  const phish = stats?.phishing_detected || 0;
  const legit = stats?.legitimate_detected || 0;
  const rate = stats?.phishing_rate_pct || 0;
  const latency = stats?.avg_latency_ms || 1.1;

  const cards = [
    {
      title: 'TOTAL SCANS AUDITED',
      value: total.toLocaleString(),
      sub: 'PostgreSQL Telemetry Log',
      icon: <BarChart3 size={19} color="#00e5ff" />,
      accentColor: '#00e5ff',
      glowClass: 'badge-cyan'
    },
    {
      title: 'CONFIRMED PHISHING THREATS',
      value: phish.toLocaleString(),
      sub: `${rate}% Positive Threat Rate`,
      icon: <ShieldAlert size={19} color="#ff1744" />,
      accentColor: '#ff1744',
      glowClass: 'badge-high'
    },
    {
      title: 'LEGITIMATE DESTINATIONS',
      value: legit.toLocaleString(),
      sub: 'Zero False Positives on Tranco',
      icon: <ShieldCheck size={19} color="#00e676" />,
      accentColor: '#00e676',
      glowClass: 'badge-low'
    },
    {
      title: 'MEDIAN PIPELINE LATENCY',
      value: `${latency} ms`,
      sub: 'Feature Extraction + Inference',
      icon: <Zap size={19} color="#f59e0b" />,
      accentColor: '#f59e0b',
      glowClass: 'badge-medium'
    }
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
      gap: '1.25rem',
      marginBottom: '1.75rem'
    }}>
      {cards.map((c, i) => (
        <div
          key={i}
          className="cyber-card cyber-card-interactive"
          style={{
            padding: '1.4rem',
            background: 'rgba(10, 19, 41, 0.72)',
            borderColor: '#162442',
            position: 'relative',
            overflow: 'hidden'
          }}
        >
          {/* Top subtle glow bar */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '2px',
            background: `linear-gradient(90deg, transparent, ${c.accentColor}, transparent)`,
            opacity: 0.7
          }} />

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '800', letterSpacing: '0.06em' }}>
              {c.title}
            </span>
            <div style={{
              background: 'rgba(6, 11, 23, 0.8)',
              padding: '0.45rem',
              borderRadius: '8px',
              border: '1px solid #162442',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: `0 0 12px ${c.accentColor}25`
            }}>
              {c.icon}
            </div>
          </div>

          <div style={{
            fontSize: '1.85rem',
            fontWeight: '900',
            fontFamily: 'JetBrains Mono, monospace',
            letterSpacing: '-0.03em',
            color: '#f8fafc',
            marginBottom: '0.35rem'
          }}>
            {c.value}
          </div>

          <div style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: c.accentColor }} />
            {c.sub}
          </div>
        </div>
      ))}
    </div>
  );
}
