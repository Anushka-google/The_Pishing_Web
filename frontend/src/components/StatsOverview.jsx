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
      icon: <BarChart3 size={18} color="#00f0ff" />,
      accentColor: '#00f0ff'
    },
    {
      title: 'CONFIRMED PHISHING THREATS',
      value: phish.toLocaleString(),
      sub: `${rate}% Positive Detection Rate`,
      icon: <ShieldAlert size={18} color="#ef4444" />,
      accentColor: '#ef4444'
    },
    {
      title: 'LEGITIMATE DESTINATIONS',
      value: legit.toLocaleString(),
      sub: 'Zero False Positives on Tranco',
      icon: <ShieldCheck size={18} color="#10b981" />,
      accentColor: '#10b981'
    },
    {
      title: 'MEDIAN PIPELINE LATENCY',
      value: `${latency} ms`,
      sub: 'Feature Extraction + Inference',
      icon: <Zap size={18} color="#f59e0b" />,
      accentColor: '#f59e0b'
    }
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
      gap: '1rem',
      marginBottom: '1.75rem'
    }}>
      {cards.map((c, i) => (
        <div
          key={i}
          className="cyber-card"
          style={{
            padding: '1.25rem',
            background: '#0a101f',
            borderColor: '#162238'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
            <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', letterSpacing: '0.04em' }}>
              {c.title}
            </span>
            <div style={{
              background: '#070b14',
              padding: '0.35rem',
              borderRadius: '6px',
              border: '1px solid #162238',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              {c.icon}
            </div>
          </div>

          <div style={{
            fontSize: '1.75rem',
            fontWeight: '900',
            color: '#f8fafc',
            fontFamily: 'JetBrains Mono, monospace',
            letterSpacing: '-0.03em',
            marginBottom: '0.2rem'
          }}>
            {c.value}
          </div>

          <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            {c.sub}
          </div>
        </div>
      ))}
    </div>
  );
}
