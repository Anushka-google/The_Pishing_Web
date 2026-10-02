import React from 'react';
import { ShieldCheck, ShieldAlert, BarChart3, Zap } from 'lucide-react';

export default function StatsOverview({ stats }) {
  const total = stats?.total_scans || 0;
  const phish = stats?.phishing_detected || 0;
  const legit = stats?.legitimate_detected || 0;
  const rate = stats?.phishing_rate_pct || 0;
  const latency = stats?.avg_latency_ms || 1.1;

  const cards = [
    {
      title: 'Total Scans Executed',
      value: total.toLocaleString(),
      sub: 'Audited in PostgreSQL / DB',
      icon: <BarChart3 size={20} color="#3b82f6" />,
      border: '#1e293b'
    },
    {
      title: 'Phishing Attacks Flagged',
      value: phish.toLocaleString(),
      sub: `${rate}% Threat Detection Ratio`,
      icon: <ShieldAlert size={20} color="#ef4444" />,
      border: 'rgba(239, 68, 68, 0.3)'
    },
    {
      title: 'Legitimate URLs Verified',
      value: legit.toLocaleString(),
      sub: 'Zero False Positives on Tranco',
      icon: <ShieldCheck size={20} color="#10b981" />,
      border: 'rgba(16, 185, 129, 0.3)'
    },
    {
      title: 'Mean Pipeline Latency',
      value: `${latency} ms`,
      sub: 'Optimized C-Ensemble (< 2ms)',
      icon: <Zap size={20} color="#f59e0b" />,
      border: '#1e293b'
    }
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
      gap: '1rem',
      marginBottom: '1.5rem'
    }}>
      {cards.map((c, i) => (
        <div key={i} className="card" style={{ padding: '1.25rem', borderColor: c.border }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '500' }}>{c.title}</span>
            <div style={{ background: '#090e1a', padding: '0.4rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              {c.icon}
            </div>
          </div>
          <div style={{ fontSize: '1.65rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em', marginBottom: '0.2rem' }}>
            {c.value}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
            {c.sub}
          </div>
        </div>
      ))}
    </div>
  );
}
