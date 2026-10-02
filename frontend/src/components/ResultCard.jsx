import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Clock, Cpu } from 'lucide-react';

export default function ResultCard({ result }) {
  if (!result) return null;

  const {
    url,
    prediction,
    probability,
    risk_level,
    action,
    recommendation,
    thresholds,
    metadata
  } = result;

  const pct = Math.round(probability * 100);

  const getRiskColor = (level) => {
    switch (level) {
      case 'HIGH': return { text: '#ef4444', bg: 'badge-high', glow: 'card-glow-high', bar: '#ef4444' };
      case 'MEDIUM': return { text: '#f59e0b', bg: 'badge-medium', glow: 'card-glow-med', bar: '#f59e0b' };
      default: return { text: '#10b981', bg: 'badge-low', glow: 'card-glow-low', bar: '#10b981' };
    }
  };

  const riskStyle = getRiskColor(risk_level);

  const getActionBadge = (act) => {
    switch (act) {
      case 'BLOCK': return { label: 'ACTION: BLOCK / ISOLATE', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' };
      case 'CAUTION': return { label: 'ACTION: CAUTION / INSPECT', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' };
      default: return { label: 'ACTION: ALLOW / BENIGN', color: '#10b981', bg: 'rgba(16, 185, 129, 0.15)' };
    }
  };

  const actionStyle = getActionBadge(action);

  return (
    <div className={`card ${riskStyle.glow}`} style={{ marginBottom: '1.5rem', background: '#0a101f' }}>
      {/* Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <div>
          <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: '600', textTransform: 'uppercase' }}>
            Target Destination
          </span>
          <div style={{
            fontSize: '1rem',
            color: '#f8fafc',
            fontFamily: 'JetBrains Mono, monospace',
            wordBreak: 'break-all',
            marginTop: '0.2rem'
          }}>
            {url}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span className={`badge ${riskStyle.bg}`}>
            {risk_level === 'HIGH' && <ShieldAlert size={14} />}
            {risk_level === 'MEDIUM' && <AlertTriangle size={14} />}
            {risk_level === 'LOW' && <ShieldCheck size={14} />}
            {risk_level} RISK
          </span>
          <span style={{
            padding: '0.25rem 0.65rem',
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: '700',
            background: actionStyle.bg,
            color: actionStyle.color,
            border: `1px solid ${actionStyle.color}40`
          }}>
            {actionStyle.label}
          </span>
        </div>
      </div>

      {/* Probability Gauge & Progress Bar */}
      <div style={{ background: '#070b14', padding: '1.25rem', borderRadius: '10px', border: '1px solid #1e293b', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '0.5rem' }}>
          <div>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Posterior Malicious Probability:</span>
            <div style={{ fontSize: '1.75rem', fontWeight: '800', color: riskStyle.text, letterSpacing: '-0.02em' }}>
              {pct}% <span style={{ fontSize: '0.9rem', color: '#64748b', fontWeight: '500' }}>({probability.toFixed(4)})</span>
            </div>
          </div>
          <div style={{ textAlign: 'right', fontSize: '0.75rem', color: '#64748b' }}>
            <span>T1 (Low): {thresholds?.t1_low ?? 0.40} | T2 (High): {thresholds?.t2_high ?? 0.65}</span>
          </div>
        </div>

        {/* Multi-tier bar */}
        <div className="progress-bar-bg" style={{ position: 'relative', height: '10px' }}>
          <div
            className="progress-bar-fill"
            style={{
              width: `${pct}%`,
              backgroundColor: riskStyle.bar,
              boxShadow: `0 0 10px ${riskStyle.bar}60`
            }}
          ></div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#475569', marginTop: '0.4rem' }}>
          <span>0.00 (Safe)</span>
          <span style={{ color: '#10b981' }}>Low Threshold (0.40)</span>
          <span style={{ color: '#f59e0b' }}>High Threshold (0.65)</span>
          <span>1.00 (Phishing)</span>
        </div>
      </div>

      {/* Security Recommendation */}
      <div style={{
        background: 'rgba(30, 41, 59, 0.4)',
        borderLeft: `4px solid ${riskStyle.text}`,
        padding: '0.85rem 1rem',
        borderRadius: '0 8px 8px 0',
        marginBottom: '1rem'
      }}>
        <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
          SOC Security Directive:
        </div>
        <div style={{ fontSize: '0.9rem', color: '#e2e8f0' }}>
          {recommendation}
        </div>
      </div>

      {/* Operational Latency Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: '#64748b', borderTop: '1px solid #1e293b', paddingTop: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Cpu size={14} />
          <span>Model: {metadata?.model_name || 'Random Forest'} ({metadata?.model_version || 'v1.0.0'})</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Clock size={14} />
          <span>Total Latency: {metadata?.total_latency_ms || 0.45} ms</span>
        </div>
      </div>
    </div>
  );
}
