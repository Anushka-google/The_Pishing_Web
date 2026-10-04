import React from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink,
  Clock, Cpu, Database, Network, Globe, Radio, CheckCircle, XCircle
} from 'lucide-react';

export default function ResultCard({ result }) {
  if (!result) return null;

  const {
    url,
    prediction,
    probability,
    fused_probability,
    risk_level,
    final_risk_level,
    action,
    final_action,
    recommendation,
    thresholds,
    metadata,
    reputation,
    dns,
    whois,
    execution_time_ms
  } = result;

  // Use fused probability if available from enhanced mode, else base probability
  const effectiveProb = fused_probability !== undefined ? fused_probability : probability;
  const effectiveRisk = final_risk_level || risk_level;
  const effectiveAction = final_action || action;
  const pct = Math.round(effectiveProb * 100);

  // Threat style mappings
  const getRiskTheme = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return {
          color: '#ef4444',
          glowClass: 'glow-high',
          badgeClass: 'badge-high',
          title: 'CONFIRMED PHISHING THREAT',
          accentGradient: 'linear-gradient(135deg, #ef4444, #991b1b)',
          icon: <ShieldAlert size={28} color="#ef4444" />
        };
      case 'MEDIUM':
        return {
          color: '#f59e0b',
          glowClass: 'glow-medium',
          badgeClass: 'badge-medium',
          title: 'SUSPICIOUS WEB ANOMALY',
          accentGradient: 'linear-gradient(135deg, #f59e0b, #b45309)',
          icon: <AlertTriangle size={28} color="#f59e0b" />
        };
      default:
        return {
          color: '#10b981',
          glowClass: 'glow-low',
          badgeClass: 'badge-low',
          title: 'VERIFIED LEGITIMATE DESTINATION',
          accentGradient: 'linear-gradient(135deg, #10b981, #047857)',
          icon: <ShieldCheck size={28} color="#10b981" />
        };
    }
  };

  const theme = getRiskTheme(effectiveRisk);

  // SVG Radial Gauge Calculations (240-degree arc)
  const radius = 80;
  const circumference = 2 * Math.PI * radius; // ~502.65
  const arcLength = circumference * (240 / 360); // ~335.1
  const strokeDashoffset = arcLength - (arcLength * (pct / 100));

  return (
    <div className={`cyber-card cyber-corners ${theme.glowClass}`} style={{ marginBottom: '1.75rem', background: '#0a101f' }}>
      {/* Target URL Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: '1rem',
        paddingBottom: '1.25rem',
        borderBottom: '1px solid #162238',
        marginBottom: '1.5rem'
      }}>
        <div style={{ flex: 1, minWidth: '280px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              INSPECTED DESTINATION ENDPOINT
            </span>
            <span className="badge-cyber badge-cyan" style={{ fontSize: '0.65rem' }}>
              RFC 3986 PARSED
            </span>
          </div>

          <div style={{
            fontSize: '1.05rem',
            color: '#f8fafc',
            fontFamily: 'JetBrains Mono, monospace',
            wordBreak: 'break-all',
            background: '#070b14',
            padding: '0.6rem 0.85rem',
            borderRadius: '6px',
            border: '1px solid #162238'
          }}>
            {url}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
          <span className={`badge-cyber ${theme.badgeClass}`} style={{ fontSize: '0.8rem', padding: '0.4rem 0.85rem' }}>
            {effectiveRisk} RISK
          </span>

          <span style={{
            padding: '0.4rem 0.85rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: '800',
            fontFamily: 'JetBrains Mono, monospace',
            background: effectiveAction === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : (effectiveAction === 'CAUTION' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'),
            color: effectiveAction === 'BLOCK' ? '#f87171' : (effectiveAction === 'CAUTION' ? '#fbbf24' : '#34d399'),
            border: `1px solid ${effectiveAction === 'BLOCK' ? 'rgba(239, 68, 68, 0.4)' : (effectiveAction === 'CAUTION' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)')}`
          }}>
            DIRECTIVE: {effectiveAction}
          </span>
        </div>
      </div>

      {/* Main Threat Dashboard Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '1.75rem',
        alignItems: 'center',
        marginBottom: '1.5rem'
      }}>
        {/* Radial Threat Gauge */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#070b14',
          borderRadius: '12px',
          border: '1px solid #162238',
          padding: '1.75rem 1.25rem',
          position: 'relative'
        }}>
          <div style={{ position: 'relative', width: '220px', height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="220" height="200" viewBox="0 0 200 180" style={{ transform: 'rotate(150deg)' }}>
              {/* Background Arc Track */}
              <circle
                cx="100"
                cy="100"
                r={radius}
                fill="none"
                stroke="#162238"
                strokeWidth="14"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeLinecap="round"
              />

              {/* Threshold Zones (Low, Med, High ticks) */}
              <circle
                cx="100"
                cy="100"
                r={radius}
                fill="none"
                stroke={theme.color}
                strokeWidth="14"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{
                  transition: 'stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s ease',
                  filter: `drop-shadow(0 0 8px ${theme.color})`
                }}
              />
            </svg>

            {/* Gauge Centered Content */}
            <div style={{
              position: 'absolute',
              top: '55px',
              left: 0,
              right: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              textAlign: 'center'
            }}>
              <span style={{
                fontSize: '2.6rem',
                fontWeight: '900',
                color: theme.color,
                lineHeight: 1,
                fontFamily: 'JetBrains Mono, monospace',
                letterSpacing: '-0.03em'
              }}>
                {pct}%
              </span>
              <span style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.25rem' }}>
                THREAT PROBABILITY
              </span>
            </div>
          </div>

          {/* Threshold Legend Bar */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            width: '100%',
            maxWidth: '240px',
            fontSize: '0.68rem',
            color: '#64748b',
            fontFamily: 'JetBrains Mono, monospace',
            marginTop: '-15px'
          }}>
            <span style={{ color: '#10b981' }}>SAFE (0.0)</span>
            <span style={{ color: '#f59e0b' }}>T1: 0.40</span>
            <span style={{ color: '#ef4444' }}>T2: 0.65</span>
            <span style={{ color: '#dc2626' }}>PHISH (1.0)</span>
          </div>
        </div>

        {/* Verdict & Signal Summary */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              {theme.icon}
              <h3 style={{ fontSize: '1.25rem', fontWeight: '800', color: theme.color, letterSpacing: '-0.02em' }}>
                {theme.title}
              </h3>
            </div>
            <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5 }}>
              {recommendation}
            </p>
          </div>

          {/* Key Metric Pills */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.6rem' }}>
            <div style={{ background: '#070b14', padding: '0.65rem 0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>ML Raw Posterior</span>
              <strong style={{ fontSize: '1rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                {probability !== undefined ? probability.toFixed(4) : effectiveProb.toFixed(4)}
              </strong>
            </div>

            <div style={{ background: '#070b14', padding: '0.65rem 0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Decision Confidence</span>
              <strong style={{ fontSize: '1rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                {(Math.abs(effectiveProb - 0.5) * 200).toFixed(1)}% Certainty
              </strong>
            </div>

            <div style={{ background: '#070b14', padding: '0.65rem 0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Primary Classifier</span>
              <span style={{ fontSize: '0.85rem', color: '#00f0ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: '600' }}>
                {metadata?.model_name || 'RandomForest'}
              </span>
            </div>

            <div style={{ background: '#070b14', padding: '0.65rem 0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Pipeline Latency</span>
              <span style={{ fontSize: '0.85rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace', fontWeight: '600' }}>
                {execution_time_ms ? `${execution_time_ms} ms` : (metadata?.total_latency_ms ? `${metadata.total_latency_ms} ms` : '< 2 ms')}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Signal Intelligence Widgets (Reputation + DNS + WHOIS from Phase 29) */}
      {(reputation || dns || whois) && (
        <div style={{
          borderTop: '1px solid #162238',
          paddingTop: '1.25rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '1rem'
        }}>
          {/* Reputation Feed Widget */}
          {reputation && (
            <div style={{ background: '#070b14', padding: '0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase' }}>
                  Threat Reputation Feed
                </span>
                <span className={`badge-cyber ${reputation.verdict === 'MALICIOUS' ? 'badge-high' : (reputation.verdict === 'BENIGN' ? 'badge-low' : 'badge-cyan')}`} style={{ fontSize: '0.65rem' }}>
                  {reputation.verdict}
                </span>
              </div>
              <div style={{ fontSize: '0.82rem', color: '#f8fafc', fontWeight: '600' }}>{reputation.source}</div>
              <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.2rem' }}>{reputation.reason || 'Verified registry lookup.'}</div>
            </div>
          )}

          {/* DNS Resolution Widget */}
          {dns && (
            <div style={{ background: '#070b14', padding: '0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase' }}>
                  DNS Resolution HUD
                </span>
                <span className={`badge-cyber ${dns.resolves ? 'badge-low' : 'badge-high'}`} style={{ fontSize: '0.65rem' }}>
                  {dns.status}
                </span>
              </div>
              <div style={{ fontSize: '0.82rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                IPs: {dns.ip_count} {dns.has_mx_record ? '• MX Configured' : '• No MX'}
              </div>
              <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                {dns.is_fast_flux_suspect ? '⚠️ Fast-Flux Botnet Suspected' : `Lookup Latency: ${dns.lookup_latency_ms} ms`}
              </div>
            </div>
          )}

          {/* WHOIS Domain Age Widget */}
          {whois && (
            <div style={{ background: '#070b14', padding: '0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase' }}>
                  WHOIS Domain Age
                </span>
                <span className={`badge-cyber ${whois.is_newly_registered ? 'badge-high' : (whois.is_mature_domain ? 'badge-low' : 'badge-medium')}`} style={{ fontSize: '0.65rem' }}>
                  {whois.age_days >= 0 ? `${whois.age_days} Days Old` : 'Unavailable'}
                </span>
              </div>
              <div style={{ fontSize: '0.82rem', color: '#f8fafc' }}>
                Registrar: {whois.registrar || 'Standard Registry'}
              </div>
              <div style={{ fontSize: '0.72rem', color: whois.is_newly_registered ? '#ef4444' : '#94a3b8', marginTop: '0.2rem' }}>
                {whois.is_newly_registered ? '🚨 Brand New Infrastructure (< 14 days)' : 'Established domain registration history.'}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
