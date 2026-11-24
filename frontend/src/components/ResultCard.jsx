import React from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink,
  Clock, Cpu, Database, Network, Globe, Radio, CheckCircle, XCircle, Zap
} from 'lucide-react';

export default function ResultCard({ result }) {
  if (!result) return null;

  const {
    url,
    prediction,
    probability,
    ml_probability,
    composite_threat_score,
    fused_probability,
    boundary_separation_margin,
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
    is_enhanced_mode,
    execution_time_ms
  } = result;

  // Explicitly separate composite threat score from pure ML posterior
  const effectiveProb = composite_threat_score !== undefined 
    ? composite_threat_score 
    : (fused_probability !== undefined ? fused_probability : probability);
  const mlProb = ml_probability !== undefined ? ml_probability : probability;
  const margin = boundary_separation_margin !== undefined 
    ? boundary_separation_margin 
    : Math.abs(effectiveProb - 0.50);

  const effectiveRisk = final_risk_level || risk_level;
  const effectiveAction = final_action || action;
  const pct = Math.round(effectiveProb * 100);

  // Threat style mappings
  const getRiskTheme = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return {
          color: '#ff1744',
          glowClass: 'glow-high',
          badgeClass: 'badge-high',
          title: 'CONFIRMED PHISHING THREAT',
          accentGradient: 'linear-gradient(135deg, #ff1744, #b71c1c)',
          icon: <ShieldAlert size={30} color="#ff1744" />
        };
      case 'MEDIUM':
        return {
          color: '#f59e0b',
          glowClass: 'glow-medium',
          badgeClass: 'badge-medium',
          title: 'SUSPICIOUS WEB ANOMALY',
          accentGradient: 'linear-gradient(135deg, #f59e0b, #b45309)',
          icon: <AlertTriangle size={30} color="#f59e0b" />
        };
      default:
        return {
          color: '#00e676',
          glowClass: 'glow-low',
          badgeClass: 'badge-low',
          title: 'VERIFIED LEGITIMATE DESTINATION',
          accentGradient: 'linear-gradient(135deg, #00e676, #007e33)',
          icon: <ShieldCheck size={30} color="#00e676" />
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
    <div
      className={`cyber-card cyber-corners ${theme.glowClass}`}
      style={{
        marginBottom: '1.75rem',
        background: 'rgba(10, 19, 41, 0.82)',
        borderColor: '#162442'
      }}
    >
      {/* Target URL Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: '1rem',
        paddingBottom: '1.25rem',
        borderBottom: '1px solid #162442',
        marginBottom: '1.5rem'
      }}>
        <div style={{ flex: 1, minWidth: '280px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
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
            background: 'rgba(6, 11, 23, 0.85)',
            padding: '0.65rem 0.95rem',
            borderRadius: '8px',
            border: '1px solid #162442',
            boxShadow: 'inset 0 2px 4px rgba(0, 0, 0, 0.3)'
          }}>
            {url}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          <span className={`badge-cyber ${theme.badgeClass}`} style={{ fontSize: '0.82rem', padding: '0.45rem 0.95rem' }}>
            {effectiveRisk} RISK
          </span>

          <span style={{
            padding: '0.45rem 0.95rem',
            borderRadius: '8px',
            fontSize: '0.78rem',
            fontWeight: '800',
            fontFamily: 'JetBrains Mono, monospace',
            background: effectiveAction === 'BLOCK' ? 'rgba(255, 23, 68, 0.2)' : (effectiveAction === 'CAUTION' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(0, 230, 118, 0.2)'),
            color: effectiveAction === 'BLOCK' ? '#ff5252' : (effectiveAction === 'CAUTION' ? '#fbbf24' : '#00e676'),
            border: `1px solid ${effectiveAction === 'BLOCK' ? 'rgba(255, 23, 68, 0.45)' : (effectiveAction === 'CAUTION' ? 'rgba(245, 158, 11, 0.45)' : 'rgba(0, 230, 118, 0.45)')}`,
            boxShadow: `0 0 15px ${theme.color}25`
          }}>
            DIRECTIVE: {effectiveAction}
          </span>
        </div>
      </div>

      {/* Main Threat Dashboard Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '2rem',
        alignItems: 'center',
        marginBottom: '1.5rem'
      }}>
        {/* Radial Threat Gauge */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'rgba(6, 11, 23, 0.75)',
          borderRadius: '14px',
          border: '1px solid #162442',
          padding: '1.85rem 1.4rem',
          position: 'relative',
          boxShadow: 'inset 0 0 30px rgba(0, 0, 0, 0.5)'
        }}>
          <div style={{ position: 'relative', width: '220px', height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="220" height="200" viewBox="0 0 200 180" style={{ transform: 'rotate(150deg)' }}>
              {/* Background Arc Track */}
              <circle
                cx="100"
                cy="100"
                r={radius}
                fill="none"
                stroke="#162442"
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
                  filter: `drop-shadow(0 0 12px ${theme.color})`
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
                fontSize: '2.8rem',
                fontWeight: '900',
                color: theme.color,
                lineHeight: 1,
                fontFamily: 'JetBrains Mono, monospace',
                letterSpacing: '-0.03em',
                textShadow: `0 0 20px ${theme.color}66`
              }}>
                {pct}%
              </span>
              <span style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: '0.35rem' }}>
                {is_enhanced_mode || composite_threat_score !== undefined ? 'COMPOSITE THREAT SCORE' : 'CALIBRATED ML PROBABILITY'}
              </span>
            </div>
          </div>

          {/* Threshold Legend Bar */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            width: '100%',
            maxWidth: '250px',
            fontSize: '0.68rem',
            color: '#64748b',
            fontFamily: 'JetBrains Mono, monospace',
            marginTop: '-12px'
          }}>
            <span style={{ color: '#00e676' }}>SAFE (0.0)</span>
            <span style={{ color: '#f59e0b' }}>T1: 0.40</span>
            <span style={{ color: '#ff1744' }}>T2: 0.65</span>
            <span style={{ color: '#d50000' }}>PHISH (1.0)</span>
          </div>
        </div>

        {/* Verdict & Signal Summary */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.45rem' }}>
              {theme.icon}
              <h3 style={{ fontSize: '1.3rem', fontWeight: '900', color: theme.color, letterSpacing: '-0.02em', textShadow: `0 0 15px ${theme.color}40` }}>
                {theme.title}
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.55 }}>
              {recommendation}
            </p>
          </div>

          {/* Key Metric Pills */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.65rem' }}>
            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.75rem 0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>ML Calibrated Posterior</span>
              <strong style={{ fontSize: '1.05rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                {(mlProb * 100).toFixed(1)}% <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>({mlProb.toFixed(4)})</span>
              </strong>
            </div>

            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.75rem 0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>Boundary Separation Margin</span>
              <strong style={{ fontSize: '1.05rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                {(margin * 100).toFixed(1)}% Distance
              </strong>
            </div>

            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.75rem 0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>Primary Classifier</span>
              <span style={{ fontSize: '0.88rem', color: '#00e5ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: '700' }}>
                {metadata?.model_name || 'RandomForest'}
              </span>
            </div>

            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.75rem 0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>Pipeline Latency</span>
              <span style={{ fontSize: '0.88rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace', fontWeight: '700' }}>
                {execution_time_ms ? `${execution_time_ms} ms` : (metadata?.total_latency_ms ? `${metadata.total_latency_ms} ms` : '< 2 ms')}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Signal Intelligence Widgets (Reputation + DNS + WHOIS) */}
      {(reputation || dns || whois) && (
        <div style={{
          borderTop: '1px solid #162442',
          paddingTop: '1.35rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '1rem'
        }}>
          {/* Reputation Feed Widget */}
          {reputation && (
            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase' }}>
                  Threat Reputation Feed
                </span>
                <span className={`badge-cyber ${reputation.verdict === 'MALICIOUS' ? 'badge-high' : (reputation.verdict === 'BENIGN' ? 'badge-low' : 'badge-cyan')}`} style={{ fontSize: '0.65rem' }}>
                  {reputation.verdict}
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', color: '#f8fafc', fontWeight: '700' }}>{reputation.source}</div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.25rem' }}>{reputation.reason || 'Verified registry lookup.'}</div>
            </div>
          )}

          {/* DNS Resolution Widget */}
          {dns && (
            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase' }}>
                  DNS Resolution HUD
                </span>
                <span className={`badge-cyber ${dns.resolves ? 'badge-low' : 'badge-high'}`} style={{ fontSize: '0.65rem' }}>
                  {dns.status}
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                IPs: {dns.ip_count} {dns.has_mx_record ? '• MX Configured' : '• No MX'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                {dns.is_fast_flux_suspect ? '⚠️ Fast-Flux Botnet Suspected' : `Lookup Latency: ${dns.lookup_latency_ms} ms`}
              </div>
            </div>
          )}

          {/* WHOIS Domain Age Widget */}
          {whois && (
            <div style={{ background: 'rgba(6, 11, 23, 0.75)', padding: '0.95rem', borderRadius: '10px', border: '1px solid #162442' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '800', textTransform: 'uppercase' }}>
                  WHOIS Domain Age
                </span>
                <span className={`badge-cyber ${whois.is_newly_registered ? 'badge-high' : (whois.is_mature_domain ? 'badge-low' : 'badge-medium')}`} style={{ fontSize: '0.65rem' }}>
                  {whois.age_days >= 0 ? `${whois.age_days} Days Old` : 'Unavailable'}
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', color: '#f8fafc', fontWeight: '600' }}>
                Registrar: {whois.registrar || 'Standard Registry'}
              </div>
              <div style={{ fontSize: '0.75rem', color: whois.is_newly_registered ? '#ff5252' : '#94a3b8', marginTop: '0.25rem' }}>
                {whois.is_newly_registered ? '🚨 Brand New Infrastructure (< 14 days)' : 'Established domain registration history.'}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
