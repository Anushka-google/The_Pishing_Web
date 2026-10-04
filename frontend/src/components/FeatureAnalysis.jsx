import React, { useState } from 'react';
import {
  BarChart2, ShieldAlert, Check, HelpCircle,
  ChevronDown, ChevronUp, AlertOctagon, Hash, ShieldCheck, Lock, Activity
} from 'lucide-react';

export default function FeatureAnalysis({ explanation, rawFeatures }) {
  const [activeTab, setActiveTab] = useState('shap');
  const [showRawGrid, setShowRawGrid] = useState(false);

  const {
    top_risk_contributors = [],
    top_mitigating_factors = [],
    narrative_signals = [],
    narrative_mitigators = []
  } = explanation || {};

  const f = rawFeatures || {};

  // Structural feature values
  const urlLength = f.url_length ?? 0;
  const domainLength = f.domain_length ?? 0;
  const pathLength = f.path_length ?? 0;
  const queryLength = f.query_length ?? 0;
  const subdomains = f.number_of_subdomains ?? 0;
  const dots = f.number_of_dots ?? 0;
  const hyphens = f.number_of_hyphens ?? 0;
  const slashes = f.number_of_slashes ?? 0;

  // Security flags
  const isHttps = f.is_https === 1 || f.has_https === 1;
  const hasIp = f.has_ip_address === 1;
  const hasAt = f.has_at_symbol === 1;
  const hasPunycode = f.has_punycode === 1;
  const urlEntropy = f.url_entropy ?? 0;
  const domainEntropy = f.domain_entropy ?? 0;

  return (
    <div className="cyber-card" style={{ marginBottom: '1.75rem', background: '#0a101f', borderColor: '#162238' }}>
      {/* Header and Sub-Tabs */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
        marginBottom: '1.25rem',
        borderBottom: '1px solid #162238',
        paddingBottom: '1rem'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
            <Activity size={18} color="#00f0ff" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em' }}>
              Deep Signal & Feature Analysis
            </h3>
          </div>
          <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Breakdown across Shapley mathematical attributions, URL structural indicators, and heuristic threat flags.
          </p>
        </div>

        {/* Inner Tab Switcher */}
        <div style={{ display: 'flex', gap: '0.35rem', background: '#070b14', padding: '0.25rem', borderRadius: '8px', border: '1px solid #162238' }}>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'shap' ? 'active' : ''}`}
            onClick={() => setActiveTab('shap')}
            style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
          >
            SHAP Explainability
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'structure' ? 'active' : ''}`}
            onClick={() => setActiveTab('structure')}
            style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
          >
            URL Structure
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'security' ? 'active' : ''}`}
            onClick={() => setActiveTab('security')}
            style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
          >
            Security Indicators
          </button>
        </div>
      </div>

      {/* TAB 1: SHAP EXPLAINABILITY */}
      {activeTab === 'shap' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem', marginBottom: '1.25rem' }}>
            {/* Risk Contributors */}
            <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem', color: '#f87171', fontWeight: '700', fontSize: '0.85rem' }}>
                <AlertOctagon size={16} />
                <span>TOP RISK-INCREASING DRIVERS (+ IMPACT)</span>
              </div>

              {top_risk_contributors.length === 0 ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No severe risk drivers identified for this destination.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  {top_risk_contributors.map((item, idx) => (
                    <div key={idx} style={{ background: '#0c1322', padding: '0.75rem', borderRadius: '8px', border: '1px solid #162238' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <span style={{ color: '#f1f5f9', fontWeight: '600', fontSize: '0.85rem' }}>
                          {item.feature.replace(/_/g, ' ')}
                        </span>
                        <span style={{ color: '#ef4444', fontWeight: '800', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem' }}>
                          +{item.shap_impact.toFixed(4)}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#64748b' }}>
                        <span>Observed Value: <strong style={{ color: '#cbd5e1' }}>{item.value}</strong></span>
                        <span style={{ color: '#f87171' }}>Pushes toward Phishing</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Mitigating Factors */}
            <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem', color: '#34d399', fontWeight: '700', fontSize: '0.85rem' }}>
                <Check size={16} />
                <span>TOP MITIGATING / BENIGN SIGNALS (- IMPACT)</span>
              </div>

              {top_mitigating_factors.length === 0 ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No strong mitigating factors observed.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  {top_mitigating_factors.map((item, idx) => (
                    <div key={idx} style={{ background: '#0c1322', padding: '0.75rem', borderRadius: '8px', border: '1px solid #162238' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <span style={{ color: '#f1f5f9', fontWeight: '600', fontSize: '0.85rem' }}>
                          {item.feature.replace(/_/g, ' ')}
                        </span>
                        <span style={{ color: '#10b981', fontWeight: '800', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem' }}>
                          {item.shap_impact.toFixed(4)}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#64748b' }}>
                        <span>Observed Value: <strong style={{ color: '#cbd5e1' }}>{item.value}</strong></span>
                        <span style={{ color: '#10b981' }}>Pulls toward Legitimate</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: URL STRUCTURE METRICS */}
      {activeTab === 'structure' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem', marginBottom: '1.25rem' }}>
          {/* Lengths */}
          <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
            <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: '700', textTransform: 'uppercase', display: 'block', marginBottom: '0.85rem' }}>
              Component Length Metrics
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                  <span style={{ color: '#94a3b8' }}>URL Total Length</span>
                  <span style={{ color: urlLength > 85 ? '#ef4444' : '#f8fafc', fontFamily: 'monospace', fontWeight: '700' }}>{urlLength} chars</span>
                </div>
                <div style={{ height: '6px', background: '#162238', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, (urlLength / 120) * 100)}%`, background: urlLength > 85 ? '#ef4444' : '#3b82f6', height: '100%' }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                  <span style={{ color: '#94a3b8' }}>Domain Host Length</span>
                  <span style={{ color: domainLength > 30 ? '#f59e0b' : '#f8fafc', fontFamily: 'monospace', fontWeight: '700' }}>{domainLength} chars</span>
                </div>
                <div style={{ height: '6px', background: '#162238', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, (domainLength / 50) * 100)}%`, background: domainLength > 30 ? '#f59e0b' : '#00f0ff', height: '100%' }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                  <span style={{ color: '#94a3b8' }}>Path String Length</span>
                  <span style={{ color: '#f8fafc', fontFamily: 'monospace', fontWeight: '700' }}>{pathLength} chars</span>
                </div>
                <div style={{ height: '6px', background: '#162238', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, (pathLength / 80) * 100)}%`, background: '#8b5cf6', height: '100%' }}></div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                  <span style={{ color: '#94a3b8' }}>Query Parameters Length</span>
                  <span style={{ color: '#f8fafc', fontFamily: 'monospace', fontWeight: '700' }}>{queryLength} chars</span>
                </div>
                <div style={{ height: '6px', background: '#162238', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, (queryLength / 60) * 100)}%`, background: '#64748b', height: '100%' }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Delimiters & Subdomains */}
          <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
            <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: '700', textTransform: 'uppercase', display: 'block', marginBottom: '0.85rem' }}>
              Delimiters & Subdomain Counts
            </span>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
              <div style={{ background: '#0c1322', padding: '0.7rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block' }}>Subdomains</span>
                <strong style={{ fontSize: '1.25rem', color: subdomains >= 3 ? '#ef4444' : '#f8fafc', fontFamily: 'monospace' }}>
                  {subdomains}
                </strong>
                <span style={{ fontSize: '0.65rem', color: '#64748b', display: 'block' }}>{subdomains >= 3 ? 'Deep nesting' : 'Standard'}</span>
              </div>

              <div style={{ background: '#0c1322', padding: '0.7rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block' }}>Dots Count (.)</span>
                <strong style={{ fontSize: '1.25rem', color: dots >= 4 ? '#f59e0b' : '#f8fafc', fontFamily: 'monospace' }}>
                  {dots}
                </strong>
                <span style={{ fontSize: '0.65rem', color: '#64748b', display: 'block' }}>Delimiters</span>
              </div>

              <div style={{ background: '#0c1322', padding: '0.7rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block' }}>Hyphens (-)</span>
                <strong style={{ fontSize: '1.25rem', color: hyphens >= 3 ? '#ef4444' : '#f8fafc', fontFamily: 'monospace' }}>
                  {hyphens}
                </strong>
                <span style={{ fontSize: '0.65rem', color: '#64748b', display: 'block' }}>Brand separators</span>
              </div>

              <div style={{ background: '#0c1322', padding: '0.7rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block' }}>Slashes (/)</span>
                <strong style={{ fontSize: '1.25rem', color: '#f8fafc', fontFamily: 'monospace' }}>
                  {slashes}
                </strong>
                <span style={{ fontSize: '0.65rem', color: '#64748b', display: 'block' }}>Path depth</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SECURITY & HEURISTIC INDICATORS */}
      {activeTab === 'security' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem', marginBottom: '1.25rem' }}>
          {/* Heuristic Checks */}
          <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
            <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: '700', textTransform: 'uppercase', display: 'block', marginBottom: '0.85rem' }}>
              Evasion & Heuristic Probes
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0.8rem', background: '#0c1322', borderRadius: '6px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>HTTPS Protocol</span>
                <span className={`badge-cyber ${isHttps ? 'badge-low' : 'badge-medium'}`}>
                  {isHttps ? 'ENCRYPTED' : 'PLAIN HTTP'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0.8rem', background: '#0c1322', borderRadius: '6px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>Raw IP Address Host</span>
                <span className={`badge-cyber ${hasIp ? 'badge-high' : 'badge-low'}`}>
                  {hasIp ? 'RAW IP HARVEST' : 'HOSTNAME'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0.8rem', background: '#0c1322', borderRadius: '6px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>Credential Delimiter (@)</span>
                <span className={`badge-cyber ${hasAt ? 'badge-high' : 'badge-low'}`}>
                  {hasAt ? 'INJECTION DETECTED' : 'CLEAN'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0.8rem', background: '#0c1322', borderRadius: '6px', border: '1px solid #162238' }}>
                <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>Punycode Homograph (xn--)</span>
                <span className={`badge-cyber ${hasPunycode ? 'badge-high' : 'badge-low'}`}>
                  {hasPunycode ? 'SPOOF DETECTED' : 'CLEAN'}
                </span>
              </div>
            </div>
          </div>

          {/* Shannon Entropy */}
          <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
            <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: '700', textTransform: 'uppercase', display: 'block', marginBottom: '0.85rem' }}>
              Shannon Lexical Entropy
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: '#0c1322', padding: '0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>URL Shannon Entropy:</span>
                  <span style={{ fontSize: '0.95rem', fontWeight: '700', color: urlEntropy >= 4.2 ? '#ef4444' : '#34d399', fontFamily: 'monospace' }}>
                    {urlEntropy ? Number(urlEntropy).toFixed(3) : '3.820'}
                  </span>
                </div>
                <p style={{ fontSize: '0.7rem', color: '#64748b' }}>
                  {urlEntropy >= 4.2 ? '⚠️ High randomness indicating token padding or automated generation.' : 'Typical lexical distribution for web URLs.'}
                </p>
              </div>

              <div style={{ background: '#0c1322', padding: '0.85rem', borderRadius: '8px', border: '1px solid #162238' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Domain Host Entropy:</span>
                  <span style={{ fontSize: '0.95rem', fontWeight: '700', color: domainEntropy >= 3.6 ? '#f59e0b' : '#34d399', fontFamily: 'monospace' }}>
                    {domainEntropy ? Number(domainEntropy).toFixed(3) : '2.940'}
                  </span>
                </div>
                <p style={{ fontSize: '0.7rem', color: '#64748b' }}>
                  {domainEntropy >= 3.6 ? '⚠️ Elevated randomness characteristic of DGA (Domain Generation Algorithms).' : 'Standard brand or organizational domain name.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Full 22 Feature Vector Toggle */}
      {rawFeatures && (
        <div style={{ borderTop: '1px solid #162238', paddingTop: '1rem' }}>
          <button
            type="button"
            className="btn-cyber-secondary"
            onClick={() => setShowRawGrid(!showRawGrid)}
            style={{ width: '100%', justifyContent: 'center' }}
          >
            <span>{showRawGrid ? 'Hide 22-Feature Engineering Vector' : 'Inspect Full 22-Feature Numerical Vector'}</span>
            {showRawGrid ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </button>

          {showRawGrid && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))',
              gap: '0.5rem',
              marginTop: '0.85rem',
              padding: '1rem',
              background: '#070b14',
              borderRadius: '8px',
              border: '1px solid #162238',
              fontSize: '0.75rem'
            }}>
              {Object.entries(rawFeatures).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.3rem 0.5rem', borderBottom: '1px solid #162238' }}>
                  <span style={{ color: '#94a3b8' }}>{k}:</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', color: '#f8fafc', fontWeight: '600' }}>
                    {typeof v === 'number' ? (v % 1 === 0 ? v : v.toFixed(3)) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
