import React, { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp, Check, AlertOctagon, Info } from 'lucide-react';

export default function RiskExplanation({ explanation, rawFeatures }) {
  const [showFeatures, setShowFeatures] = useState(false);

  if (!explanation) return null;

  const {
    top_risk_contributors = [],
    top_mitigating_factors = [],
    narrative_signals = [],
    narrative_mitigators = []
  } = explanation;

  return (
    <div className="card" style={{ marginBottom: '1.5rem', background: '#0a101f' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f8fafc', marginBottom: '0.2rem' }}>
            Explainability Engine (SHAP Attributions)
          </h3>
          <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Mathematical Shapley feature contributions explaining why this URL received its probability score.
          </p>
        </div>
        <span className="badge badge-blue">TreeExplainer Exact</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem', marginBottom: '1.25rem' }}>
        {/* Risk Contributors (+ Impact) */}
        <div style={{ background: '#070b14', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: '#f87171', fontWeight: '700', fontSize: '0.85rem' }}>
            <AlertOctagon size={16} />
            <span>Top Risk-Increasing Indicators (+ Impact)</span>
          </div>

          {top_risk_contributors.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No severe risk drivers identified.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {top_risk_contributors.map((item, idx) => (
                <div key={idx} style={{ background: '#0c1322', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.3rem' }}>
                    <span style={{ color: '#f1f5f9', fontWeight: '500' }}>
                      {item.feature.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: '#ef4444', fontWeight: '700', fontFamily: 'monospace' }}>
                      +{item.shap_impact.toFixed(4)}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b' }}>
                    <span>Observed Value: <strong style={{ color: '#94a3b8' }}>{item.value}</strong></span>
                    <span>Pushes toward Phishing</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Mitigating Factors (- Impact) */}
        <div style={{ background: '#070b14', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: '#34d399', fontWeight: '700', fontSize: '0.85rem' }}>
            <Check size={16} />
            <span>Top Mitigating / Safe Factors (- Impact)</span>
          </div>

          {top_mitigating_factors.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No strong mitigating factors observed.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {top_mitigating_factors.map((item, idx) => (
                <div key={idx} style={{ background: '#0c1322', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.3rem' }}>
                    <span style={{ color: '#f1f5f9', fontWeight: '500' }}>
                      {item.feature.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: '#10b981', fontWeight: '700', fontFamily: 'monospace' }}>
                      {item.shap_impact.toFixed(4)}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b' }}>
                    <span>Observed Value: <strong style={{ color: '#94a3b8' }}>{item.value}</strong></span>
                    <span>Pulls toward Legitimate</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Raw 22 Features Toggle */}
      {rawFeatures && (
        <div>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setShowFeatures(!showFeatures)}
            style={{ width: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.5rem', padding: '0.6rem' }}
          >
            <span>{showFeatures ? 'Hide Extracted 22-Feature Vector' : 'Inspect Full 22-Feature Numerical Vector'}</span>
            {showFeatures ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showFeatures && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
              gap: '0.6rem',
              marginTop: '0.75rem',
              padding: '1rem',
              background: '#070b14',
              borderRadius: '8px',
              border: '1px solid #1e293b',
              fontSize: '0.75rem'
            }}>
              {Object.entries(rawFeatures).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.25rem 0.4rem', borderBottom: '1px solid #1e293b' }}>
                  <span style={{ color: '#94a3b8' }}>{k}:</span>
                  <span style={{ fontFamily: 'monospace', color: '#f8fafc', fontWeight: '600' }}>{typeof v === 'number' ? v.toFixed ? (v % 1 === 0 ? v : v.toFixed(3)) : v : String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
