import React, { useState } from 'react';
import {
  Mail, Search, Loader2, AlertCircle, ShieldAlert, ShieldCheck,
  AlertTriangle, ExternalLink, UserCheck, UserX, FileText, Globe, Sparkles
} from 'lucide-react';

export default function EmailAnalyzerTab({ onAnalyzeEmail, isLoading, error, result }) {
  const [subject, setSubject] = useState('');
  const [senderEmail, setSenderEmail] = useState('');
  const [senderDisplayName, setSenderDisplayName] = useState('');
  const [body, setBody] = useState('');

  const PRESETS = [
    {
      label: 'PayPal Brand Impersonation',
      category: 'CREDENTIAL HARVESTING',
      subject: 'URGENT: Suspicious Account Access Blocked — Action Required',
      senderEmail: 'security-update@paypal-verify-alert.com',
      senderDisplayName: 'PayPal Security Center',
      body: 'Dear Customer,\n\nWe detected unauthorized login attempts to your PayPal account from an unrecognized IP address. For your security, your account has been temporarily restricted.\n\nPlease verify your identity, password, and linked banking cards immediately within 24 hours to prevent permanent account suspension:\nhttps://login.paypal.com.cloud-node-402.cc/session/verify?token=9284\n\nThank you,\nPayPal Fraud Operations Team'
    },
    {
      label: 'Direct IP Harvester Phish',
      category: 'MALICIOUS HOST',
      subject: 'Invoice #INV-92849 Overdue Notice - Immediate Payment Required',
      senderEmail: 'billing@corporate-accounts-support.net',
      senderDisplayName: 'Finance Operations',
      body: 'Attention Accounts Payable,\n\nPlease find the overdue statement for Q3 attached. Download and review the transaction audit report from our secure server: http://176.77.46.141:53458/bin.sh to avoid penalty fees.\n\nUrgent action is required within 48 hours.'
    },
    {
      label: 'Legitimate Google Security Alert',
      category: 'BENIGN NOTIFICATION',
      subject: 'Security alert: New sign-in from Chrome on Windows',
      senderEmail: 'no-reply@accounts.google.com',
      senderDisplayName: 'Google Security',
      body: 'Hi Anushka,\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you do not need to do anything. If this was not you, review your account security here:\nhttps://accounts.google.com/signin/v2/identifier\n\nGoogle Cloud Identity Team'
    }
  ];

  const handlePreset = (preset) => {
    setSubject(preset.subject);
    setSenderEmail(preset.senderEmail);
    setSenderDisplayName(preset.senderDisplayName);
    setBody(preset.body);
    onAnalyzeEmail({
      subject: preset.subject,
      sender_email: preset.senderEmail,
      sender_display_name: preset.senderDisplayName,
      body: preset.body
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (subject.trim() && senderEmail.trim() && body.trim()) {
      onAnalyzeEmail({
        subject: subject.trim(),
        sender_email: senderEmail.trim(),
        sender_display_name: senderDisplayName.trim() || undefined,
        body: body.trim()
      });
    }
  };

  const verdict = result?.overall_verdict;
  const riskTier = result?.risk_tier;
  const riskScore = result?.overall_risk_score !== undefined ? Math.round(result.overall_risk_score * 100) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Input Console Card */}
      <div className="cyber-card cyber-corners" style={{ background: '#0a101f', borderColor: '#162238' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Mail size={18} color="#00f0ff" />
              <h2 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em' }}>
                Email Threat Inspector Console
              </h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
              Phase 29.4 Multi-Modal Phishing Architecture: URL Detection + Text NLP Analysis + Sender Identity Verification.
            </p>
          </div>
          <span className="badge-cyber badge-cyan">Phase 29.4 Active</span>
        </div>

        {/* Preset Vectors */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
            <Sparkles size={14} color="#00f0ff" />
            <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Load Attack Scenario Presets
            </span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                className="btn-cyber-secondary"
                onClick={() => handlePreset(p)}
                disabled={isLoading}
                style={{ fontSize: '0.75rem', padding: '0.4rem 0.75rem' }}
              >
                <span style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  backgroundColor: idx === 2 ? '#10b981' : (idx === 1 ? '#f59e0b' : '#ef4444'),
                  display: 'inline-block'
                }}></span>
                <span style={{ color: '#e2e8f0', fontWeight: '600' }}>{p.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Email Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: '600', display: 'block', marginBottom: '0.35rem' }}>
                Sender Email Address *
              </label>
              <input
                type="email"
                className="cyber-input"
                placeholder="e.g. security-alert@service.com"
                value={senderEmail}
                onChange={(e) => setSenderEmail(e.target.value)}
                required
                disabled={isLoading}
                style={{ fontSize: '0.85rem', padding: '0.75rem 1rem' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: '600', display: 'block', marginBottom: '0.35rem' }}>
                Sender Display Name Header (Optional)
              </label>
              <input
                type="text"
                className="cyber-input"
                placeholder="e.g. PayPal Support Center"
                value={senderDisplayName}
                onChange={(e) => setSenderDisplayName(e.target.value)}
                disabled={isLoading}
                style={{ fontSize: '0.85rem', padding: '0.75rem 1rem' }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: '600', display: 'block', marginBottom: '0.35rem' }}>
              Email Subject Line *
            </label>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g. URGENT: Account Suspension Notice"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              required
              disabled={isLoading}
              style={{ fontSize: '0.85rem', padding: '0.75rem 1rem' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: '600', display: 'block', marginBottom: '0.35rem' }}>
              Email Message Body (Plaintext or HTML with embedded URLs) *
            </label>
            <textarea
              className="cyber-input"
              rows={5}
              placeholder="Paste raw email body text or HTML content here..."
              value={body}
              onChange={(e) => setBody(e.target.value)}
              required
              disabled={isLoading}
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '0.85rem',
                lineHeight: 1.5,
                resize: 'vertical'
              }}
            />
          </div>

          {error && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: '8px',
              padding: '0.75rem 1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              color: '#fca5a5',
              fontSize: '0.85rem'
            }}>
              <AlertCircle size={16} color="#ef4444" />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              className="btn-cyber-primary"
              disabled={isLoading || !subject.trim() || !senderEmail.trim() || !body.trim()}
            >
              {isLoading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  <span>Scanning Multi-Modal Vector Signals...</span>
                </>
              ) : (
                <>
                  <Search size={18} />
                  <span>Execute Email Phishing Analysis</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Analysis Result Card */}
      {result && (
        <div className={`cyber-card cyber-corners ${riskTier === 'HIGH' ? 'glow-high' : (riskTier === 'MEDIUM' ? 'glow-medium' : 'glow-low')}`} style={{ background: '#0a101f' }}>
          {/* Verdict Banner */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
            paddingBottom: '1.25rem',
            borderBottom: '1px solid #162238',
            marginBottom: '1.5rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              {riskTier === 'HIGH' ? (
                <ShieldAlert size={32} color="#ef4444" />
              ) : (riskTier === 'MEDIUM' ? (
                <AlertTriangle size={32} color="#f59e0b" />
              ) : (
                <ShieldCheck size={32} color="#10b981" />
              ))}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{
                    fontSize: '1.4rem',
                    fontWeight: '900',
                    letterSpacing: '-0.02em',
                    color: riskTier === 'HIGH' ? '#ef4444' : (riskTier === 'MEDIUM' ? '#f59e0b' : '#10b981')
                  }}>
                    {verdict} VERDICT
                  </span>
                  <span className={`badge-cyber ${riskTier === 'HIGH' ? 'badge-high' : (riskTier === 'MEDIUM' ? 'badge-medium' : 'badge-low')}`}>
                    {riskTier} TIER
                  </span>
                </div>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                  {result.recommendation}
                </p>
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{
                fontSize: '2.2rem',
                fontWeight: '900',
                fontFamily: 'JetBrains Mono, monospace',
                lineHeight: 1,
                color: riskTier === 'HIGH' ? '#ef4444' : (riskTier === 'MEDIUM' ? '#f59e0b' : '#10b981')
              }}>
                {riskScore}%
              </div>
              <span style={{ fontSize: '0.68rem', color: '#64748b', fontWeight: '700', textTransform: 'uppercase' }}>
                Fused Phishing Score
              </span>
            </div>
          </div>

          {/* Multi-Modal Score Decomposition */}
          <div style={{ marginBottom: '1.75rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: '700', textTransform: 'uppercase', display: 'block', marginBottom: '0.75rem' }}>
              Multi-Modal Scoring Weights Decomposition
            </span>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
              {/* URL Score */}
              <div style={{ background: '#070b14', padding: '1rem', borderRadius: '10px', border: '1px solid #162238' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Embedded URL Risk</span>
                  <span style={{ fontSize: '0.7rem', color: '#64748b' }}>Weight: 50%</span>
                </div>
                <div style={{ fontSize: '1.35rem', fontWeight: '800', fontFamily: 'monospace', color: (result.multimodal_scores?.url_risk_score || 0) >= 0.65 ? '#ef4444' : '#f8fafc' }}>
                  {((result.multimodal_scores?.url_risk_score || 0) * 100).toFixed(1)}%
                </div>
                <div style={{ height: '4px', background: '#162238', borderRadius: '9999px', marginTop: '0.5rem', overflow: 'hidden' }}>
                  <div style={{ width: `${(result.multimodal_scores?.url_risk_score || 0) * 100}%`, background: '#ef4444', height: '100%' }}></div>
                </div>
              </div>

              {/* Sender Score */}
              <div style={{ background: '#070b14', padding: '1rem', borderRadius: '10px', border: '1px solid #162238' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Sender Anomaly Risk</span>
                  <span style={{ fontSize: '0.7rem', color: '#64748b' }}>Weight: 30%</span>
                </div>
                <div style={{ fontSize: '1.35rem', fontWeight: '800', fontFamily: 'monospace', color: (result.multimodal_scores?.sender_risk_score || 0) >= 0.40 ? '#f59e0b' : '#f8fafc' }}>
                  {((result.multimodal_scores?.sender_risk_score || 0) * 100).toFixed(1)}%
                </div>
                <div style={{ height: '4px', background: '#162238', borderRadius: '9999px', marginTop: '0.5rem', overflow: 'hidden' }}>
                  <div style={{ width: `${(result.multimodal_scores?.sender_risk_score || 0) * 100}%`, background: '#f59e0b', height: '100%' }}></div>
                </div>
              </div>

              {/* Text Score */}
              <div style={{ background: '#070b14', padding: '1rem', borderRadius: '10px', border: '1px solid #162238' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Text Urgency / Lures</span>
                  <span style={{ fontSize: '0.7rem', color: '#64748b' }}>Weight: 20%</span>
                </div>
                <div style={{ fontSize: '1.35rem', fontWeight: '800', fontFamily: 'monospace', color: (result.multimodal_scores?.text_risk_score || 0) >= 0.35 ? '#00f0ff' : '#f8fafc' }}>
                  {((result.multimodal_scores?.text_risk_score || 0) * 100).toFixed(1)}%
                </div>
                <div style={{ height: '4px', background: '#162238', borderRadius: '9999px', marginTop: '0.5rem', overflow: 'hidden' }}>
                  <div style={{ width: `${(result.multimodal_scores?.text_risk_score || 0) * 100}%`, background: '#00f0ff', height: '100%' }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Deep Subsystem Signal Breakdown Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>
            {/* Sender Identity & Header Probes */}
            <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <UserCheck size={16} color="#00f0ff" />
                <span style={{ fontSize: '0.8rem', color: '#f8fafc', fontWeight: '700', textTransform: 'uppercase' }}>
                  Sender Authenticity Probes
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
                  <span style={{ color: '#94a3b8' }}>Sender Domain:</span>
                  <span style={{ color: '#f8fafc', fontFamily: 'monospace', fontWeight: '600' }}>
                    {result.sender_analysis?.sender_domain || 'Unknown'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
                  <span style={{ color: '#94a3b8' }}>Display Name Spoofing:</span>
                  <span className={`badge-cyber ${result.sender_analysis?.display_name_spoofing_detected ? 'badge-high' : 'badge-low'}`}>
                    {result.sender_analysis?.display_name_spoofing_detected ? '🚨 DETECTED' : 'CLEAR'}
                  </span>
                </div>

                {result.sender_analysis?.anomalies_detected?.length > 0 && (
                  <div style={{ marginTop: '0.5rem', padding: '0.65rem', background: '#0c1322', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                    <span style={{ fontSize: '0.7rem', color: '#f87171', fontWeight: '700', display: 'block', marginBottom: '0.35rem' }}>
                      SECURITY ANOMALIES IDENTIFIED:
                    </span>
                    <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.72rem', color: '#cbd5e1' }}>
                      {result.sender_analysis.anomalies_detected.map((a, i) => (
                        <li key={i}>{a}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            {/* Text & Psychological Analysis */}
            <div style={{ background: '#070b14', padding: '1.1rem', borderRadius: '10px', border: '1px solid #162238' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <FileText size={16} color="#00f0ff" />
                <span style={{ fontSize: '0.8rem', color: '#f8fafc', fontWeight: '700', textTransform: 'uppercase' }}>
                  Text & Psychological Lures
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
                  <span style={{ color: '#94a3b8' }}>Urgency Psychological Triggers:</span>
                  <span className={`badge-cyber ${result.text_analysis?.has_urgency_cue ? 'badge-medium' : 'badge-low'}`}>
                    {result.text_analysis?.has_urgency_cue ? '⚠️ HIGH URGENCY' : 'STANDARD'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
                  <span style={{ color: '#94a3b8' }}>Credential Solicitation Cues:</span>
                  <span className={`badge-cyber ${result.text_analysis?.has_credential_lure ? 'badge-high' : 'badge-low'}`}>
                    {result.text_analysis?.has_credential_lure ? '🚨 HARVESTING CUE' : 'CLEAR'}
                  </span>
                </div>

                {result.text_analysis?.urgency_keywords_found?.length > 0 && (
                  <div style={{ marginTop: '0.4rem' }}>
                    <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>Urgency Trigger Tokens:</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {result.text_analysis.urgency_keywords_found.map((kw, i) => (
                        <span key={i} style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.7rem', fontFamily: 'monospace' }}>
                          "{kw}"
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Extracted Hyperlinks Inspection List */}
          {result.url_analysis && (
            <div style={{ marginTop: '1.5rem', borderTop: '1px solid #162238', paddingTop: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Globe size={16} color="#00f0ff" />
                  <span style={{ fontSize: '0.85rem', color: '#f8fafc', fontWeight: '700' }}>
                    Extracted Hyperlink Destinations ({result.url_analysis.total_urls_found || 0} discovered)
                  </span>
                </div>
                <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                  Compromised: <strong style={{ color: result.url_analysis.compromised_urls_count > 0 ? '#ef4444' : '#10b981' }}>{result.url_analysis.compromised_urls_count || 0}</strong>
                </span>
              </div>

              {(!result.url_analysis.analyzed_urls || result.url_analysis.analyzed_urls.length === 0) ? (
                <div style={{ padding: '0.85rem', background: '#070b14', borderRadius: '8px', color: '#64748b', fontSize: '0.8rem', textAlign: 'center' }}>
                  No hyperlink destinations were extracted from this message body.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                  {result.url_analysis.analyzed_urls.map((link, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '0.75rem',
                        padding: '0.75rem 1rem',
                        background: '#070b14',
                        borderRadius: '8px',
                        border: '1px solid #162238'
                      }}
                    >
                      <div style={{ flex: 1, minWidth: '240px' }}>
                        <span style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: '0.82rem',
                          color: '#f8fafc',
                          wordBreak: 'break-all'
                        }}>
                          {link.url}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <span style={{
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          fontWeight: '700',
                          color: link.risk_level === 'HIGH' ? '#ef4444' : (link.risk_level === 'MEDIUM' ? '#f59e0b' : '#10b981')
                        }}>
                          {Math.round(((link.fused_probability !== undefined ? link.fused_probability : (link.probability ?? link.ml_probability ?? 0))) * 100)}%
                        </span>

                        <span className={`badge-cyber ${link.risk_level === 'HIGH' ? 'badge-high' : (link.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low')}`}>
                          {link.risk_level}
                        </span>

                        <span style={{
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.72rem',
                          fontFamily: 'monospace',
                          fontWeight: '700',
                          background: link.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                          color: link.action === 'BLOCK' ? '#f87171' : '#34d399',
                          border: `1px solid ${link.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`
                        }}>
                          {link.action}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
