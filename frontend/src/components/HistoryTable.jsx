import React, { useState } from 'react';
import { History, RefreshCw, Search, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Filter } from 'lucide-react';

export default function HistoryTable({ history, onRefresh, onSelectUrl, isLoading }) {
  const [filterText, setFilterText] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('ALL');

  const getBadgeClass = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  const formatTime = (isoString) => {
    if (!isoString) return 'Just now';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  const filteredHistory = (history || []).filter((item) => {
    const matchesText = !filterText.trim() ||
      item.url?.toLowerCase().includes(filterText.toLowerCase()) ||
      item.prediction?.toLowerCase().includes(filterText.toLowerCase());

    const matchesRisk = selectedRisk === 'ALL' || item.risk_level === selectedRisk;

    return matchesText && matchesRisk;
  });

  return (
    <div className="cyber-card cyber-corners" style={{ background: '#0a101f', borderColor: '#162238' }}>
      {/* Header Bar */}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <History size={18} color="#00f0ff" />
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: '800', color: '#f8fafc', letterSpacing: '-0.02em' }}>
              SOC Historical Audit Log
            </h3>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Persistent scan telemetry ({history?.length || 0} total records recorded)
            </span>
          </div>
        </div>

        <button
          type="button"
          className="btn-cyber-secondary"
          onClick={onRefresh}
          disabled={isLoading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
          <span>Refresh Audit Feed</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '0.75rem',
        marginBottom: '1.25rem'
      }}>
        {/* Search Input */}
        <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Filter audit log by URL or verdict..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{ fontSize: '0.82rem', padding: '0.55rem 0.85rem 0.55rem 2.2rem' }}
          />
          <Search size={14} color="#64748b" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
        </div>

        {/* Risk Level Filter Chips */}
        <div style={{ display: 'flex', gap: '0.35rem', background: '#070b14', padding: '0.2rem', borderRadius: '6px', border: '1px solid #162238' }}>
          {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((risk) => (
            <button
              key={risk}
              type="button"
              className={`nav-tab ${selectedRisk === risk ? 'active' : ''}`}
              onClick={() => setSelectedRisk(risk)}
              style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }}
            >
              {risk}
            </button>
          ))}
        </div>
      </div>

      {/* Table Data */}
      {filteredHistory.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2.5rem 1rem', color: '#64748b', fontSize: '0.85rem', background: '#070b14', borderRadius: '8px', border: '1px solid #162238' }}>
          No scan records match the active criteria. Execute a scan in the URL Scanner or Email Inspector to generate security telemetry.
        </div>
      ) : (
        <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid #162238' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', background: '#070b14' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #162238', textAlign: 'left', color: '#64748b', fontSize: '0.72rem', textTransform: 'uppercase', background: '#0a101f' }}>
                <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
                <th style={{ padding: '0.75rem 1rem' }}>Destination Endpoint</th>
                <th style={{ padding: '0.75rem 1rem' }}>Risk Tier</th>
                <th style={{ padding: '0.75rem 1rem' }}>Threat Prob</th>
                <th style={{ padding: '0.75rem 1rem' }}>Directive</th>
                <th style={{ padding: '0.75rem 1rem' }}>Latency</th>
                <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((item, idx) => (
                <tr
                  key={item.id || idx}
                  style={{
                    borderBottom: '1px solid #131c2e',
                    transition: 'background 0.15s ease'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = '#0d1527'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '0.75rem 1rem', color: '#64748b', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }}>
                    {formatTime(item.created_at)}
                  </td>

                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', maxWidth: '340px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span
                      style={{ color: '#f1f5f9', cursor: 'pointer', textDecoration: 'underline' }}
                      onClick={() => onSelectUrl(item.url)}
                      title={item.url}
                    >
                      {item.url}
                    </span>
                  </td>

                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span className={`badge-cyber ${getBadgeClass(item.risk_level)}`}>
                      {item.risk_level}
                    </span>
                  </td>

                  <td style={{
                    padding: '0.75rem 1rem',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: '700',
                    color: item.risk_level === 'HIGH' ? '#ef4444' : (item.risk_level === 'MEDIUM' ? '#f59e0b' : '#10b981')
                  }}>
                    {Math.round(item.probability * 100)}%
                  </td>

                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span style={{
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      fontFamily: 'monospace',
                      fontWeight: '700',
                      background: item.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : (item.action === 'CAUTION' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'),
                      color: item.action === 'BLOCK' ? '#f87171' : (item.action === 'CAUTION' ? '#fbbf24' : '#34d399'),
                      border: `1px solid ${item.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.4)' : (item.action === 'CAUTION' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)')}`
                    }}>
                      {item.action || 'ALLOW'}
                    </span>
                  </td>

                  <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {item.feature_extraction_ms ? `${(item.feature_extraction_ms + (item.model_inference_ms || 0)).toFixed(2)} ms` : '< 2 ms'}
                  </td>

                  <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                    <button
                      type="button"
                      className="btn-cyber-secondary"
                      onClick={() => onSelectUrl(item.url)}
                      style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem' }}
                    >
                      Re-Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
