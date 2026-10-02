import React from 'react';
import { History, RefreshCw, ExternalLink, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function HistoryTable({ history, onRefresh, onSelectUrl, isLoading }) {
  const getBadgeClass = (level) => {
    switch (level) {
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

  return (
    <div className="card" style={{ background: '#0a101f', borderColor: '#1e293b' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <History size={18} color="#3b82f6" />
          <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f8fafc' }}>
            Historical Scan Log
          </h3>
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
            ({history?.length || 0} recent inspections)
          </span>
        </div>

        <button
          type="button"
          className="btn-secondary"
          onClick={onRefresh}
          disabled={isLoading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {!history || history.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b', fontSize: '0.85rem' }}>
          No scans recorded yet. Enter a URL above to perform an automated threat assessment.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e293b', textAlign: 'left', color: '#94a3b8', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                <th style={{ padding: '0.75rem 0.5rem' }}>Timestamp</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Inspected URL</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Risk Level</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Probability</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item, idx) => (
                <tr
                  key={item.id || idx}
                  style={{
                    borderBottom: '1px solid #131c2e',
                    transition: 'background 0.15s ease'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = '#0d1527'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '0.75rem 0.5rem', color: '#64748b', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                    {formatTime(item.created_at)}
                  </td>
                  <td style={{ padding: '0.75rem 0.5rem', fontFamily: 'JetBrains Mono, monospace', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span
                      style={{ color: '#f1f5f9', cursor: 'pointer', textDecoration: 'underline' }}
                      onClick={() => onSelectUrl(item.url)}
                      title={item.url}
                    >
                      {item.url}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>
                    <span className={`badge ${getBadgeClass(item.risk_level)}`}>
                      {item.risk_level}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 0.5rem', fontFamily: 'monospace', fontWeight: '600', color: item.risk_level === 'HIGH' ? '#ef4444' : (item.risk_level === 'MEDIUM' ? '#f59e0b' : '#10b981') }}>
                    {Math.round(item.probability * 100)}%
                  </td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => onSelectUrl(item.url)}
                      style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
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
