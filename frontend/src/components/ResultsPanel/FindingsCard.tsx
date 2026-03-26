import React from 'react'
import type { Finding } from '../../types'

function riskClassName(risk: string) {
  const normalized = (risk || '').toUpperCase()
  if (normalized === 'CRITICAL') return 'risk-critical'
  if (normalized === 'HIGH') return 'risk-high'
  if (normalized === 'MEDIUM') return 'risk-medium'
  return 'risk-low'
}

function findingClassName(type: string, risk: string) {
  const ipClasses: Record<string, string> = {
    malicious_ip: 'finding-ip-malicious',
    attacker_ip: 'finding-ip-attacker',
    suspicious_ip: 'finding-ip-suspicious',
    repeated_external_ip: 'finding-ip-repeated',
    internal_ip_errors: 'finding-ip-internal-errors',
    external_ip: 'finding-ip-external',
  }

  return ipClasses[type] || riskClassName(risk)
}

function methodBadge(method: string) {
  const normalized = (method || 'regex').toUpperCase()
  const colorClass = `bg-${normalized.toLowerCase()}`
  return <span className={`method-badge ${colorClass}`}>{normalized}</span>
}

interface FindingsCardProps {
  findings: Finding[];
  onExportJSON: () => void;
  onExportCSV: () => void;
  onCopySummary: () => void;
}

export default function FindingsCard({
  findings,
  onExportJSON,
  onExportCSV,
  onCopySummary,
}: FindingsCardProps) {
  if (!findings || findings.length === 0) {
    return <div className="panel empty-findings">No findings detected</div>
  }

  const sortedFindings = [...findings].sort((a, b) => {
    const lineA = a.line ?? 9999
    const lineB = b.line ?? 9999
    if (lineA !== lineB) return lineA - lineB

    const riskOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    }
    const riskA = riskOrder[(a.risk || '').toLowerCase()] ?? 4
    const riskB = riskOrder[(b.risk || '').toLowerCase()] ?? 4
    return riskA - riskB
  })

  return (
    <div className="findings-container">
      <div className="findings-actions">
        <button className="accent-btn" onClick={onExportJSON}>JSON</button>
        <button className="accent-btn" onClick={onExportCSV}>CSV</button>
        <button className="accent-btn" onClick={onCopySummary}>Copy Summary</button>
      </div>
      <div className="findings-list">
        {sortedFindings.map((finding, index) => (
          <div
            key={index}
            className={`finding-card ${findingClassName(finding.type, finding.risk)}`}
          >
            <div className="finding-card-header">
              <div>
                <span className="finding-type">
                  {finding.type.replace(/_/g, ' ').toUpperCase()}
                </span>
                {methodBadge(finding.detection_method || 'regex')}
              </div>
              <div className="muted finding-line">
                {finding.line ? `Line ${finding.line}` : 'Line -'}
              </div>
            </div>

            <div className="finding-value">
              {finding.masked_value || finding.value || finding.original_line || 'No details'}
            </div>

            {finding.detail && (
              <div className="finding-detail">{finding.detail}</div>
            )}

            {finding.context && (
              <div className="finding-context">
                {finding.context.ip_type && (
                  <span>
                    Type: <strong>{finding.context.ip_type}</strong>
                  </span>
                )}
                {typeof finding.context.appearances === 'number' && (
                  <span>
                    Seen: <strong>{finding.context.appearances}x</strong>
                  </span>
                )}
                {typeof finding.context.failed_login_count === 'number' && (
                  <span className="finding-context-critical">
                    Failed logins: <strong>{finding.context.failed_login_count}</strong>
                  </span>
                )}
                {typeof finding.context.failed_logins === 'number' &&
                  typeof finding.context.failed_login_count !== 'number' && (
                    <span className="finding-context-critical">
                      Failed logins: <strong>{finding.context.failed_logins}</strong>
                    </span>
                  )}
                {typeof finding.context.error_count === 'number' && (
                  <span>
                    Errors: <strong>{finding.context.error_count}</strong>
                  </span>
                )}
              </div>
            )}

            {finding.recommendation && (
              <div className="finding-rec">
                {finding.recommendation}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
