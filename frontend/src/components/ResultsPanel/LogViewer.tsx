import React from 'react'
import type { Finding } from '../../types'

export default function LogViewer({ text, findings }: { text: string; findings: Finding[] }) {
  const lines = text.split('\n')
  const findingLines = new Set(findings.map(f => f.line).filter(Boolean))
  const riskOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 }

  return (
    <pre className="log-viewer-pre">
      {lines.map((l, idx) => {
        const lineNumber = idx + 1
        const hasFindings = findingLines.has(lineNumber)
        const findingsOnLine = findings.filter(f => f.line === lineNumber)
        const highestRisk = findingsOnLine.reduce((max, finding) => {
          const currentRisk = (finding.risk || 'none').toLowerCase()
          return (riskOrder[currentRisk] || 0) > (riskOrder[max] || 0) ? currentRisk : max
        }, 'none')
        const riskClass = hasFindings ? highestRisk : ''

        return (
          <div key={idx} className={`log-viewer-line ${riskClass}`}>
            <span className="log-viewer-num">{lineNumber.toString().padStart(3, ' ')} </span>
            <span>{l}</span>
          </div>
        )
      })}
    </pre>
  )
}
