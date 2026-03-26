import { useDeferredValue, useEffect, useRef, useState } from 'react'

import { getLogHistory, streamLogs } from '../services/api'
import type { LiveLogEntry } from '../types'

type StreamStatus = 'idle' | 'connecting' | 'live' | 'error'

const MAX_LOG_LINES = 200

function trimLogs(entries: LiveLogEntry[]) {
  const seen = new Set<string>()
  const deduped: LiveLogEntry[] = []

  for (const entry of entries) {
    const key = `${entry.timestamp}|${entry.level}|${entry.message}|${entry.path ?? ''}|${entry.event ?? ''}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    deduped.push(entry)
  }

  return deduped.slice(-MAX_LOG_LINES)
}

function formatTimestamp(timestamp: string) {
  const parsed = new Date(timestamp)
  if (Number.isNaN(parsed.getTime())) {
    return timestamp
  }

  return parsed.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function buildMessage(entry: LiveLogEntry) {
  const details: string[] = []

  if (entry.method && entry.path) {
    details.push(`${entry.method} ${entry.path}`)
  }
  if (typeof entry.status_code === 'number') {
    details.push(`status ${entry.status_code}`)
  }
  if (typeof entry.response_time_ms === 'number') {
    details.push(`${Math.round(entry.response_time_ms)}ms`)
  }
  if (entry.ip) {
    details.push(entry.ip)
  }

  return details.length > 0 ? `${entry.message} • ${details.join(' • ')}` : entry.message
}

export default function LogViewer({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const [logs, setLogs] = useState<LiveLogEntry[]>([])
  const [filter, setFilter] = useState('')
  const [paused, setPaused] = useState(false)
  const [status, setStatus] = useState<StreamStatus>('idle')
  const listRef = useRef<HTMLDivElement | null>(null)
  const pausedRef = useRef(paused)
  const deferredFilter = useDeferredValue(filter.trim().toLowerCase())

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    if (!open) {
      return
    }

    let cancelled = false
    setStatus('connecting')

    getLogHistory()
      .then((history) => {
        if (!cancelled) {
          setLogs(trimLogs(history))
        }
      })
      .catch(() => {
        if (!cancelled) {
          setStatus('error')
        }
      })

    const stopStreaming = streamLogs(
      (entry) => {
        if (cancelled || pausedRef.current) {
          return
        }

        setStatus('live')
        setLogs((current) => trimLogs([...current, entry]))
      },
      () => {
        if (!cancelled) {
          setStatus('error')
        }
      },
    )

    return () => {
      cancelled = true
      stopStreaming()
      setStatus('idle')
    }
  }, [open])

  useEffect(() => {
    if (!open || paused || !listRef.current) {
      return
    }

    listRef.current.scrollTop = listRef.current.scrollHeight
  }, [open, paused, logs, deferredFilter])

  useEffect(() => {
    if (!open) {
      return
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose()
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  if (!open) {
    return null
  }

  const visibleLogs = logs.filter((entry) => {
    if (!deferredFilter) {
      return true
    }

    const haystack = `${entry.timestamp} ${entry.level} ${entry.message} ${entry.path ?? ''} ${entry.source ?? ''}`.toLowerCase()
    return haystack.includes(deferredFilter)
  })

  const statusLabel = paused
    ? 'Paused'
    : status === 'live'
      ? 'Live'
      : status === 'connecting'
        ? 'Connecting'
        : status === 'error'
          ? 'Reconnecting'
          : 'Idle'

  return (
    <>
      <button className="log-drawer-overlay" type="button" aria-label="Close live logs" onClick={onClose} />
      <aside className="log-drawer" role="dialog" aria-modal="true" aria-label="Live logs">
        <div className="log-drawer-header">
          <div>
            <div className="log-drawer-title">Live Logs</div>
            <div className="log-drawer-subtitle">{statusLabel} • {visibleLogs.length} shown</div>
          </div>
          <button className="log-drawer-close" type="button" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="log-drawer-controls">
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Search logs"
            className="log-search-input"
            aria-label="Search logs"
          />
          <button className="accent-btn" type="button" onClick={() => setPaused((current) => !current)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button className="accent-btn" type="button" onClick={() => setLogs([])}>
            Clear
          </button>
        </div>

        <div ref={listRef} className="log-drawer-body">
          {visibleLogs.length === 0 ? (
            <div className="log-empty-state">No logs match the current filter.</div>
          ) : (
            visibleLogs.map((entry, index) => (
              <div key={`${entry.timestamp}-${entry.message}-${index}`} className="live-log-row">
                <div className="live-log-meta">
                  <span className="live-log-time">{formatTimestamp(entry.timestamp)}</span>
                  <span className={`live-log-level ${String(entry.level).toLowerCase()}`}>{entry.level}</span>
                </div>
                <div className="live-log-message">{buildMessage(entry)}</div>
              </div>
            ))
          )}
        </div>
      </aside>
    </>
  )
}
