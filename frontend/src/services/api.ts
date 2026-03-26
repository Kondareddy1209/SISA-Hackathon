import type { AnalyzeResponse, AnalyzeOptions, LiveLogEntry } from "../types/index"

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request<T>(path: string, init: RequestInit = {}, timeout = 30000): Promise<T> {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeout)
  try {
    const res = await fetch(`${API_BASE_URL}${path}`, { ...init, signal: controller.signal })
    clearTimeout(id)
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`${res.status} ${res.statusText}: ${text}`)
    }
    return await res.json()
  } finally {
    clearTimeout(id)
  }
}

export async function analyzeText(content: string, inputType: string, options: AnalyzeOptions): Promise<AnalyzeResponse> {
  return request<AnalyzeResponse>('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input_type: inputType, content, options }),
  })
}

export async function analyzeFile(file: File, options: AnalyzeOptions): Promise<AnalyzeResponse> {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('options', JSON.stringify(options))
  return request<AnalyzeResponse>('/analyze', { method: 'POST', body: fd })
}

export async function checkHealth(): Promise<{ status: string; version: string }> {
  return request('/health')
}

export async function getLogHistory(): Promise<LiveLogEntry[]> {
  return request<LiveLogEntry[]>('/api/logs/history')
}

export function streamLogs(
  onMessage: (entry: LiveLogEntry) => void,
  onError?: (error: Event | Error) => void,
) {
  const source = new EventSource(`${API_BASE_URL}/api/logs/stream`)

  source.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data) as LiveLogEntry)
    } catch (error) {
      onError?.(error instanceof Error ? error : new Error('Failed to parse log event'))
    }
  }

  source.onerror = (error) => {
    onError?.(error)
  }

  return () => {
    source.close()
  }
}
