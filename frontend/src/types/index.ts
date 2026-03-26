export type InputType = "text" | "file" | "sql" | "log" | "chat"
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "low" | "medium" | "high" | "critical"
export type ActionTaken = "allowed" | "masked" | "blocked"

export interface Finding {
  type: string;
  risk: RiskLevel;
  line?: number;
  masked_value?: string;
  original_line?: string;
  detection_method?: string;
  recommendation?: string;
  value?: string;
  detail?: string;
  context?: {
    ip_type?: string;
    appearances?: number;
    failed_login_count?: number;
    failed_logins?: number;
    error_count?: number;
    attack_lines?: number[];
    failed_login_lines?: number[];
    lines?: number[];
  };
}

export interface AnalyzeResponse {
  summary: string;
  content_type: string;
  findings: Finding[];
  risk_score: number;
  risk_level: RiskLevel;
  action: ActionTaken;
  insights: string[];
  anomalies?: string[];
  ai_used?: boolean;
  request_id?: string;
  duration_ms?: number;
  total_lines?: number;
  total_lines_analyzed?: number;
  detection_breakdown?: {
    regex?: number;
    statistical?: number;
    ml?: number;
    ai?: number;
  };
}

export interface AnalyzeOptions {
  mask: boolean;
  log_analysis: boolean;
  block_high_risk: boolean;
}

export interface LiveLogEntry {
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | "DEBUG" | string;
  message: string;
  method?: string;
  path?: string;
  status_code?: number;
  response_time_ms?: number;
  ip?: string;
  event?: string;
  source?: string;
  error?: string;
}

