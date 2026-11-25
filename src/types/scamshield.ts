export type PageRoute = 'home' | 'scanner' | 'dashboard' | 'how-it-works' | 'about';

export type RiskLevel = 'LOW' | 'SUSPICIOUS' | 'HIGH';

export type PredictionLabel = 'LEGITIMATE' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS';

export type ApiMode = 'integrated' | 'fastapi';

export interface LexicalFeatures {
  url_length: number;
  hostname_length: number;
  dot_count: number;
  hyphen_count: number;
  has_ip_address: boolean;
  has_https: boolean;
  subdomain_count: number;
  suspicious_keyword_count: number;
  has_punycode: boolean;
  is_shortener: boolean;
}

export interface IndicatorDetail {
  label: string;
  severity: 'info' | 'warning' | 'danger';
  explanation: string;
}

export interface SslAnalysis {
  protocol: 'HTTPS' | 'HTTP';
  status_label: string;
  summary: string;
}

export interface DomainAgeAnalysis {
  hostname_type: 'Registered Domain' | 'Raw IP Address' | 'Punycode / IDN' | 'URL Shortener';
  risk_assessment: string;
  summary: string;
}

export type ThreatCategoryId =
  | 'domain_spoofing'
  | 'ssl_https'
  | 'suspicious_keywords'
  | 'redirect_risk';

export type ThreatCategorySeverity = 'safe' | 'warning' | 'danger';

export interface ThreatBreakdownCard {
  id: ThreatCategoryId;
  title: 'Domain Spoofing' | 'SSL/HTTPS Check' | 'Suspicious Keywords' | 'Redirect Risk';
  severity: ThreatCategorySeverity;
  status_label: string;
  metric_value: string;
  summary: string;
}

export interface ScanResponse {
  url: string;
  normalized_hostname: string;
  risk_score: number;
  risk_level: RiskLevel;
  prediction: PredictionLabel;
  phishing_probability: number;
  indicators: string[];
  indicator_details?: IndicatorDetail[];
  recommendation: string;
  ssl_analysis?: SslAnalysis;
  domain_age_analysis?: DomainAgeAnalysis;
  threat_breakdown?: ThreatBreakdownCard[];
  features?: LexicalFeatures;
  matched_keywords?: string[];
  analysis_scope_note?: string;
  engine?: string;
  fallback_used?: boolean;
  fallback_reason?: string;
  scanned_at?: string;
  latency_ms?: number;
}

export interface ScanHistoryItem extends ScanResponse {
  id: string;
  scanned_at: string;
  is_demo?: boolean;
}

export interface ModelInfoResponse {
  model_name: string;
  algorithm: string;
  dataset: string;
  training_samples: number;
  features: string[];
  thresholds: {
    low: string;
    suspicious: string;
    high: string;
  };
  limitations: string;
  status: string;
}

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl: string;
  error?: string;
}
