export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  titleEn: string;
  detail: string;
  detailEn: string;
  fix: string;
  fixEn: string;
  category: string;
  tags: string[];
  attackIds: string[];
  effort: 'low' | 'medium' | 'high';
  riskOfFix: 'low' | 'medium' | 'high';
  fixed?: boolean;
  discoveredAt: string;
}

export interface UsbDevice {
  id: string;
  vendorId: string;
  productId: string;
  name: string;
  nameEn: string;
  deviceType: 'Storage' | 'HID' | 'Network' | 'Phone' | 'SmartCard' | 'Unknown';
  busNumber: string;
  authorized: boolean;
  mountPoint?: string;
  badUsbRisk: 'low' | 'medium' | 'high';
  heuristics: string[];
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'CRIT' | 'ACTION' | 'FIX';
  message: string;
  messageEn: string;
  category: string;
}

export interface PlaybookStep {
  stepId: number;
  title: string;
  titleEn: string;
  command: string;
  description: string;
  descriptionEn: string;
  completed: boolean;
  automated: boolean;
}

export interface Playbook {
  id: string;
  title: string;
  titleEn: string;
  description: string;
  descriptionEn: string;
  category: string;
  mitreRef: string;
  steps: PlaybookStep[];
}

export interface ThreatIntelItem {
  id: string;
  cveId: string;
  title: string;
  severity: Severity;
  cvss: number;
  affected: string;
  published: string;
  description: string;
  descriptionEn: string;
  exploitAvailable: boolean;
  pocSnippet?: string;
  mitreTactic: string;
}

export interface KnowledgeDoc {
  id: string;
  title: string;
  titleEn: string;
  category: string;
  standard: string; // e.g. 'CIS Benchmark', 'NIST SP 800-53', 'ISO 27001'
  summary: string;
  summaryEn: string;
  content: string;
  contentEn: string;
  tags: string[];
}

export interface SystemTelemetry {
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  activeSockets: number;
  openPorts: number[];
  securityScore: number;
  status: 'idle' | 'scanning' | 'remediating' | 'analyzing';
  lastAuditTime: string;
  hostname: string;
  kernelVersion: string;
  osRelease: string;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'agent' | 'system';
  text: string;
  textEn: string;
  timestamp: string;
  recommendedCommand?: string;
  relatedFindingId?: string;
}
