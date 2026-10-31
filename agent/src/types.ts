export type WhitelistedAction =
  | 'kill_process'
  | 'force_logout'
  | 'isolate_device'
  | 'release_isolation'
  | 'quarantine_file'
  | 'reset_credentials'
  | 'collect_diagnostics';

export interface AgentConfig {
  backendUrl: string;
  wsUrl: string;
  orgId: string;
  deviceId: string;
  token: string;
  commandSecret: string;
  hostname: string;
  os: string;
}

export interface AgentEvent {
  eventType: string;
  details: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
}

export interface SignedCommand {
  id: string;
  deviceId: string;
  action: WhitelistedAction;
  params: Record<string, any>;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  signature: string;
}

export interface CommandExecutionResult {
  commandId: string;
  status: 'Executed' | 'Failed' | 'Rejected';
  result?: any;
  error?: string;
  executionTimeMs: number;
  timestamp: string;
}

