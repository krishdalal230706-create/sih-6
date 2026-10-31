import WebSocket from 'ws';
import { AgentConfig, AgentEvent, SignedCommand } from './types.js';
import { CommandExecutor } from './commandExecutor.js';

export class AgentClient {
  private config: AgentConfig;
  private ws: WebSocket | null = null;
  private isConnected: boolean = false;
  private reconnectTimeout: NodeJS.Timeout | null = null;
  private backoffMs: number = 1000;
  private maxBackoffMs: number = 10000;
  private heartbeatInterval: NodeJS.Timeout | null = null;

  private eventQueue: AgentEvent[] = [];
  private recentEventsBuffer: AgentEvent[] = [];
  public executor: CommandExecutor;

  constructor(config: AgentConfig) {
    this.config = config;
    this.executor = new CommandExecutor(config.commandSecret);
  }

  public connect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    const wsUrl = `${this.config.wsUrl}/ws/agent?deviceId=${encodeURIComponent(this.config.deviceId)}&token=${encodeURIComponent(this.config.token)}`;
    console.log(`🌐 [Agent Client] Connecting to CyberGuard SOC at ${this.config.wsUrl}...`);

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.on('open', () => {
        this.isConnected = true;
        this.backoffMs = 1000; // Reset backoff
        console.log(`✅ [Agent Client] Authenticated and connected to SOC mesh as ${this.config.deviceId} (${this.config.orgId})`);

        this.startHeartbeat();
        this.flushEventQueue();
      });

      this.ws.on('message', async (data) => {
        try {
          const msg = JSON.parse(data.toString());
          await this.handleSocMessage(msg);
        } catch (err: any) {
          console.error('⚠️ [Agent Client] Error parsing incoming message:', err.message);
        }
      });

      this.ws.on('close', (code, reason) => {
        this.isConnected = false;
        this.stopHeartbeat();
        console.warn(`🔌 [Agent Client] Connection closed (code: ${code}). Reconnecting in ${this.backoffMs / 1000}s...`);
        this.scheduleReconnect();
      });

      this.ws.on('error', (err: any) => {
        console.warn(`⚠️ [Agent Client] WebSocket error: ${err.message}`);
        this.ws?.close();
      });
    } catch (err: any) {
      console.error('❌ [Agent Client] Failed to establish socket:', err.message);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) return;
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      this.backoffMs = Math.min(this.backoffMs * 2, this.maxBackoffMs);
      this.connect();
    }, this.backoffMs);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'HEARTBEAT', timestamp: new Date().toISOString() }));
      }
    }, 15000);
  }

  private stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  public sendEvent(eventType: string, details: string, severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM') {
    const event: AgentEvent = {
      eventType,
      details,
      severity,
      timestamp: new Date().toISOString()
    };

    this.recentEventsBuffer.push(event);
    if (this.recentEventsBuffer.length > 50) this.recentEventsBuffer.shift();
    this.executor.updateEventsBuffer(this.recentEventsBuffer);

    if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'EVENT', event }));
      console.log(`📡 [Agent Telemetry] Dispatched [${severity}] ${eventType}: ${details}`);
    } else {
      console.log(`📦 [Agent Telemetry] Queued event while offline [${severity}] ${eventType}`);
      this.eventQueue.push(event);
    }
  }

  private flushEventQueue() {
    if (this.eventQueue.length === 0) return;
    console.log(`🚀 [Agent Client] Flushing ${this.eventQueue.length} buffered telemetry events to SOC...`);
    while (this.eventQueue.length > 0 && this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      const event = this.eventQueue.shift();
      if (event) {
        this.ws.send(JSON.stringify({ type: 'EVENT', event }));
      }
    }
  }

  private async handleSocMessage(msg: any) {
    switch (msg.type) {
      case 'CONNECTED':
        console.log(`🛡️ [SOC Welcome] ${msg.message}`);
        break;

      case 'HEARTBEAT_ACK':
        // Heartbeat acknowledged by server
        break;

      case 'COMMAND': {
        const cmd: SignedCommand = msg.command;
        console.log(`⚡ [Incoming Remediation Command] Received action "${cmd.action}" (ID: ${cmd.id}) from ${cmd.issuedBy}`);

        // Execute whitelisted command securely
        const execResult = await this.executor.executeCommand(cmd);

        // Transmit result back to server
        if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({
            type: 'COMMAND_RESULT',
            commandId: execResult.commandId,
            status: execResult.status,
            result: execResult.result,
            error: execResult.error,
            executionTimeMs: execResult.executionTimeMs,
            timestamp: execResult.timestamp
          }));
        }
        break;
      }

      default:
        console.log(`[Agent Client] Received message from SOC:`, msg);
    }
  }

  public disconnect() {
    this.stopHeartbeat();
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    if (this.ws) this.ws.close();
  }
}

