import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage, Server } from 'http';
import { parse as parseUrl } from 'url';
import { endpointDb, DeviceRecord } from '../db/endpointDb.js';
import { verifyUserToken, AuthUserPayload } from '../middleware/authMiddleware.js';
import { AUTH_CONFIG } from '../config/authConfig.js';
import { db } from '../models/db.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';

export interface UserConnection {
  userId: string;
  orgId: string;
  email: string;
  ws: WebSocket;
  isAlive: boolean;
}

export interface AgentConnection {
  deviceId: string;
  orgId: string;
  hostname: string;
  ws: WebSocket;
  isAlive: boolean;
  connectedAt: string;
}

export interface AdminConnection {
  userId: string;
  orgId: string;
  email: string;
  ws: WebSocket;
  isAlive: boolean;
}

class WebSocketHub {
  private wssAgent: WebSocketServer;
  private wssAdmin: WebSocketServer;
  private wssUser: WebSocketServer;

  private connectedAgents = new Map<string, AgentConnection>();
  private connectedAdmins = new Map<string, Set<AdminConnection>>();
  private connectedUsers = new Map<string, Set<UserConnection>>();

  // Event listener callback hook (e.g. for detection engine to analyze live events)
  private eventHandlers: Array<(deviceId: string, orgId: string, event: any) => void> = [];

  constructor() {
    this.wssAgent = new WebSocketServer({ noServer: true });
    this.wssAdmin = new WebSocketServer({ noServer: true });
    this.wssUser = new WebSocketServer({ noServer: true });

    this.setupAgentWss();
    this.setupAdminWss();
    this.setupUserWss();
    this.setupHeartbeatInterval();
  }

  public registerEventHandler(handler: (deviceId: string, orgId: string, event: any) => void) {
    this.eventHandlers.push(handler);
  }

  public attachToServer(server: Server) {
    server.on('upgrade', (req: IncomingMessage, socket, head) => {
      const parsed = parseUrl(req.url || '', true);
      const pathname = parsed.pathname;

      if (pathname === '/ws/agent') {
        if (!AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
          socket.write('HTTP/1.1 404 Not Found: Endpoint Agent Module Disabled\r\n\r\n');
          socket.destroy();
          return;
        }

        const deviceId = parsed.query.deviceId as string;
        const token = parsed.query.token as string;

        if (!deviceId || !token) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          return;
        }

        const isValid = endpointDb.verifyDeviceToken(deviceId, token);
        if (!isValid) {
          socket.write('HTTP/1.1 403 Forbidden: Invalid Device Credentials\r\n\r\n');
          socket.destroy();
          return;
        }

        const device = endpointDb.getDeviceById(deviceId);
        if (!device) {
          socket.write('HTTP/1.1 404 Not Found: Device Not Enrolled\r\n\r\n');
          socket.destroy();
          return;
        }

        this.wssAgent.handleUpgrade(req, socket, head, (ws) => {
          this.wssAgent.emit('connection', ws, req, device);
        });
      } else if (pathname === '/ws/admin') {
        const token = parsed.query.token as string;

        if (!token) {
          socket.write('HTTP/1.1 401 Unauthorized: Missing Token\r\n\r\n');
          socket.destroy();
          return;
        }

        const payload = verifyUserToken(token);
        if (!payload || payload.role !== 'admin') {
          socket.write('HTTP/1.1 403 Forbidden: Admin Privileges Required\r\n\r\n');
          socket.destroy();
          return;
        }

        this.wssAdmin.handleUpgrade(req, socket, head, (ws) => {
          this.wssAdmin.emit('connection', ws, req, payload);
        });
      } else if (pathname === '/ws/user') {
        const token = parsed.query.token as string;

        if (!token) {
          socket.write('HTTP/1.1 401 Unauthorized: Missing Token\r\n\r\n');
          socket.destroy();
          return;
        }

        const payload = verifyUserToken(token);
        if (!payload) {
          socket.write('HTTP/1.1 401 Unauthorized: Invalid Token\r\n\r\n');
          socket.destroy();
          return;
        }

        this.wssUser.handleUpgrade(req, socket, head, (ws) => {
          this.wssUser.emit('connection', ws, req, payload);
        });
      } else {
        // Unknown websocket endpoint
        socket.destroy();
      }
    });
  }

  private setupAgentWss() {
    this.wssAgent.on('connection', (ws: WebSocket, req: IncomingMessage, device: DeviceRecord) => {
      const connection: AgentConnection = {
        deviceId: device.id,
        orgId: device.org_id,
        hostname: device.hostname,
        ws,
        isAlive: true,
        connectedAt: new Date().toISOString()
      };

      this.connectedAgents.set(device.id, connection);

      // Update DB status if it was offline
      if (device.status === 'Offline') {
        endpointDb.updateDeviceStatus(device.id, 'Healthy');
      }
      endpointDb.updateDeviceHeartbeat(device.id);

      console.log(`🔌 [WS Agent] Device connected: ${device.id} (${device.hostname}) for org ${device.org_id}`);

      // Broadcast to admins of this org
      this.broadcastToAdmins(device.org_id, {
        type: 'DEVICE_CONNECTED',
        deviceId: device.id,
        hostname: device.hostname,
        status: device.status === 'Offline' ? 'Healthy' : device.status,
        timestamp: new Date().toISOString()
      });

      // Send initial welcome & pending commands if any
      ws.send(JSON.stringify({
        type: 'CONNECTED',
        deviceId: device.id,
        orgId: device.org_id,
        message: `Connected to CyberGuard SOC (${device.org_id})`,
        serverTime: new Date().toISOString()
      }));

      // Deliver pending commands
      const pending = endpointDb.getPendingCommandsForDevice(device.id);
      for (const cmd of pending) {
        if (new Date(cmd.expires_at).getTime() > Date.now()) {
          ws.send(JSON.stringify({
            type: 'COMMAND',
            command: {
              id: cmd.id,
              deviceId: cmd.device_id,
              action: cmd.action,
              params: JSON.parse(cmd.params),
              issuedBy: cmd.issued_by,
              issuedAt: cmd.issued_at,
              expiresAt: cmd.expires_at,
              nonce: cmd.nonce,
              signature: cmd.signature
            }
          }));
          endpointDb.updateCommandStatus(cmd.id, 'Sent');
        } else {
          endpointDb.updateCommandStatus(cmd.id, 'Failed', 'Command expired in queue');
        }
      }

      ws.on('pong', () => {
        connection.isAlive = true;
      });

      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          this.handleAgentMessage(connection, msg);
        } catch (err: any) {
          console.error(`[WS Agent] Bad message from ${device.id}:`, err.message);
        }
      });

      ws.on('close', () => {
        console.log(`🔌 [WS Agent] Device disconnected: ${device.id}`);
        this.connectedAgents.delete(device.id);
        endpointDb.updateDeviceStatus(device.id, 'Offline');

        this.broadcastToAdmins(device.org_id, {
          type: 'DEVICE_OFFLINE',
          deviceId: device.id,
          timestamp: new Date().toISOString()
        });
      });
    });
  }

  private handleAgentMessage(conn: AgentConnection, msg: any) {
    switch (msg.type) {
      case 'HEARTBEAT':
        endpointDb.updateDeviceHeartbeat(conn.deviceId);
        conn.ws.send(JSON.stringify({ type: 'HEARTBEAT_ACK', timestamp: new Date().toISOString() }));
        break;

      case 'EVENT': {
        const evt = {
          id: `evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          device_id: conn.deviceId,
          event_type: msg.event?.eventType || 'INFO',
          details: msg.event?.details || 'Generic agent event',
          severity: msg.event?.severity || 'LOW',
          timestamp: msg.event?.timestamp || new Date().toISOString()
        };

        endpointDb.recordDeviceEvent(evt);
        endpointDb.updateDeviceHeartbeat(conn.deviceId);

        // Notify admins in real-time
        this.broadcastToAdmins(conn.orgId, {
          type: 'DEVICE_EVENT',
          deviceId: conn.deviceId,
          event: evt
        });

        // Trigger detection engine hook
        for (const handler of this.eventHandlers) {
          handler(conn.deviceId, conn.orgId, evt);
        }
        break;
      }

      case 'COMMAND_RESULT': {
        const { commandId, status, result, error } = msg;
        const resultString = JSON.stringify({ result, error });
        endpointDb.updateCommandStatus(commandId, status, resultString);

        endpointDb.appendAudit(
          `agent:${conn.deviceId}`,
          conn.orgId,
          `COMMAND_RESULT_${status.toUpperCase()}`,
          `Command ${commandId} execution completed with status ${status}: ${resultString}`,
          conn.deviceId
        );

        const cmd = endpointDb.getCommandById(commandId);
        let updatedDeviceStatus: string | null = null;
        let updatedDeviceRisk: number | null = null;
        let updatedOrgRisk: number | null = null;

        if (status === 'Executed' && cmd) {
          const device = endpointDb.getDeviceById(conn.deviceId);

          if (cmd.action === 'isolate_device') {
            updatedDeviceStatus = 'Isolated';
            updatedDeviceRisk = 30;
            endpointDb.updateDeviceStatus(conn.deviceId, 'Isolated', 30);
          } else if (cmd.action === 'release_isolation') {
            updatedDeviceStatus = 'Healthy';
            updatedDeviceRisk = 15;
            endpointDb.updateDeviceStatus(conn.deviceId, 'Healthy', 15);
          } else if (cmd.action === 'kill_process' || cmd.action === 'quarantine_file') {
            updatedDeviceStatus = 'Remediated';
            updatedDeviceRisk = 20;
            endpointDb.updateDeviceStatus(conn.deviceId, 'Remediated', 20);
          } else if (cmd.action === 'force_logout') {
            updatedDeviceStatus = 'Remediated';
            updatedDeviceRisk = 20;
            endpointDb.updateDeviceStatus(conn.deviceId, 'Remediated', 20);
            if (device) {
              endpointDb.revokeAllUserSessions(device.user_id);
            }
          } else if (cmd.action === 'reset_credentials') {
            if (device) {
              endpointDb.updateUserMustReset(device.user_id, true);
            }
          }

          // Recalculate Organization Risk via riskEngine
          const org = db.organizations[conn.orgId] || db.getActiveOrganization();
          if (org) {
            org.riskBreakdown.authentication = Math.max(10, org.riskBreakdown.authentication - 15);
            org.riskBreakdown.endpointSecurity = Math.max(10, org.riskBreakdown.endpointSecurity - 15);
            org.riskTrend = 'FALLING';

            // Mark associated incidents as Contained
            const relatedIncidents = db.incidents.filter((i) =>
              i.orgId === org.id && (i.affectedAsset?.includes(conn.deviceId) || i.id?.includes(conn.deviceId.toLowerCase().replace(/[^a-z0-9]/g, '')))
            );
            for (const inc of relatedIncidents) {
              inc.status = 'Contained';
              inc.timeline.push({
                id: `tl-rem-${Date.now()}`,
                time: new Date().toTimeString().slice(0, 8),
                title: `Remediation Executed: ${cmd.action}`,
                description: `Admin executed remote remediation action ${cmd.action} on ${conn.deviceId}. Threat neutralized.`,
                type: 'RESPONSE'
              });
            }

            const activeIncidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
            const newRisk = calculateOrganizationRisk(org, activeIncidents.length);
            org.riskScore = newRisk.overallRiskScore;
            updatedOrgRisk = org.riskScore;
          }
        }

        // Notify admins of command status shift and potential risk drop
        this.broadcastToAdmins(conn.orgId, {
          type: 'COMMAND_UPDATED',
          commandId,
          deviceId: conn.deviceId,
          status,
          result,
          error,
          updatedDeviceStatus,
          updatedDeviceRisk,
          updatedOrgRisk,
          timestamp: new Date().toISOString()
        });
        break;
      }

      default:
        console.log(`[WS Agent] Unknown message type from ${conn.deviceId}:`, msg.type);
    }
  }

  private setupAdminWss() {
    this.wssAdmin.on('connection', (ws: WebSocket, req: IncomingMessage, user: AuthUserPayload) => {
      const adminConn: AdminConnection = {
        userId: user.userId,
        orgId: user.orgId,
        email: user.email,
        ws,
        isAlive: true
      };

      if (!this.connectedAdmins.has(user.orgId)) {
        this.connectedAdmins.set(user.orgId, new Set());
      }
      this.connectedAdmins.get(user.orgId)!.add(adminConn);

      console.log(`🖥️ [WS Admin] Admin connected: ${user.email} for org ${user.orgId}`);

      ws.send(JSON.stringify({
        type: 'ADMIN_CONNECTED',
        orgId: user.orgId,
        user: user.name,
        onlineAgentsCount: this.getOnlineAgentsForOrg(user.orgId).length,
        timestamp: new Date().toISOString()
      }));

      ws.on('pong', () => {
        adminConn.isAlive = true;
      });

      ws.on('close', () => {
        console.log(`🖥️ [WS Admin] Admin disconnected: ${user.email}`);
        const orgAdmins = this.connectedAdmins.get(user.orgId);
        if (orgAdmins) {
          orgAdmins.delete(adminConn);
          if (orgAdmins.size === 0) {
            this.connectedAdmins.delete(user.orgId);
          }
        }
      });
    });
  }

  private setupUserWss() {
    this.wssUser.on('connection', (ws: WebSocket, req: IncomingMessage, user: AuthUserPayload) => {
      const userConn: UserConnection = {
        userId: user.userId,
        orgId: user.orgId,
        email: user.email,
        ws,
        isAlive: true
      };

      if (!this.connectedUsers.has(user.userId)) {
        this.connectedUsers.set(user.userId, new Set());
      }
      this.connectedUsers.get(user.userId)!.add(userConn);

      console.log(`👤 [WS User] User connected: ${user.email} (${user.userId}) for org ${user.orgId}`);

      ws.send(JSON.stringify({
        type: 'USER_CONNECTED',
        userId: user.userId,
        orgId: user.orgId,
        email: user.email,
        timestamp: new Date().toISOString()
      }));

      ws.on('pong', () => {
        userConn.isAlive = true;
      });

      ws.on('close', () => {
        console.log(`👤 [WS User] User disconnected: ${user.email}`);
        const userSet = this.connectedUsers.get(user.userId);
        if (userSet) {
          userSet.delete(userConn);
          if (userSet.size === 0) {
            this.connectedUsers.delete(user.userId);
          }
        }
      });
    });
  }

  private setupHeartbeatInterval() {
    const interval = setInterval(() => {
      // Check agent heartbeats
      for (const [deviceId, conn] of this.connectedAgents.entries()) {
        if (!conn.isAlive) {
          console.log(`⚠️ [WS Agent] Heartbeat timed out for device ${deviceId}. Terminating.`);
          conn.ws.terminate();
          this.connectedAgents.delete(deviceId);
          endpointDb.updateDeviceStatus(deviceId, 'Offline');
          this.broadcastToAdmins(conn.orgId, {
            type: 'DEVICE_OFFLINE',
            deviceId,
            timestamp: new Date().toISOString()
          });
        } else {
          conn.isAlive = false;
          conn.ws.ping();
        }
      }

      // Check admin heartbeats
      for (const [orgId, adminSet] of this.connectedAdmins.entries()) {
        for (const admin of adminSet) {
          if (!admin.isAlive) {
            admin.ws.terminate();
            adminSet.delete(admin);
          } else {
            admin.isAlive = false;
            admin.ws.ping();
          }
        }
      }

      // Check user heartbeats
      for (const [userId, userSet] of this.connectedUsers.entries()) {
        for (const user of userSet) {
          if (!user.isAlive) {
            user.ws.terminate();
            userSet.delete(user);
          } else {
            user.isAlive = false;
            user.ws.ping();
          }
        }
      }
    }, 15000);

    if (interval.unref) {
      interval.unref();
    }
  }

  public broadcastToUser(userId: string, message: any) {
    const userSet = this.connectedUsers.get(userId);
    if (!userSet) return;
    const payload = JSON.stringify(message);
    for (const user of userSet) {
      if (user.ws.readyState === WebSocket.OPEN) {
        user.ws.send(payload);
      }
    }
  }

  public broadcastToOrgUsers(orgId: string, message: any) {
    const payload = JSON.stringify(message);
    for (const userSet of this.connectedUsers.values()) {
      for (const user of userSet) {
        if (user.orgId === orgId && user.ws.readyState === WebSocket.OPEN) {
          user.ws.send(payload);
        }
      }
    }
  }

  public sendToAgent(deviceId: string, message: any): boolean {
    const conn = this.connectedAgents.get(deviceId);
    if (!conn || conn.ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    conn.ws.send(JSON.stringify(message));
    return true;
  }

  public broadcastToAdmins(orgId: string, message: any) {
    const adminSet = this.connectedAdmins.get(orgId);
    if (!adminSet) return;

    const payload = JSON.stringify(message);
    for (const admin of adminSet) {
      if (admin.ws.readyState === WebSocket.OPEN) {
        admin.ws.send(payload);
      }
    }
  }

  public isAgentOnline(deviceId: string): boolean {
    const conn = this.connectedAgents.get(deviceId);
    return Boolean(conn && conn.ws.readyState === WebSocket.OPEN);
  }

  public getOnlineAgentsForOrg(orgId: string): string[] {
    const list: string[] = [];
    for (const [id, conn] of this.connectedAgents.entries()) {
      if (conn.orgId === orgId && conn.ws.readyState === WebSocket.OPEN) {
        list.push(id);
      }
    }
    return list;
  }
}

export const wsHub = new WebSocketHub();

// Automatically wire detection pipeline to live agent events
import { endpointDetectionEngine } from '../engine/endpointDetectionEngine.js';
wsHub.registerEventHandler((deviceId, orgId, event) => {
  endpointDetectionEngine.processEvent(deviceId, orgId, event);
});


