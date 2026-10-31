import { db } from '../models/db.js';
import { endpointDb } from '../db/endpointDb.js';
import { calculateOrganizationRisk } from './riskEngine.js';
import { wsHub } from '../ws/wsHub.js';
import { Incident, ResponseAction, RiskContributor } from '../types.js';

export interface FactorContribution {
  id: string;
  category: 'Authentication' | 'Identity' | 'Endpoint Security' | 'Data Security';
  points: number;
  explanation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface EndpointDetectionResult {
  detected: boolean;
  deviceId: string;
  orgId: string;
  hostname: string;
  userEmail: string;
  status: 'Healthy' | 'Suspicious' | 'Compromised';
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  summary: string;
  matchedRules: string[];
  factorContributions: FactorContribution[];
  incidentId: string;
  timestamp: string;
}

interface WindowEvent {
  eventType: string;
  details: string;
  severity: string;
  timestamp: number;
}

class EndpointDetectionEngine {
  // Sliding window of events per device (retained for 60 seconds)
  private deviceWindows = new Map<string, WindowEvent[]>();

  // In-memory cache of latest detection per device for Explainability Waterfall queries
  public latestDetections = new Map<string, EndpointDetectionResult>();

  public processEvent(
    deviceId: string,
    orgId: string,
    rawEvent: { event_type: string; details: string; severity: string; timestamp: string }
  ): EndpointDetectionResult | null {
    const now = Date.now();
    const eventTime = new Date(rawEvent.timestamp).getTime() || now;

    if (!this.deviceWindows.has(deviceId)) {
      this.deviceWindows.set(deviceId, []);
    }
    const window = this.deviceWindows.get(deviceId)!;

    // Append new event
    window.push({
      eventType: rawEvent.event_type,
      details: rawEvent.details,
      severity: rawEvent.severity,
      timestamp: eventTime
    });

    // Prune events outside 60s sliding window
    const windowStart = now - 60000;
    while (window.length > 0 && window[0].timestamp < windowStart) {
      window.shift();
    }

    // Evaluate Detection Rules
    const matchedRules: string[] = [];
    const factorContributions: FactorContribution[] = [];
    let confidenceSum = 0;
    let ruleCount = 0;

    // Rule 1: Rapid Credential Stuffing / Brute Force
    const failedLogins = window.filter((e) => e.eventType === 'FAILED_LOGIN');
    if (failedLogins.length >= 5) {
      matchedRules.push(`RULE-AUTH-01: Rapid Failed Logins Anomaly (${failedLogins.length} attempts in 60s window)`);
      factorContributions.push({
        id: 'fc-auth-1',
        category: 'Authentication',
        points: Math.min(30, 15 + failedLogins.length),
        explanation: `${failedLogins.length} repeated failed interactive authentications indicating credential stuffing.`,
        severity: 'HIGH'
      });
      confidenceSum += 88;
      ruleCount++;
    }

    // Rule 2: Infiltration (Failed Logins followed by Successful Login + New Device or Unusual Location)
    const hasSuccess = window.some((e) => e.eventType === 'SUCCESSFUL_LOGIN');
    const hasNewDeviceOrLocation = window.some((e) => e.eventType === 'NEW_DEVICE' || e.eventType === 'UNUSUAL_LOCATION');
    if (failedLogins.length >= 3 && hasSuccess && hasNewDeviceOrLocation) {
      matchedRules.push('RULE-IAM-02: Anomalous Infiltration & Unrecognized Hardware Fingerprint');
      factorContributions.push({
        id: 'fc-iam-2',
        category: 'Identity',
        points: 24,
        explanation: 'Successful logon from unrecognized device hardware hash & foreign IP following failed attempts.',
        severity: 'CRITICAL'
      });
      confidenceSum += 92;
      ruleCount++;
    }

    // Rule 3: Privilege Escalation & Suspicious Process Spawn
    const privEsc = window.find((e) => e.eventType === 'PRIVILEGE_ESCALATION');
    if (privEsc) {
      matchedRules.push('RULE-PROC-03: Unauthorized Privilege Escalation & Suspicious Child Process Spawn');
      factorContributions.push({
        id: 'fc-proc-3',
        category: 'Endpoint Security',
        points: 26,
        explanation: 'Elevated process token acquisition and SeDebugPrivilege assignment (demo_suspicious).',
        severity: 'CRITICAL'
      });
      confidenceSum += 96;
      ruleCount++;
    }

    // Rule 4: Anomalous Large Data Transfer (Exfiltration Stage)
    const exfil = window.find((e) => e.eventType === 'LARGE_DATA_TRANSFER' || e.eventType === 'DATA_EXFILTRATION');
    if (exfil) {
      matchedRules.push('RULE-DATA-04: High-Volume Outbound Data Egress Anomaly');
      factorContributions.push({
        id: 'fc-data-4',
        category: 'Data Security',
        points: 20,
        explanation: 'Unusual outbound encrypted HTTPS egress exceeding baseline threshold (4.8 GB).',
        severity: 'CRITICAL'
      });
      confidenceSum += 95;
      ruleCount++;
    }

    // If any high-confidence rules triggered, emit detection
    if (matchedRules.length === 0) {
      return null;
    }

    const device = endpointDb.getDeviceById(deviceId);
    const hostname = device?.hostname || deviceId;
    const userEmail = device?.user_email || 'assigned.user@demobank.com';
    const confidence = Math.round(confidenceSum / ruleCount);

    const isCritical = factorContributions.some((fc) => fc.severity === 'CRITICAL') || matchedRules.length >= 2;
    const status: 'Suspicious' | 'Compromised' = isCritical ? 'Compromised' : 'Suspicious';
    const severity: 'CRITICAL' | 'HIGH' = isCritical ? 'CRITICAL' : 'HIGH';

    // Deterministic Incident ID (No Math.random!)
    const cleanId = deviceId.toLowerCase().replace(/[^a-z0-9]/g, '');
    const incidentId = `inc-endpoint-${cleanId}`;

    const detectionResult: EndpointDetectionResult = {
      detected: true,
      deviceId,
      orgId,
      hostname,
      userEmail,
      status,
      confidence,
      severity,
      title: isCritical
        ? `ACCOUNT COMPROMISE & ELEVATED PRIVILEGE ON ${hostname}`
        : `SUSPICIOUS BEHAVIOR ANOMALIES ON ${hostname}`,
      summary: `Correlated ${matchedRules.length} threat detection rule(s) across recent 60-second sliding telemetry window.`,
      matchedRules,
      factorContributions,
      incidentId,
      timestamp: new Date().toISOString()
    };

    this.latestDetections.set(deviceId, detectionResult);

    // 1. Update Endpoint Status in DB
    const elevatedRisk = isCritical ? 92 : 72;
    endpointDb.updateDeviceStatus(deviceId, status, elevatedRisk);

    // 2. Recompute Organization Risk through riskEngine
    const org = db.organizations[orgId] || db.getActiveOrganization();
    org.riskBreakdown.authentication = Math.min(99, org.riskBreakdown.authentication + 12);
    org.riskBreakdown.endpointSecurity = Math.min(99, org.riskBreakdown.endpointSecurity + 22);
    if (exfil) {
      org.riskBreakdown.dataSecurity = Math.min(99, org.riskBreakdown.dataSecurity + 15);
    }
    org.riskTrend = 'RISING';

    const activeIncidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
    const newRisk = calculateOrganizationRisk(org, activeIncidents.length + 1);
    org.riskScore = newRisk.overallRiskScore;

    // 3. Create or Update Incident in SOC DB
    this.createOrUpdateIncident(detectionResult, org.id);

    // 4. Append to Audit Log
    endpointDb.appendAudit(
      'detectionEngine',
      orgId,
      'ENDPOINT_ATTACK_DETECTED',
      `Correlated attack detection on ${deviceId} (${status}, ${confidence}% confidence, ${matchedRules.length} rules matched). Device risk: ${elevatedRisk}, Org risk: ${org.riskScore}.`,
      deviceId
    );

    // 5. Real-Time Broadcast to Connected Admins
    wsHub.broadcastToAdmins(orgId, {
      type: 'ENDPOINT_ALERT',
      detection: detectionResult,
      device: {
        id: deviceId,
        hostname,
        status,
        risk: elevatedRisk
      },
      updatedOrgRisk: org.riskScore,
      timestamp: new Date().toISOString()
    });

    console.log(`🚨 [Detection Engine] Alert dispatched for ${deviceId}: ${detectionResult.title} (Confidence: ${confidence}%)`);
    return detectionResult;
  }

  private createOrUpdateIncident(detection: EndpointDetectionResult, orgId: string) {
    const existing = db.incidents.find((i) => i.id === detection.incidentId);

    const nowTimeStr = new Date().toTimeString().slice(0, 8);
    const timelineEntry = {
      id: `tl-${detection.deviceId.toLowerCase()}-${Date.now()}`,
      time: nowTimeStr,
      title: `Endpoint Threat Detected: ${detection.status.toUpperCase()}`,
      description: `${detection.summary} (${detection.matchedRules.join(' | ')})`,
      type: 'DETECTION' as const
    };

    if (existing) {
      existing.status = 'Detected';
      existing.severity = detection.severity;
      existing.confidence = detection.confidence;
      existing.riskScore = 92;
      existing.timeline.push(timelineEntry);
    } else {
      const newIncident: Incident = {
        id: detection.incidentId,
        incidentId: `INC-2026-${detection.deviceId.replace(/[^0-9]/g, '') || '9100'}`,
        orgId,
        title: detection.title,
        threatType: 'Endpoint Host Compromise & Lateral Movement',
        severity: detection.severity,
        status: 'Detected',
        detectionTime: new Date().toISOString().replace('T', ' ').slice(0, 19),
        affectedAsset: `${detection.hostname} (${detection.deviceId})`,
        confidence: detection.confidence,
        riskScore: 92,
        description: `Endpoint agent detected multi-stage kill chain: ${detection.matchedRules.join('; ')}`,
        timeline: [timelineEntry]
      };

      db.incidents.unshift(newIncident);

      // Create Associated Response Actions for Admin Console
      const responseActions: ResponseAction[] = [
        {
          id: `act-kill-${detection.deviceId.toLowerCase()}`,
          incidentId: newIncident.id,
          orgId,
          title: `Terminate Malicious Process on ${detection.hostname}`,
          priority: 'CRITICAL',
          reason: `Execute kill_process to terminate tracked unauthorized process "demo_suspicious".`,
          status: 'Pending',
          estimatedRiskReduction: 24,
          effort: 'Low',
          isQuickWin: true
        },
        {
          id: `act-logout-${detection.deviceId.toLowerCase()}`,
          incidentId: newIncident.id,
          orgId,
          title: `Force Invalidate User Sessions on ${detection.hostname}`,
          priority: 'HIGH',
          reason: `Execute force_logout to revoke all active authentication sessions for ${detection.userEmail}.`,
          status: 'Pending',
          estimatedRiskReduction: 18,
          effort: 'Low',
          isQuickWin: true
        },
        {
          id: `act-isolate-${detection.deviceId.toLowerCase()}`,
          incidentId: newIncident.id,
          orgId,
          title: `Isolate Workstation ${detection.hostname}`,
          priority: 'HIGH',
          reason: `Execute isolate_device to quarantine device in simulated mesh posture.`,
          status: 'Pending',
          estimatedRiskReduction: 16,
          effort: 'Medium',
          isQuickWin: false
        }
      ];

      for (const act of responseActions) {
        db.responseActions.unshift(act);
      }
    }
  }

  public getLatestDetection(deviceId: string): EndpointDetectionResult | undefined {
    return this.latestDetections.get(deviceId);
  }

  public resetBaseline() {
    this.deviceWindows.clear();
    this.latestDetections.clear();
  }
}

export const endpointDetectionEngine = new EndpointDetectionEngine();
