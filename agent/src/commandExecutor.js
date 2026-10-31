import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
export function computeCommandSignature(secret, commandId, deviceId, action, params, issuedBy, issuedAt, expiresAt, nonce) {
    // Canonical serialization for deterministic signing
    const sortedParams = JSON.stringify(params, Object.keys(params).sort());
    const payload = `${commandId}|${deviceId}|${action}|${sortedParams}|${issuedBy}|${issuedAt}|${expiresAt}|${nonce}`;
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}
export class CommandExecutor {
    commandSecret;
    usedNonces = new Set();
    trackedProcesses = new Map();
    isIsolated = false;
    sandboxDir;
    quarantineDir;
    recentEventsBuffer = [];
    constructor(commandSecret) {
        this.commandSecret = commandSecret;
        // Initialize sandbox directories
        this.sandboxDir = path.resolve(process.cwd(), 'sandbox');
        this.quarantineDir = path.resolve(this.sandboxDir, 'quarantine');
        if (!fs.existsSync(this.quarantineDir)) {
            fs.mkdirSync(this.quarantineDir, { recursive: true });
        }
    }
    setCommandSecret(secret) {
        this.commandSecret = secret;
    }
    updateEventsBuffer(events) {
        this.recentEventsBuffer = events;
    }
    trackProcess(name, pid, killFn) {
        this.trackedProcesses.set(name, { pid, name, kill: killFn });
        console.log(`🔎 [Agent Process Tracker] Registered harmless tracked process: "${name}" (PID: ${pid})`);
    }
    getIsIsolated() {
        return this.isIsolated;
    }
    async executeCommand(cmd) {
        const startMs = Date.now();
        // 1. Replay Attack Protection: Check Nonce
        if (this.usedNonces.has(cmd.nonce)) {
            console.warn(`🚨 [SECURITY ALERT] Replay attack rejected: Nonce ${cmd.nonce} has already been used.`);
            return {
                commandId: cmd.id,
                status: 'Rejected',
                error: `REPLAY_ATTACK_REJECTED: Nonce ${cmd.nonce} was already consumed.`,
                executionTimeMs: Date.now() - startMs,
                timestamp: new Date().toISOString()
            };
        }
        // 2. Expiry Check
        const expiryTime = new Date(cmd.expiresAt).getTime();
        if (Date.now() > expiryTime) {
            console.warn(`🚨 [SECURITY ALERT] Expired command rejected: Command ${cmd.id} expired at ${cmd.expiresAt}`);
            return {
                commandId: cmd.id,
                status: 'Rejected',
                error: `EXPIRED_COMMAND: Command expired at ${cmd.expiresAt}. Current time: ${new Date().toISOString()}`,
                executionTimeMs: Date.now() - startMs,
                timestamp: new Date().toISOString()
            };
        }
        // 3. Cryptographic HMAC Signature Verification
        const expectedSig = computeCommandSignature(this.commandSecret, cmd.id, cmd.deviceId, cmd.action, cmd.params, cmd.issuedBy, cmd.issuedAt, cmd.expiresAt, cmd.nonce);
        if (cmd.signature !== expectedSig) {
            console.error(`🚨 [SECURITY ALERT] Signature mismatch on command ${cmd.id}! Potential forgery attempt.`);
            return {
                commandId: cmd.id,
                status: 'Rejected',
                error: 'INVALID_SIGNATURE: HMAC-SHA256 signature verification failed. Command secret mismatch.',
                executionTimeMs: Date.now() - startMs,
                timestamp: new Date().toISOString()
            };
        }
        // Mark nonce as used
        this.usedNonces.add(cmd.nonce);
        // 4. Whitelist Only Enforcement
        try {
            let executionOutput = null;
            switch (cmd.action) {
                case 'kill_process': {
                    const targetName = cmd.params.processName || 'demo_suspicious';
                    if (targetName !== 'demo_suspicious') {
                        throw new Error(`SECURITY_VIOLATION: Whitelist restricts kill_process strictly to the tracked agent process "demo_suspicious". Arbitrary process execution is blocked.`);
                    }
                    const tracked = this.trackedProcesses.get(targetName);
                    if (tracked) {
                        tracked.kill();
                        this.trackedProcesses.delete(targetName);
                        executionOutput = {
                            killedProcess: targetName,
                            pid: tracked.pid,
                            message: `Harmless process "${targetName}" (PID: ${tracked.pid}) terminated successfully.`
                        };
                        console.log(`🛑 [Agent Remediation] Terminated tracked process: ${targetName} (PID: ${tracked.pid})`);
                    }
                    else {
                        executionOutput = {
                            killedProcess: targetName,
                            message: `Harmless process "${targetName}" was not actively running or already stopped.`
                        };
                    }
                    break;
                }
                case 'force_logout': {
                    executionOutput = {
                        action: 'force_logout',
                        clearedSessionsCount: 1,
                        message: 'User session tokens invalidated. Workstation session state cleared.'
                    };
                    console.log(`🔒 [Agent Remediation] force_logout executed for active user session.`);
                    break;
                }
                case 'isolate_device': {
                    this.isIsolated = true;
                    executionOutput = {
                        action: 'isolate_device',
                        status: 'ISOLATED',
                        simulated: true,
                        message: 'Workstation marked ISOLATED in security mesh. External network traffic simulated as dropped.'
                    };
                    console.log(`🛡️ [Agent Remediation] Device isolated in simulated mesh posture.`);
                    break;
                }
                case 'release_isolation': {
                    this.isIsolated = false;
                    executionOutput = {
                        action: 'release_isolation',
                        status: 'HEALTHY',
                        simulated: true,
                        message: 'Workstation isolation lifted. Normal network connectivity restored.'
                    };
                    console.log(`🛡️ [Agent Remediation] Isolation released.`);
                    break;
                }
                case 'quarantine_file': {
                    const filename = cmd.params.filename;
                    if (!filename || typeof filename !== 'string') {
                        throw new Error('INVALID_PARAMS: filename string parameter required.');
                    }
                    // Path Traversal Prevention
                    const normalizedPath = path.normalize(filename);
                    if (normalizedPath.includes('..') || path.isAbsolute(normalizedPath)) {
                        throw new Error(`PATH_TRAVERSAL_BLOCKED: File path must stay strictly inside agent sandbox.`);
                    }
                    const targetFile = path.resolve(this.sandboxDir, normalizedPath);
                    if (!targetFile.startsWith(this.sandboxDir)) {
                        throw new Error(`PATH_TRAVERSAL_BLOCKED: Attempt to escape sandbox boundary.`);
                    }
                    // If file does not exist in sandbox, create a harmless test file for demonstration
                    if (!fs.existsSync(targetFile)) {
                        fs.writeFileSync(targetFile, 'HARMLOWS_SIMULATED_SUSPICIOUS_PAYLOAD_FOR_DEMO', 'utf-8');
                    }
                    const destFile = path.resolve(this.quarantineDir, path.basename(targetFile));
                    fs.renameSync(targetFile, destFile);
                    executionOutput = {
                        action: 'quarantine_file',
                        originalPath: `sandbox/${path.basename(targetFile)}`,
                        quarantinePath: `sandbox/quarantine/${path.basename(targetFile)}`,
                        message: `File moved safely into quarantine vault inside sandbox.`
                    };
                    console.log(`📦 [Agent Remediation] Quarantined file: ${path.basename(targetFile)}`);
                    break;
                }
                case 'reset_credentials': {
                    executionOutput = {
                        action: 'reset_credentials',
                        mustResetRequired: true,
                        message: 'Workstation marked for mandatory password reset. User will be forced to change credentials upon next login.'
                    };
                    console.log(`🔑 [Agent Remediation] Flagged user credentials for mandatory reset.`);
                    break;
                }
                case 'collect_diagnostics': {
                    executionOutput = {
                        action: 'collect_diagnostics',
                        eventsCount: this.recentEventsBuffer.length,
                        events: this.recentEventsBuffer.slice(-15),
                        isolationStatus: this.isIsolated ? 'ISOLATED' : 'ACTIVE',
                        timestamp: new Date().toISOString()
                    };
                    console.log(`📊 [Agent Remediation] Returned agent diagnostic telemetry buffer (${this.recentEventsBuffer.length} events).`);
                    break;
                }
                default:
                    throw new Error(`UNAUTHORIZED_COMMAND: Action "${cmd.action}" is not in the strict CyberGuard whitelist.`);
            }
            return {
                commandId: cmd.id,
                status: 'Executed',
                result: executionOutput,
                executionTimeMs: Date.now() - startMs,
                timestamp: new Date().toISOString()
            };
        }
        catch (err) {
            console.error(`❌ [Agent Command Error] ${err.message}`);
            return {
                commandId: cmd.id,
                status: 'Failed',
                error: err.message,
                executionTimeMs: Date.now() - startMs,
                timestamp: new Date().toISOString()
            };
        }
    }
}
