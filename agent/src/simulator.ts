import { spawn } from 'child_process';
import { loadConfig } from './config.js';
import WebSocket from 'ws';

async function runSimulator() {
  const line = '='.repeat(74);
  console.log(`\n${line}`);
  console.log(`🧪 CYBERGUARD ATTACK SIMULATOR (DEMO MODE ONLY)`);
  console.log(`-`.repeat(74));
  console.log(`LAB PROTOTYPE: ALL ATTACK TELEMETRY IS SYNTHETIC & HARMLESS.`);
  console.log(`NO REAL MALWARE • NO PERSISTENCE • LAB EVALUATION ONLY`);
  console.log(`${line}\n`);

  const config = loadConfig();

  // 1. Spawn harmless idle loop process "demo_suspicious"
  console.log('🚀 [Simulator Step 1] Spawning harmless idle loop process titled "demo_suspicious"...');
  const harmlessProc = spawn(process.execPath, ['-e', 'process.title = "demo_suspicious"; setInterval(() => {}, 20000);'], {
    detached: false,
    stdio: 'ignore'
  });

  console.log(`✅ Harmless demo process running (PID: ${harmlessProc.pid}). Agent tracking registered.`);

  // 2. Connect over WebSocket to inject the deterministic telemetry sequence
  console.log(`📡 [Simulator Step 2] Connecting to SOC at ${config.wsUrl}/ws/agent to emit telemetry sequence...`);
  const wsUrl = `${config.wsUrl}/ws/agent?deviceId=${encodeURIComponent(config.deviceId)}&token=${encodeURIComponent(config.token)}`;
  const ws = new WebSocket(wsUrl);

  await new Promise<void>((resolve, reject) => {
    ws.on('open', () => {
      console.log('✅ Connected to SOC agent stream.');
      resolve();
    });
    ws.on('error', reject);
  });

  const sendEvent = (eventType: string, details: string, severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM') => {
    const payload = {
      type: 'EVENT',
      event: {
        eventType,
        details,
        severity,
        timestamp: new Date().toISOString()
      }
    };
    ws.send(JSON.stringify(payload));
    console.log(`   ⚡ [Emitted ${severity}] ${eventType}: ${details}`);
  };

  // Deterministic sequence:
  // 15 failed logins in 30 seconds
  console.log('\n▶ Emitting 15 consecutive failed logins (credential stuffing pattern)...');
  for (let i = 1; i <= 15; i++) {
    sendEvent('FAILED_LOGIN', `Failed interactive logon attempt #${i} from IP 198.51.100.42 (bad password hash).`, 'MEDIUM');
    await new Promise((r) => setTimeout(r, 100));
  }

  await new Promise((r) => setTimeout(r, 400));
  console.log('\n▶ Emitting anomalous successful login from new device/location...');
  sendEvent('SUCCESSFUL_LOGIN', 'Interactive logon succeeded for user after 15 failed attempts.', 'LOW');
  sendEvent('NEW_DEVICE', 'Unrecognized hardware fingerprint DEV-UNKNOWN-889 detected on corporate VPN.', 'HIGH');
  sendEvent('UNUSUAL_LOCATION', 'GeoIP anomaly: Login origin Frankfurt, Germany (Distance deviation: 6,400 km).', 'HIGH');

  await new Promise((r) => setTimeout(r, 400));
  console.log('\n▶ Emitting privilege escalation and exfiltration indicators...');
  sendEvent('PRIVILEGE_ESCALATION', `Unauthorized privilege elevation: Process spawned with SeDebugPrivilege (demo_suspicious, PID: ${harmlessProc.pid}).`, 'CRITICAL');
  sendEvent('LARGE_DATA_TRANSFER', 'Anomalous outbound HTTPS transfer: 4.8 GB transmitted to unknown external IP.', 'CRITICAL');

  console.log('\n' + '-'.repeat(74));
  console.log('✅ SIMULATION COMPLETE: All 20 synthetic telemetry events emitted to SOC.');
  console.log('👀 Inspect the SOC Admin Console or My Device page to see live detection!');
  console.log('-'.repeat(74) + '\n');

  // Keep simulator open for a few seconds then close socket, leaving process running for admin to test kill_process
  setTimeout(() => {
    ws.close();
    console.log('Simulator detached. Harmless background process will exit when killed by admin or on terminal exit.');
  }, 3000);
}

runSimulator().catch((err) => {
  console.error('Simulator error:', err);
  process.exit(1);
});

