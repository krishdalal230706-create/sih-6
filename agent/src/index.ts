import readline from 'readline';
import { loadConfig, saveConfig } from './config.js';
import { AgentClient } from './client.js';
import { AgentConfig } from './types.js';

async function performEnrollment(backendUrl: string, codeInput?: string): Promise<AgentConfig | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const question = (query: string): Promise<string> => new Promise((resolve) => rl.question(query, resolve));

  console.log('\n📝 [Device Enrollment Wizard]');
  const enrollmentCode = codeInput || (await question('Enter Admin-Generated Enrollment Code: '));
  const hostname = (await question('Workstation Hostname (default: current): ')) || (process.env.COMPUTERNAME || 'MY-WORKSTATION');
  rl.close();

  console.log(`⏳ Contacting CyberGuard Server at ${backendUrl}/api/devices/enroll...`);
  try {
    const res = await fetch(`${backendUrl}/api/devices/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollmentCode: enrollmentCode.trim(),
        hostname: hostname.trim(),
        os: `${process.platform} (${process.arch})`
      })
    });

    const data = await res.json();
    if (!res.ok) {
      console.error(`❌ Enrollment Failed: ${data.message || 'Server rejected request'}`);
      return null;
    }

    const newConfig: AgentConfig = {
      backendUrl,
      wsUrl: backendUrl.replace(/^http/, 'ws'),
      orgId: data.orgId,
      deviceId: data.deviceId,
      token: data.token,
      commandSecret: data.commandSecret,
      hostname,
      os: `${process.platform} (${process.arch})`
    };

    saveConfig(newConfig);
    console.log(`✅ Successfully enrolled as ${data.deviceId} for organization ${data.orgId}!`);
    return newConfig;
  } catch (err: any) {
    console.error(`❌ Network error during enrollment: ${err.message}`);
    return null;
  }
}

function printConsentBanner(config: AgentConfig) {
  const line = '='.repeat(74);
  console.log(`\n${line}`);
  console.log(`🛡️  CYBERGUARD ENDPOINT AGENT (SIH PROTOTYPE - MODULE 8)`);
  console.log(`-`.repeat(74));
  console.log(`Status       : RUNNING • CONSENT-BASED • SANDBOXED`);
  console.log(`Monitored by : ${config.orgId.toUpperCase()} (Institutional SOC Defense Mesh)`);
  console.log(`Device ID    : ${config.deviceId} (${config.hostname})`);
  console.log(`OS Platform  : ${config.os}`);
  console.log(`Server URL   : ${config.backendUrl}`);
  console.log(`Safety Mode  : Whitelist Only (7 Actions) • Signed HMAC • Nonce Enforced`);
  console.log(`-`.repeat(74));
  console.log(`⚠️  USER NOTICE: This agent is running with full user consent.`);
  console.log(`   To stop monitoring at any time, press Ctrl+C in this terminal.`);
  console.log(`   This agent does NOT hide, tamper with system files, or auto-persist.`);
  console.log(`${line}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const isEnroll = args.includes('--enroll');
  let config = loadConfig();

  if (isEnroll) {
    const codeIndex = args.indexOf('--enroll') + 1;
    const code = args[codeIndex] && !args[codeIndex].startsWith('--') ? args[codeIndex] : undefined;
    const enrolledConfig = await performEnrollment(config.backendUrl, code);
    if (enrolledConfig) {
      config = enrolledConfig;
    } else {
      process.exit(1);
    }
  }

  printConsentBanner(config);

  const client = new AgentClient(config);
  client.connect();

  const shutdown = () => {
    console.log('\n🛑 [User Action] CyberGuard Agent stopped by user consent. Exiting cleanly.');
    client.disconnect();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('Fatal agent startup error:', err);
  process.exit(1);
});

