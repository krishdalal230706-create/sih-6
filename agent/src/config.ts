import fs from 'fs';
import path from 'path';
import os from 'os';
import { AgentConfig } from './types.js';

const CONFIG_FILE = path.resolve(process.cwd(), 'agent.config.json');

export function loadConfig(): AgentConfig {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
      return JSON.parse(raw);
    } catch (e) {
      console.warn('⚠️ [Agent Config] Failed to parse agent.config.json, using prototype baseline.');
    }
  }

  // Prototype baseline default: Bank A Alice Walker workstation
  return {
    backendUrl: process.env.CYBERGUARD_BACKEND_URL || 'http://127.0.0.1:5000',
    wsUrl: process.env.CYBERGUARD_WS_URL || 'ws://127.0.0.1:5000',
    orgId: 'org-1',
    deviceId: 'DEV-BANK-01',
    token: 'devtoken-bank-01-prototype',
    commandSecret: 'secret-cmd-bank-dev-01-prototype',
    hostname: os.hostname() || 'ALICE-LAPTOP-W11',
    os: `${os.type()} ${os.release()} (${os.arch()})`
  };
}

export function saveConfig(config: AgentConfig) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
  console.log(`💾 [Agent Config] Configuration saved to ${CONFIG_FILE}`);
}

