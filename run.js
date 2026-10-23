const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const isWindows = process.platform === 'win32';
const npmCmd = isWindows ? 'npm.cmd' : 'npm';

console.clear();
console.log('\x1b[36m%s\x1b[0m', '=======================================================');
console.log('\x1b[36m%s\x1b[0m', '       ⚡ STARTING CYBERGUARD GRID PLATFORM ⚡        ');
console.log('\x1b[36m%s\x1b[0m', '=======================================================');

// 1. Verify dependencies exist in backend & frontend
const backendModules = path.join(__dirname, 'backend', 'node_modules');
const frontendModules = path.join(__dirname, 'frontend', 'node_modules');

if (!fs.existsSync(backendModules)) {
  console.log('\x1b[33m%s\x1b[0m', '📦 Installing backend dependencies...');
  try {
    execSync(`${npmCmd} install`, { cwd: path.join(__dirname, 'backend'), stdio: 'inherit' });
  } catch (err) {
    console.error('Failed to install backend dependencies:', err.message);
  }
}

if (!fs.existsSync(frontendModules)) {
  console.log('\x1b[33m%s\x1b[0m', '📦 Installing frontend dependencies...');
  try {
    execSync(`${npmCmd} install`, { cwd: path.join(__dirname, 'frontend'), stdio: 'inherit' });
  } catch (err) {
    console.error('Failed to install frontend dependencies:', err.message);
  }
}

// 2. Start Backend & Frontend processes
console.log('\x1b[32m%s\x1b[0m', '🚀 Launching Backend API on port 5000...');
const backendProcess = spawn(`${npmCmd} run dev`, {
  cwd: path.join(__dirname, 'backend'),
  shell: true,
  stdio: 'pipe'
});

console.log('\x1b[35m%s\x1b[0m', '🚀 Launching Frontend App on port 5173...');
const frontendProcess = spawn(`${npmCmd} run dev`, {
  cwd: path.join(__dirname, 'frontend'),
  shell: true,
  stdio: 'pipe'
});

let frontendReady = false;

function formatOutput(prefix, color, data) {
  const lines = data.toString().split('\n');
  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    console.log(`${color}${prefix}\x1b[0m ${line}`);
    
    if (!frontendReady && (trimmed.includes('5173') || trimmed.includes('ready in'))) {
      frontendReady = true;
      console.log('\n\x1b[32m%s\x1b[0m', '=======================================================');
      console.log('\x1b[32m%s\x1b[0m', '  ✅  CYBERGUARD GRID IS READY AND RUNNING!');
      console.log('\x1b[32m%s\x1b[0m', '  🌐  Frontend Web App:  http://localhost:5173');
      console.log('\x1b[32m%s\x1b[0m', '  🔌  Backend REST API:  http://localhost:5000/api/health');
      console.log('\x1b[32m%s\x1b[0m', '=======================================================');
      console.log('\x1b[90m%s\x1b[0m\n', '  Press Ctrl + C in this terminal to stop all servers.');
    }
  });
}

backendProcess.stdout.on('data', (data) => formatOutput('[BACKEND]', '\x1b[36m', data));
backendProcess.stderr.on('data', (data) => formatOutput('[BACKEND-ERR]', '\x1b[31m', data));

frontendProcess.stdout.on('data', (data) => formatOutput('[FRONTEND]', '\x1b[35m', data));
frontendProcess.stderr.on('data', (data) => formatOutput('[FRONTEND-ERR]', '\x1b[31m', data));

function killProcesses() {
  console.log('\n\x1b[33m%s\x1b[0m', '🛑 Stopping all servers...');
  if (isWindows) {
    if (backendProcess.pid) {
      try { execSync(`taskkill /pid ${backendProcess.pid} /T /F`, { stdio: 'ignore' }); } catch (e) {}
    }
    if (frontendProcess.pid) {
      try { execSync(`taskkill /pid ${frontendProcess.pid} /T /F`, { stdio: 'ignore' }); } catch (e) {}
    }
  } else {
    backendProcess.kill('SIGTERM');
    frontendProcess.kill('SIGTERM');
  }
  process.exit(0);
}

process.on('SIGINT', killProcesses);
process.on('SIGTERM', killProcesses);
process.on('exit', killProcesses);
