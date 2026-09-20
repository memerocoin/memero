// Memero Desktop Wallet — Electron main process
//
// Spawns the non-custodial memero-wallet-rpc backend (keys stay on the
// user's machine) and opens a window serving the wallet UI, which talks
// to the local backend over localhost JSON-RPC.

const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const RPC_PORT = 18082;
let walletRpcProcess = null;

// Resolve the memero-wallet-rpc binary: prefer a bundled copy next to the
// app, then fall back to PATH.
function findWalletRpcBinary() {
  const candidates = [
    path.join(process.resourcesPath, 'bin', process.platform === 'win32' ? 'memero-wallet-rpc.exe' : 'memero-wallet-rpc'),
    path.join(__dirname, 'bin', process.platform === 'win32' ? 'memero-wallet-rpc.exe' : 'memero-wallet-rpc'),
    'memero-wallet-rpc',
  ];
  for (const c of candidates) {
    if (c === 'memero-wallet-rpc') return c; // rely on PATH
    if (fs.existsSync(c)) return c;
  }
  return 'memero-wallet-rpc';
}

function startWalletRpc(daemonAddr, dataDir) {
  const bin = findWalletRpcBinary();
  const args = [
    '--rpc-bind-ip', '127.0.0.1',
    '--rpc-bind-port', String(RPC_PORT),
    '--daemon-address', daemonAddr,
  ];
  walletRpcProcess = spawn(bin, args, { stdio: 'ignore' });
  walletRpcProcess.on('error', (err) => {
    dialog.showErrorBox('Wallet backend failed to start',
      `Could not launch ${bin}.\n` +
      'Build memero-wallet-rpc and place it on your PATH, or in a "bin/" folder next to the app.\n\n' + err.message);
  });
  walletRpcProcess.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      dialog.showErrorBox('Wallet backend stopped', `memero-wallet-rpc exited with code ${code}.`);
    }
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 720,
    backgroundColor: '#000000',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(__dirname, 'wallet.html'));
}

app.whenReady().then(() => {
  // Defaults: connect to the public seed node, or a daemon passed via env.
  const daemonAddr = process.env.MEMERO_DAEMON || '127.0.0.1:50709';
  startWalletRpc(daemonAddr);
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('quit', () => {
  if (walletRpcProcess) walletRpcProcess.kill();
});
