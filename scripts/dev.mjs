// Cross-platform dev loop (works in Windows cmd/PowerShell): initial build, then tsc --watch + node --watch.
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const tsc = require.resolve('typescript/bin/tsc');
const first = spawnSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], { stdio: 'inherit' });
if (first.status !== 0) process.exit(first.status ?? 1);
const watcher = spawn(process.execPath, [tsc, '-p', 'tsconfig.build.json', '--watch', '--preserveWatchOutput'], { stdio: 'inherit' });
const server = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', '--watch', 'dist/main.js'], { stdio: 'inherit' });
const stop = () => { watcher.kill(); server.kill(); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
