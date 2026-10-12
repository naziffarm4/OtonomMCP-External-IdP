import * as path from 'node:path';
import { loadConfig } from './config';
import { PUBLIC_KEY_FILE } from './keys';
import { createIdp } from './server';

async function main(): Promise<void> {
  const cfg = loadConfig();
  if (!['127.0.0.1', 'localhost', '::1'].includes(cfg.host)) {
    cfg.log(`WARNING: binding to non-loopback host ${cfg.host}. Only do this behind TLS on a trusted network.`);
  }
  const idp = createIdp(cfg);
  const { port, host } = await idp.listen();
  cfg.log(`OtonomMCP External IdP v2 listening on http://${host}:${port}  (UI: ${cfg.origin}/)`);
  cfg.log(`issuer=${cfg.issuer} audience=${cfg.audience} kid=${idp.key.kid}`);
  cfg.log(`data dir: ${cfg.dataDir}`);
  cfg.log(`OtonomMCP pin: AIDM_IDP_PUBLIC_KEY_FILE=${path.join(cfg.dataDir, PUBLIC_KEY_FILE)}`);
  const sweep = setInterval(() => {
    try {
      idp.requests.expireOverdue();
    } catch (e) {
      cfg.log(`expiry sweep failed: ${(e as Error).message}`);
    }
  }, 15_000);
  sweep.unref();
  const stop = () => {
    cfg.log('shutting down');
    clearInterval(sweep);
    idp.close().then(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((e) => {
  console.error(`[idp] fatal: ${(e as Error).message}`);
  process.exit(1);
});
