import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Guards on the deployment files themselves.
 *
 * Nothing in the application can notice a secret pasted into a blueprint or a
 * relay started with a well-known password — those live in files the code
 * never reads. These checks are deliberately textual: they need no YAML
 * dependency, and they fail on exactly the edit they exist to catch.
 */
const repoFile = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../../${name}`, import.meta.url)), 'utf8');

/** Comment lines explain the rules below, so they must not trip them. */
const withoutComments = (text: string): string =>
  text
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n');

describe('docker-compose.yml', () => {
  const compose = withoutComments(repoFile('docker-compose.yml'));

  it('gives the TURN relay no default secret and stops it when one is missing', () => {
    // `${TURN_STATIC_AUTH_SECRET:-changeme}` would start a relay that anyone
    // can mint credentials for. An empty default is fine, because the
    // entrypoint refuses to start on it.
    const defaults = [...compose.matchAll(/\$\{TURN_STATIC_AUTH_SECRET:?-([^}]*)\}/g)].map((m) => m[1]);
    expect(defaults.filter((value) => value !== '')).toEqual([]);
    expect(compose).not.toMatch(/static-auth-secret=(?!\$\$TURN_STATIC_AUTH_SECRET\b)/);

    // The length check must come before the relay is exec'd, and must exit.
    expect(compose).toContain('[ "$${#TURN_STATIC_AUTH_SECRET}" -lt 16 ]');
    expect(compose).toMatch(/exit 1\s+fi\s+exec turnserver/);
  });

  it('publishes MongoDB on loopback only', () => {
    // The dev database has no authentication; 0.0.0.0 would put it on the LAN.
    const published = [...compose.matchAll(/^\s*-\s*'?([^'\n]*:27017)'?\s*$/gm)].map((m) => m[1]!);
    expect(published.length).toBeGreaterThan(0);
    for (const mapping of published) expect(mapping.startsWith('127.0.0.1:'), mapping).toBe(true);
  });
});

describe('render.yaml', () => {
  /** One entry per `- key:` under envVars, with the settings that follow it. */
  const entries = withoutComments(repoFile('render.yaml'))
    .split(/^\s*- key:\s*/m)
    .slice(1)
    .map((block) => {
      const [name = '', ...rest] = block.split('\n');
      const body = rest.join('\n');
      return {
        name: name.trim(),
        literal: /^\s*value:/m.test(body),
        dashboardOnly: /^\s*sync:\s*false\s*$/m.test(body),
        generated: /^\s*generateValue:\s*true\s*$/m.test(body),
      };
    });

  const isSecret = (name: string): boolean =>
    /KEY|SECRET|PEPPER|PASSWORD|TOKEN|_URI$|_URL$/.test(name);

  it('declares the variables the server cannot boot without', () => {
    const names = entries.map((e) => e.name);
    for (const required of [
      'MONGO_URI', 'JWT_PRIVATE_KEY_B64', 'JWT_PUBLIC_KEY_B64', 'CSRF_KEY',
      'PASSWORD_PEPPER', 'DATA_ENCRYPTION_KEY', 'BLIND_INDEX_KEY', 'IP_HASH_KEY', 'ENUM_KEY',
    ]) {
      expect(names, required).toContain(required);
    }
  });

  it('never commits a secret value: each one is generated or set in the dashboard', () => {
    const secrets = entries.filter((e) => isSecret(e.name));
    expect(secrets.length).toBeGreaterThan(0);
    for (const entry of secrets) {
      expect(entry.literal, `${entry.name} must not carry a literal value`).toBe(false);
      expect(entry.dashboardOnly || entry.generated, `${entry.name} needs sync:false or generateValue:true`).toBe(true);
    }
  });
});
