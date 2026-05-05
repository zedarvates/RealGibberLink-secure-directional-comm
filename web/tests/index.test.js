import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const html = readFileSync(resolve(__dirname, '../index.html'), 'utf-8');

beforeEach(() => {
  document.documentElement.innerHTML = html;
});

describe('HTML structure', () => {
  it('should have all required sections', () => {
    expect(html).toContain('Cryptographic Operations');
    expect(html).toContain('QR Code Utilities');
    expect(html).toContain('Protocol Engine');
  });

  it('should have no duplicate section IDs', () => {
    const idCounts = {};
    const idRegex = /id="([^"]+)"/g;
    let match;
    while ((match = idRegex.exec(html)) !== null) {
      const id = match[1];
      idCounts[id] = (idCounts[id] || 0) + 1;
    }
    const duplicates = Object.entries(idCounts).filter(([, count]) => count > 1);
    expect(duplicates).toEqual([]);
  });

  it('should link to external CSS', () => {
    expect(html).toContain('<link rel="stylesheet" href="styles.css">');
  });

  it('should not contain style tag with CSS rules', () => {
    expect(html).not.toContain('<style>');
  });
});

describe('Security', () => {
  it('should have CSP meta tag', () => {
    expect(html).toContain('Content-Security-Policy');
    expect(html).toContain("default-src 'self'");
  });

  it('key fields should use type="password"', () => {
    expect(html).toMatch(/type="password" id="hmac-key"/);
    expect(html).toMatch(/type="password" id="aes-key"/);
    expect(html).toMatch(/type="password" id="session-id-input"/);
    expect(html).toMatch(/type="password" id="public-key-input"/);
  });

  it('should have a key visibility toggle button', () => {
    expect(html).toContain('id="toggle-keys"');
  });
});

describe('No dead code', () => {
  it('should not contain duplicated async functions', () => {
    const asyncFnCount = (html.match(/async function initiateHandshake/g) || []).length;
    expect(asyncFnCount).toBe(0);
  });
});

describe('Build configuration', () => {
  it('package.json should have test scripts', () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, '../package.json'), 'utf-8'));
    expect(pkg.scripts).toHaveProperty('test');
    expect(pkg.scripts).toHaveProperty('build');
    expect(pkg.scripts).toHaveProperty('dev');
  });

  it('package.json should have devDependencies', () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, '../package.json'), 'utf-8'));
    expect(pkg.devDependencies).toHaveProperty('vite');
  });
});
