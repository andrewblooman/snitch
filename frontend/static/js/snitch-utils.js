(function () {
  const _LANG = { py: 'Python', js: 'JavaScript', ts: 'TypeScript', go: 'Go', java: 'Java', rb: 'Ruby', cs: 'C#', cpp: 'C++', rs: 'Rust', php: 'PHP' };
  const _ACRONYM = { sql: 'SQL', xss: 'XSS', csrf: 'CSRF', ssrf: 'SSRF', rce: 'RCE', lfi: 'LFI', xxe: 'XXE', iac: 'IaC', api: 'API', aws: 'AWS', url: 'URL', ssh: 'SSH', tls: 'TLS', ssl: 'SSL', xml: 'XML', html: 'HTML', http: 'HTTP', idor: 'IDOR', ssti: 'SSTI', cmd: 'Command', cve: 'CVE' };
  const _STRIP = new Set(['security', 'semgrep', 'checkov', 'gitleaks', 'trivy', 'grype', 'misc', 'rules', 'rule', 'check', 'checks', 'audit', 'detect', 'detection']);

  // Convert a dotted/hyphenated rule ID like "dockerfile.security.missing-user.missing-user"
  // into a readable title like "Dockerfile Missing User".
  // Only transforms strings that look like rule IDs (contain dots/slashes, or are all-lowercase).
  // Strings with spaces or mixed-case camelCase are returned unchanged.
  window.humanizeTitle = function (raw) {
    if (!raw || raw.includes(' ')) return raw;
    // Skip if no dots/slashes and not all-lowercase (already a readable mixed-case title)
    if (!raw.includes('.') && !raw.includes('/') && raw !== raw.toLowerCase()) return raw;
    const parts = raw.toLowerCase().split(/[.\-_/]+/).filter(Boolean);
    const seen = new Set();
    const unique = parts.filter(p => { if (seen.has(p)) return false; seen.add(p); return true; });
    const filtered = unique.filter(p => !_STRIP.has(p));
    const words = filtered.map(p => _LANG[p] || _ACRONYM[p] || (p.charAt(0).toUpperCase() + p.slice(1)));
    return words.length > 0 ? words.join(' ') : raw;
  };
})();
