/**
 * Shared sidebar component for all Snitch pages.
 *
 * Usage in each HTML page:
 *   1. A tiny inline theme script in <head> prevents FOUC:
 *      <script>(function(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||'light');})();</script>
 *   2. At the start of <body>:
 *      <div id="sidebar-mount"></div>
 *      <script src="/static/js/sidebar.js"></script>
 *
 * The script runs synchronously so the sidebar is in the DOM before the rest
 * of the page body is parsed. Page-level scripts that call lucide.createIcons()
 * will therefore pick up the sidebar icons automatically.
 *
 * applyTheme(theme) is defined here as the default global implementation.
 * Pages that need custom theme behaviour must explicitly assign
 * window.applyTheme = applyTheme to override this shared version.
 */
(function () {
  // ── Inject sidebar-specific CSS ───────────────────────────────────────────
  var styleEl = document.createElement('style');
  styleEl.textContent = [
    '#sidebar {',
    '  background: var(--bg-sidebar);',
    '  border-right: 1px solid var(--border-color);',
    '  transition: background 0.2s, border-color 0.2s;',
    '}',
    '[data-theme="light"] #sidebar {',
    '  box-shadow: 2px 0 8px rgba(0,0,0,0.04);',
    '}',
    '#sidebar .nav-link.active {',
    '  background: var(--accent-dim);',
    '  color: var(--accent);',
    '  border: 1px solid var(--accent-border);',
    '  border-left-width: 3px;',
    '  box-shadow: none;',
    '  padding-left: 10px;',
    '}',
    '.sidebar-section-label {',
    '  font-size: 11px;',
    '  color: var(--text-tertiary);',
    '  font-weight: 600;',
    '  letter-spacing: 1.5px;',
    '  text-transform: uppercase;',
    '  padding: 12px 8px 4px;',
    '  font-family: var(--font-body);',
    '}',
    '#sidebar-logo-title {',
    '  font-size: 20px;',
    '  font-weight: 700;',
    '  color: var(--text-primary);',
    '  letter-spacing: 0.5px;',
    '  font-family: var(--font-body);',
    '}',
    '#sidebar-logo-sub {',
    '  font-size: 11px;',
    '  color: var(--text-tertiary);',
    '  font-weight: 500;',
    '  letter-spacing: 1.5px;',
    '  text-transform: uppercase;',
    '  font-family: var(--font-body);',
    '  margin-top: 2px;',
    '}',
    '#sidebar-logo-icon {',
    '  width: 40px; height: 40px;',
    '  background: var(--accent-dim);',
    '  border: 1px solid var(--accent-border);',
    '  border-radius: 12px;',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  box-shadow: var(--glow-accent);',
    '  flex-shrink: 0;',
    '}',
    '[data-theme="light"] #sidebar-logo-icon {',
    '  box-shadow: 0 2px 8px rgba(14,165,233,0.12);',
    '}',
    '.sidebar-status-dot {',
    '  width: 7px; height: 7px;',
    '  background: var(--accent-safe);',
    '  border-radius: 50%;',
    '  box-shadow: var(--glow-safe);',
    '  flex-shrink: 0;',
    '}',
    '[data-theme="light"] .sidebar-status-dot {',
    '  box-shadow: 0 0 6px rgba(16,185,129,0.4);',
    '}',
    '.sidebar-status-text {',
    '  font-size: 12px;',
    '  color: var(--accent-safe);',
    '  font-weight: 500;',
    '  letter-spacing: 0.3px;',
    '  font-family: var(--font-body);',
    '}',
  ].join('\n');
  document.head.appendChild(styleEl);

  // ── Default applyTheme (may be overridden by individual pages) ───────────
  window.applyTheme = function (theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  };

  // ── Nav sections ──────────────────────────────────────────────────────────
  var NAV_SECTIONS = [
    {
      label: 'Overview',
      items: [
        { href: '/index.html',        icon: 'layout-dashboard', label: 'Dashboard',    matchPaths: ['/index.html', '/'] },
        { href: '/applications.html', icon: 'server',           label: 'Applications', matchPaths: ['/applications.html', '/app-detail.html'] },
        { href: '/findings.html',     icon: 'list',             label: 'Findings',     matchPaths: ['/findings.html'] },
        { href: '/reports.html',      icon: 'bar-chart-3',      label: 'Reports',      matchPaths: ['/reports.html'] },
        { href: '/secrets.html',      icon: 'key',              label: 'Secrets',      matchPaths: ['/secrets.html'] },
        { href: '/threat-intel.html', icon: 'radar',            label: 'Threat Intel', matchPaths: ['/threat-intel.html'] },
        { href: '/compliance.html',   icon: 'file-check-2',     label: 'Compliance',   matchPaths: ['/compliance.html'] },
      ]
    },
    {
      label: 'Config',
      items: [
        { href: '/policies.html',     icon: 'shield-check',     label: 'Policies',     matchPaths: ['/policies.html'] },
        { href: '/rules.html',        icon: 'book-open',        label: 'Rules',        matchPaths: ['/rules.html'] },
      ]
    },
    {
      label: 'Admin',
      items: [
        { href: '/settings.html',          icon: 'settings',     label: 'Settings',          matchPaths: ['/settings.html'] },
        { href: '/integrations.html',      icon: 'plug',         label: 'Integrations',      matchPaths: ['/integrations.html'] },
        { href: '/repositories.html',      icon: 'git-branch',   label: 'Repositories',      matchPaths: ['/repositories.html'] },
        { href: '/service-accounts.html',  icon: 'bot',          label: 'Service Accounts',  matchPaths: ['/service-accounts.html'] },
      ]
    },
    {
      label: 'Help',
      items: [
        { href: '/help.html',         icon: 'book-open',        label: 'Documentation', matchPaths: ['/help.html'] },
        { href: '/about.html',        icon: 'info',             label: 'About',        matchPaths: ['/about.html'] },
        { href: '/docs',              icon: 'code-2',           label: 'API Docs',     matchPaths: ['/docs'], external: true },
      ]
    }
  ];

  // ── Active-link detection ────────────────────────────────────────────────
  var currentPath = window.location.pathname;
  if (currentPath === '/index.html') currentPath = '/';

  function isActive(item) {
    return item.matchPaths.some(function (p) {
      if (p === '/') return currentPath === '/';
      var prefixPath = p.replace('.html', '');
      return currentPath === p || currentPath.startsWith(prefixPath);
    });
  }

  var INACTIVE_STYLE = 'color:var(--text-secondary);border:1px solid transparent';

  // ── HTML builders ─────────────────────────────────────────────────────────
  function navLink(item) {
    var active = isActive(item);
    var styleStr = [
      'display:flex',
      'align-items:center',
      'gap:10px',
      'padding:10px 12px',
      'border-radius:8px',
      'text-decoration:none',
      'font-size:15px',
      'font-weight:500',
      'margin-bottom:2px',
      'transition:all 0.2s',
      active ? '' : INACTIVE_STYLE,
    ].join(';');

    return '<a href="' + item.href + '"'
      + (item.external ? ' target="_blank" rel="noopener noreferrer"' : '')
      + ' class="nav-link' + (active ? ' active' : '') + '" style="' + styleStr + '">'
      + '<i data-lucide="' + item.icon + '" style="width:18px;height:18px;flex-shrink:0;"></i> '
      + item.label
      + (item.external ? '<i data-lucide="external-link" style="width:12px;height:12px;margin-left:auto;"></i>' : '')
      + '</a>';
  }

  function sectionLabel(text) {
    return '<div class="sidebar-section-label">' + text + '</div>';
  }

  var navHTML = NAV_SECTIONS.map(function (section) {
    return sectionLabel(section.label) + section.items.map(navLink).join('');
  }).join('');

  var sidebarHTML = ''
    + '<aside id="sidebar" style="width:260px;height:100vh;overflow:hidden;display:flex;flex-direction:column;position:fixed;left:0;top:0;z-index:100;">'
    +   '<div style="padding:20px;border-bottom:1px solid var(--border-color);display:flex;align-items:center;gap:12px;">'
    +     '<div id="sidebar-logo-icon">'
    +       '<i data-lucide="shield-alert" style="width:20px;height:20px;color:var(--accent);"></i>'
    +     '</div>'
    +     '<div>'
    +       '<div id="sidebar-logo-title">Snitch</div>'
    +       '<div id="sidebar-logo-sub">AppSec Platform</div>'
    +     '</div>'
    +   '</div>'
    +   '<nav style="flex:1;padding:8px 12px;overflow-y:auto;">'
    +     navHTML
    +   '</nav>'
    +   '<div style="padding:14px 20px;border-top:1px solid var(--border-color);">'
    +     '<div style="display:flex;align-items:center;gap:8px;">'
    +       '<div class="sidebar-status-dot"></div>'
    +       '<span class="sidebar-status-text">All Systems Operational</span>'
    +     '</div>'
    +   '</div>'
    + '</aside>';

  // ── Mount (synchronous — runs while body is being parsed) ────────────────
  var mount = document.getElementById('sidebar-mount');
  if (mount) {
    mount.outerHTML = sidebarHTML;
  }
})();
