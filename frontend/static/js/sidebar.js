/**
 * Shared sidebar component for all Snitch pages.
 *
 * Usage in each HTML page:
 *   1. A tiny inline theme script in <head> prevents FOUC:
 *      <script>(function(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||'dark');})();</script>
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
        { href: '/',                  icon: 'layout-dashboard', label: 'Dashboard',    matchPaths: ['/'] },
        { href: '/applications.html', icon: 'layers',           label: 'Applications', matchPaths: ['/applications.html', '/app-detail.html'] },
        { href: '/reports.html',      icon: 'bar-chart-3',      label: 'Reports',      matchPaths: ['/reports.html'] },
        { href: '/secrets.html',      icon: 'key',              label: 'Secrets',      matchPaths: ['/secrets.html'] },
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

  var ACTIVE_STYLE = [
    'background:linear-gradient(135deg,rgba(0,229,255,0.12),rgba(99,102,241,0.12))',
    'color:#00e5ff',
    'border-left:3px solid #00e5ff',
    'border-top:1px solid rgba(0,229,255,0.18)',
    'border-right:1px solid rgba(0,229,255,0.18)',
    'border-bottom:1px solid rgba(0,229,255,0.18)',
    'box-shadow:inset 0 0 12px rgba(0,229,255,0.06)',
    'padding-left:10px',
  ].join(';');

  var INACTIVE_STYLE = 'color:#94a3b8;border:1px solid transparent';

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
      'font-size:14px',
      'font-weight:500',
      'margin-bottom:2px',
      'transition:all 0.2s',
      active ? ACTIVE_STYLE : INACTIVE_STYLE,
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
    return '<div style="font-size:9px;color:#475569;font-weight:600;letter-spacing:2px;text-transform:uppercase;padding:12px 8px 4px;font-family:\'Fira Code\',monospace;">// ' + text + '</div>';
  }

  var navHTML = NAV_SECTIONS.map(function (section) {
    return sectionLabel(section.label) + section.items.map(navLink).join('');
  }).join('');

  var sidebarHTML = ''
    + '<aside id="sidebar" style="width:260px;min-height:100vh;background:#060712;border-right:1px solid rgba(0,229,255,0.10);display:flex;flex-direction:column;position:fixed;left:0;top:0;z-index:100;">'
    +   '<div style="padding:24px 20px;border-bottom:1px solid rgba(0,229,255,0.08);display:flex;align-items:center;gap:12px;">'
    +     '<div style="width:40px;height:40px;background:linear-gradient(135deg,rgba(0,229,255,0.2),rgba(99,102,241,0.2));border:1px solid rgba(0,229,255,0.5);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(0,229,255,0.2),inset 0 0 10px rgba(0,229,255,0.05);">'
    +       '<i data-lucide="shield-alert" style="width:20px;height:20px;color:#00e5ff;"></i>'
    +     '</div>'
    +     '<div>'
    +       '<div class="glitch-hover" style="font-size:20px;font-weight:700;color:#f1f5f9;letter-spacing:1px;font-family:\'Fira Code\',monospace;">Snitch</div>'
    +       '<div style="font-size:10px;color:#00e5ff;font-weight:500;letter-spacing:2px;text-transform:uppercase;font-family:\'Fira Code\',monospace;">AppSec_Platform</div>'
    +     '</div>'
    +   '</div>'
    +   '<nav style="flex:1;padding:8px 12px;overflow-y:auto;">'
    +     navHTML
    +   '</nav>'
    +   '<div style="padding:16px 20px;border-top:1px solid rgba(0,229,255,0.08);">'
    +     '<div style="display:flex;align-items:center;gap:8px;">'
    +       '<div style="width:7px;height:7px;background:#00c853;border-radius:50%;box-shadow:0 0 10px #00c853,0 0 4px #00c853;"></div>'
    +       '<span style="font-size:11px;color:#00c853;font-family:\'Fira Code\',monospace;font-weight:500;letter-spacing:0.5px;">[SECURE] · All Systems Nominal</span>'
    +     '</div>'
    +   '</div>'
    + '</aside>';

  // ── Mount (synchronous — runs while body is being parsed) ────────────────
  var mount = document.getElementById('sidebar-mount');
  if (mount) {
    mount.outerHTML = sidebarHTML;
  }
})();
