/**
 * Shared header user widget for all Snitch pages.
 *
 * Usage in each HTML page:
 *   1. Add id="header-user-slot" to the right-side container in <header>.
 *      For pages with no right-side controls, add an empty div:
 *        <div id="header-user-slot"></div>
 *   2. After the sidebar script:
 *        <script src="/static/js/header.js"></script>
 *
 * The script injects a circular user avatar button that opens a dropdown
 * with a Profile link and a (disabled) Logout placeholder.
 */
(function () {
  var DROPDOWN_ID = 'snitch-user-dropdown';

  var widgetHTML = ''
    + '<div style="position:relative;flex-shrink:0;">'
    +   '<button id="snitch-user-btn"'
    +     ' onclick="window.__snitchToggleUserMenu(event)"'
    +     ' title="Account"'
    +     ' style="display:flex;align-items:center;justify-content:center;width:36px;height:36px;'
    +       'background:var(--accent-dim);'
    +       'border:1px solid var(--accent-border);border-radius:50%;cursor:pointer;'
    +       'transition:all 0.2s;flex-shrink:0;box-shadow:var(--glow-accent);">'
    +     '<i data-lucide="user" style="width:18px;height:18px;color:var(--accent);pointer-events:none;"></i>'
    +   '</button>'
    +   '<div id="' + DROPDOWN_ID + '"'
    +     ' style="display:none;position:absolute;right:0;top:calc(100% + 8px);'
    +       'background:var(--bg-modal);border:1px solid var(--border-color);border-radius:12px;'
    +       'padding:6px;min-width:200px;z-index:500;'
    +       'box-shadow:var(--card-shadow);">'
    +     '<div style="padding:8px 12px 10px;border-bottom:1px solid var(--border-subtle);margin-bottom:4px;">'
    +       '<div style="font-size:15px;font-weight:600;color:var(--text-primary);font-family:var(--font-body);">Admin User</div>'
    +       '<div style="font-size:12px;color:var(--text-tertiary);margin-top:2px;font-family:var(--font-body);letter-spacing:0.5px;">Platform Admin</div>'
    +     '</div>'
    +     '<a href="/profile.html"'
    +       ' style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;'
    +         'text-decoration:none;font-size:15px;font-weight:500;color:var(--text-secondary);transition:background 0.15s;"'
    +       ' onmouseover="this.style.background=\'var(--table-row-hover)\';this.style.color=\'var(--text-primary)\';"'
    +       ' onmouseout="this.style.background=\'\';this.style.color=\'var(--text-secondary)\';">'
    +       '<i data-lucide="user-circle" style="width:16px;height:16px;flex-shrink:0;"></i>'
    +       'Profile'
    +     '</a>'
    +     '<button disabled title="Authentication not yet enabled"'
    +       ' style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;'
    +         'font-size:15px;font-weight:500;color:var(--text-tertiary);background:none;border:none;'
    +         'cursor:not-allowed;width:100%;text-align:left;opacity:0.45;margin-top:2px;font-family:var(--font-body);">'
    +       '<i data-lucide="log-out" style="width:16px;height:16px;flex-shrink:0;"></i>'
    +       'Logout'
    +     '</button>'
    +   '</div>'
    + '</div>';

  window.__snitchToggleUserMenu = function (e) {
    if (e) e.stopPropagation();
    var dd = document.getElementById(DROPDOWN_ID);
    if (!dd) return;
    dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
  };

  document.addEventListener('DOMContentLoaded', function () {
    var slot = document.getElementById('header-user-slot');
    if (!slot) return;

    slot.insertAdjacentHTML('beforeend', widgetHTML);

    if (typeof lucide !== 'undefined') lucide.createIcons();

    document.addEventListener('click', function (e) {
      var btn = document.getElementById('snitch-user-btn');
      var dd  = document.getElementById(DROPDOWN_ID);
      if (!dd || !btn) return;
      if (!btn.contains(e.target)) dd.style.display = 'none';
    });
  });
})();
