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
    +       'background:linear-gradient(135deg,rgba(0,229,255,0.15),rgba(99,102,241,0.15));'
    +       'border:1px solid rgba(0,229,255,0.30);border-radius:50%;cursor:pointer;'
    +       'transition:all 0.2s;flex-shrink:0;box-shadow:0 0 12px rgba(0,229,255,0.15);">'
    +     '<i data-lucide="user" style="width:18px;height:18px;color:#00e5ff;pointer-events:none;"></i>'
    +   '</button>'
    +   '<div id="' + DROPDOWN_ID + '"'
    +     ' style="display:none;position:absolute;right:0;top:calc(100% + 8px);'
    +       'background:#08091a;border:1px solid rgba(0,229,255,0.15);border-radius:12px;'
    +       'padding:6px;min-width:200px;z-index:500;'
    +       'box-shadow:0 8px 32px rgba(0,0,0,0.8),0 0 20px rgba(0,229,255,0.08);">'
    +     '<div style="padding:8px 12px 10px;border-bottom:1px solid rgba(0,229,255,0.08);margin-bottom:4px;">'
    +       '<div style="font-size:13px;font-weight:600;color:#f1f5f9;font-family:\'Fira Code\',monospace;">Admin User</div>'
    +       '<div style="font-size:10px;color:#00e5ff;margin-top:2px;font-family:\'Fira Code\',monospace;letter-spacing:0.5px;">PLATFORM_ADMIN</div>'
    +     '</div>'
    +     '<a href="/profile.html"'
    +       ' style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;'
    +         'text-decoration:none;font-size:13px;font-weight:500;color:#94a3b8;transition:background 0.15s;"'
    +       ' onmouseover="this.style.background=\'rgba(255,255,255,0.05)\';this.style.color=\'#f1f5f9\';"'
    +       ' onmouseout="this.style.background=\'\';this.style.color=\'#94a3b8\';">'
    +       '<i data-lucide="user-circle" style="width:16px;height:16px;flex-shrink:0;"></i>'
    +       'Profile'
    +     '</a>'
    +     '<button disabled title="Authentication not yet enabled"'
    +       ' style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;'
    +         'font-size:13px;font-weight:500;color:#475569;background:none;border:none;'
    +         'cursor:not-allowed;width:100%;text-align:left;opacity:0.55;margin-top:2px;">'
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
