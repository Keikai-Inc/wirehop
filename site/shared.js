(function () {
  var REPO = 'https://github.com/Keikai-Inc/wirehop';

  var NAV_LINKS = [
    { label: 'Install',      href: 'install.html' },
    { label: 'Private Network', href: 'private-network.html' },
    { label: 'AI Agents',    href: 'agents.html' },
    { label: 'Fleet',        href: 'fleet.html' },
    { label: 'Automation',   href: 'orchestration.html' },
    { label: 'Security',     href: 'security.html' },
    { label: 'FAQ',          href: 'faq.html' },
    { label: 'Source',       href: REPO },
  ];

  // Pages that get an "active" nav highlight, matched on a path substring.
  var PAGE_MATCH = ['install', 'private-network', 'fleet', 'orchestration', 'agents', 'security', 'vs-tailscale', 'faq'];

  var path = location.pathname;

  /* --- Nav --------------------------------------------------------------- */
  var navEl = document.getElementById('site-nav');
  if (navEl) {
    var items = NAV_LINKS.map(function (link) {
      var cls = '';
      for (var i = 0; i < PAGE_MATCH.length; i++) {
        if (link.href === PAGE_MATCH[i] + '.html' && path.indexOf(PAGE_MATCH[i]) !== -1) {
          cls = ' class="active"';
          break;
        }
      }
      return '<li><a href="' + link.href + '"' + cls + '>' + link.label + '</a></li>';
    }).join('');

    navEl.innerHTML =
      '<a href="index.html" class="nav-brand">' +
        '<img src="hop-icon.png" alt="WireHop" style="height:1.5rem;width:auto;filter:brightness(0) invert(1);"> WireHop' +
      '</a>' +
      '<button class="nav-toggle" aria-label="Toggle navigation" ' +
        'onclick="document.querySelector(\'.nav-links\').classList.toggle(\'open\')">' +
        '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
          '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>' +
        '</svg>' +
      '</button>' +
      '<ul class="nav-links">' + items + '</ul>';
  }

  /* --- Footer ------------------------------------------------------------ */
  var footerEl = document.getElementById('site-footer');
  if (footerEl) {
    footerEl.innerHTML =
      '<div class="footer-bottom">' +
        '<p class="footer-copy">&copy; 2026 <a href="https://keikai.ai">Keikai, Inc.</a> All rights reserved.</p>' +
        '<p class="footer-links">' +
          '<a href="install.html">Install</a>' +
          '<a href="faq.html">FAQ</a>' +
          '<a href="security.html">Security</a>' +
          '<a href="' + REPO + '/tree/main/docs">Docs</a>' +
          '<a href="' + REPO + '">Source</a>' +
        '</p>' +
        '<p class="footer-tagline">“The world has changed. Security has to change with it.”</p>' +
      '</div>';
  }

  /* --- Copy buttons: <button class="copy-btn" data-cmd="..." onclick="copyCmd(this)"> */
  var COPY_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  var DONE_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';

  // A copy button is written empty in the HTML; the icon is filled in here so
  // pages don't each carry the SVG.
  document.querySelectorAll('.copy-btn').forEach(function (b) {
    if (!b.innerHTML.trim()) b.innerHTML = COPY_ICON;
  });

  window.copyCmd = function (btn) {
    var text = btn.getAttribute('data-cmd') || '';
    navigator.clipboard.writeText(text).then(function () {
      btn.innerHTML = DONE_ICON;
      setTimeout(function () { btn.innerHTML = COPY_ICON; }, 1800);
    });
  };
})();
