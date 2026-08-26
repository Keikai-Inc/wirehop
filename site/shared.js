(function () {
  var NAV_LINKS = [
    { label: 'Features',     href: '#features',     cross: 'index.html#features' },
    { label: 'Install',      href: '#install',      cross: 'index.html#install' },
    { label: 'How It Works', href: '#how-it-works', cross: 'index.html#how-it-works' },
    { label: 'AI Agents',    href: '#ai-agents',    cross: 'index.html#ai-agents' },
    { label: 'Private Network', href: '#private-network', cross: 'index.html#private-network' },
    { label: 'Fleet',        href: 'fleet.html',    cross: 'fleet.html' },
    { label: 'Automation',   href: 'orchestration.html', cross: 'orchestration.html' },
  ];

  var path = location.pathname;
  var onIndex = path === '/' || path.endsWith('/index.html') || path.endsWith('/index') || /\/site\/?$/.test(path);

  /* --- Nav --------------------------------------------------------------- */
  var navEl = document.getElementById('site-nav');
  if (navEl) {
    var items = NAV_LINKS.map(function (link) {
      var url = (onIndex || !link.href.startsWith('#')) ? link.href : link.cross;
      var cls = '';
      if (!onIndex && link.href === 'fleet.html' && path.indexOf('fleet') !== -1) cls = ' class="active"';
      if (!onIndex && link.href === 'orchestration.html' && path.indexOf('orchestration') !== -1) cls = ' class="active"';
      return '<li><a href="' + url + '"' + cls + '>' + link.label + '</a></li>';
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
        '<p class="footer-tagline">\u201CThe world has changed. Security has to change with it.\u201D</p>' +
      '</div>';
  }
})();
