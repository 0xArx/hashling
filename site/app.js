/* =========================================================
   Hashling: app.js
   Copy buttons, theme toggle, FAQ animation, scroll reveal
   ========================================================= */

'use strict';

/* ── theme toggle ──────────────────────────────────────── */
(function () {
  var btn = document.getElementById('theme-btn');
  var html = document.documentElement;

  function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function applyTheme(theme, save) {
    html.dataset.theme = theme;
    if (btn) {
      btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    }
    if (save) { try { localStorage.setItem('hashling-theme', theme); } catch (e) {} }
  }

  var stored;
  try { stored = localStorage.getItem('hashling-theme'); } catch (e) {}
  // Hashling is light by default; the toggle remembers a visitor's own choice.
  applyTheme(stored === 'light' || stored === 'dark' ? stored : 'light');

  if (btn) {
    btn.addEventListener('click', function () {
      var current = html.dataset.theme || getSystemTheme();
      applyTheme(current === 'dark' ? 'light' : 'dark', true);
    });
  }

})();

/* ── copy buttons ──────────────────────────────────────── */
(function () {
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function initCopy(btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (!text) return;

      var label = btn.querySelector('.copy-label');
      var prevLabel = label ? label.textContent : '';

      navigator.clipboard.writeText(text).then(function () {
        btn.classList.add('copied');
        if (label) label.textContent = 'Copied';
        btn.setAttribute('aria-label', 'Copied to clipboard');

        setTimeout(function () {
          btn.classList.remove('copied');
          if (label) label.textContent = prevLabel;
          btn.setAttribute('aria-label', 'Copy install command');
        }, reducedMotion ? 800 : 2000);
      }).catch(function () {
        // fallback for older browsers
        try {
          var ta = document.createElement('textarea');
          ta.value = text;
          ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          btn.classList.add('copied');
          if (label) label.textContent = 'Copied';
          setTimeout(function () {
            btn.classList.remove('copied');
            if (label) label.textContent = prevLabel;
          }, reducedMotion ? 800 : 2000);
        } catch (e) {}
      });
    });
  }

  document.querySelectorAll('.copy-btn').forEach(initCopy);
})();

/* ── FAQ: polished open/close ──────────────────────────── */
(function () {
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reducedMotion) return; // native behaviour is fine; animation already gone via CSS

  // Close all others when one opens (accordion style)
  var items = document.querySelectorAll('.faq-item');

  items.forEach(function (item) {
    item.addEventListener('toggle', function () {
      if (item.open) {
        items.forEach(function (other) {
          if (other !== item && other.open) other.open = false;
        });
      }
    });
  });
})();

/* ── scroll reveal (IntersectionObserver) ─────────────── */
(function () {
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reducedMotion) return; // CSS already makes .reveal fully visible with no transition

  if (!('IntersectionObserver' in window)) {
    // Fallback: just show everything
    document.querySelectorAll('.reveal').forEach(function (el) {
      el.classList.add('visible');
    });
    return;
  }

  document.documentElement.classList.add('js-reveal');
  var showAll = function () { document.querySelectorAll('.reveal').forEach(function (el) { el.classList.add('visible'); }); };
  setTimeout(showAll, 2500);

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0,
    rootMargin: '0px 0px -40px 0px'
  });

  document.querySelectorAll('.reveal').forEach(function (el) {
    observer.observe(el);
  });
})();

/* ── hero entrance animation ───────────────────────────── */
(function () {
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reducedMotion) return;

  var heroContent = document.querySelector('.hero-content');
  var heroMock = document.querySelector('.hero-mock-outer');

  if (heroContent) {
    heroContent.style.opacity = '0';
    heroContent.style.transform = 'translateY(20px)';
    heroContent.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
  }
  if (heroMock) {
    heroMock.style.opacity = '0';
    heroMock.style.transform = 'translateY(28px)';
    heroMock.style.transition = 'opacity 0.7s ease 0.2s, transform 0.7s ease 0.2s';
  }

  // kick off after paint
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      if (heroContent) {
        heroContent.style.opacity = '1';
        heroContent.style.transform = 'none';
      }
      if (heroMock) {
        heroMock.style.opacity = '1';
        heroMock.style.transform = 'none';
      }
    });
  });
})();

/* ── nav: shrink on scroll ─────────────────────────────── */
(function () {
  var nav = document.querySelector('.nav');
  if (!nav) return;

  var ticking = false;

  function onScroll() {
    if (!ticking) {
      requestAnimationFrame(function () {
        if (window.scrollY > 60) {
          nav.style.borderBottomColor = 'var(--border2)';
        } else {
          nav.style.borderBottomColor = '';
        }
        ticking = false;
      });
      ticking = true;
    }
  }

  window.addEventListener('scroll', onScroll, { passive: true });
})();

/* ── Hashling in the hero: press it and it reacts ─────── */
(function () {
  var btn = document.getElementById('hero-mascot');
  var say = document.getElementById('hero-say');
  if (!btn || !say) return;
  var lines = [
    'Hi! I’m Hashling, your personal AI cybersecurity agent.',
    'I keep watch over your Mac day and night, so you don’t have to.',
    'Got a strange text or email? Paste it into my Scam check.',
    'Psst: never paste a command a website gives you into Terminal.',
    'I only change things when you say yes with Touch ID.',
    'Hehe, that tickles!',
    'Want me on your Mac? It takes about 10 minutes.'
  ];
  // Every press makes Hashling bounce: squash, spring up, land, a little rebound.
  var moves = ['hm-bounce'];
  var i = 0;
  var hideTimer;
  btn.addEventListener('click', function () {
    var move = moves[i % moves.length];
    btn.classList.remove('hm-bounce');
    void btn.offsetWidth; // restart the animation
    btn.classList.add(move);
    say.textContent = lines[i % lines.length];
    say.hidden = false;
    i++;
    clearTimeout(hideTimer);
    hideTimer = setTimeout(function () { say.hidden = true; }, 5000);
  });
  btn.addEventListener('animationend', function (e) {
    if (e.animationName === 'hm-bounce-k') btn.classList.remove('hm-bounce');
  });
})();

/* Mac or Windows: the picker swaps the install content. Windows visitors start on Windows. */
(function () {
  var picks = document.querySelectorAll('[data-platform]');
  if (!picks.length) return;
  function choose(p, focus) {
    document.body.setAttribute('data-platform', p);
    picks.forEach(function (b) {
      var on = b.getAttribute('data-platform') === p;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    });
  }
  picks.forEach(function (b) {
    b.addEventListener('click', function () { choose(b.getAttribute('data-platform')); });
    b.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      e.preventDefault();
      choose(b.getAttribute('data-platform') === 'mac' ? 'windows' : 'mac', true);
    });
  });
  document.querySelectorAll('[data-platform-link]').forEach(function (a) {
    a.addEventListener('click', function (e) { e.preventDefault(); choose(a.getAttribute('data-platform-link')); window.scrollTo({ top: 0, behavior: 'smooth' }); });
  });
  var ua = navigator.userAgent || '';
  choose(/Windows/i.test(ua) && !/Macintosh/i.test(ua) ? 'windows' : 'mac');
})();
