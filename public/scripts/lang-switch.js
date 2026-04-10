(function () {
  var switchers = document.querySelectorAll('[data-lang-switch]');
  var selectors = document.querySelectorAll('[data-lang-select]');
  if (!switchers.length && !selectors.length) {
    return;
  }

  function normalizeCookiePath(rawPath) {
    var value = String(rawPath || '/').trim();
    if (!value || value === '/') {
      return '/';
    }
    if (value[0] !== '/') {
      value = '/' + value;
    }
    return value.replace(/\/+$/, '') || '/';
  }

  function setLangCookie(lang) {
    var maxAge = 60 * 60 * 24 * 30;
    var secure = window.location.protocol === 'https:' ? '; Secure' : '';
    var basePath =
      document.body && document.body.dataset
        ? document.body.dataset.basePath
        : '/';
    var cookiePath = normalizeCookiePath(basePath);

    document.cookie =
      'lang=' +
      encodeURIComponent(lang) +
      '; Path=' +
      cookiePath +
      '; Max-Age=' +
      maxAge +
      '; SameSite=Lax' +
      secure;
  }

  function applyLanguage(lang) {
    if (!lang) {
      return;
    }

    setLangCookie(lang);

    var url = new URL(window.location.href);
    url.searchParams.delete('lang');
    window.location.replace(url.pathname + url.search + url.hash);
  }

  switchers.forEach(function (el) {
    el.addEventListener('click', function () {
      var lang = el.getAttribute('data-lang-switch');
      applyLanguage(lang);
    });
  });

  selectors.forEach(function (el) {
    el.addEventListener('change', function () {
      applyLanguage(el.value);
    });
  });
})();
