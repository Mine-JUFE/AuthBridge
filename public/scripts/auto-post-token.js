(function () {
  var form = document.getElementById('callback-form');
  if (!form) {
    return;
  }

  if (typeof form.requestSubmit === 'function') {
    window.setTimeout(function () {
      form.requestSubmit();
    }, 0);
    return;
  }

  window.setTimeout(function () {
    form.submit();
  }, 0);
}());
