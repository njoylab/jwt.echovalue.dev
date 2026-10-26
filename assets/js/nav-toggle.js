(function () {
  var toggle = document.querySelector(".navbar-toggle");
  var nav = document.querySelector(".navbar-nav");
  if (!toggle || !nav) return;

  function setOpen(open) {
    toggle.classList.toggle("active", open);
    nav.classList.toggle("active", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  toggle.addEventListener("click", function () {
    setOpen(!nav.classList.contains("active"));
  });
  nav.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      setOpen(false);
    });
  });
})();
