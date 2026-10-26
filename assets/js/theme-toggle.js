(function () {
  var btn = document.querySelector(".theme-toggle");
  if (!btn) return;

  function apply(theme) {
    var light = theme === "light";
    if (light) document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
    document.documentElement.style.colorScheme = light ? "light" : "dark";
    btn.setAttribute("aria-pressed", light ? "true" : "false");
    btn.setAttribute("aria-label", light ? "Usa il tema scuro" : "Usa il tema chiaro");
  }

  apply("dark");
  btn.addEventListener("click", function () {
    var light = document.documentElement.getAttribute("data-theme") === "light";
    apply(light ? "dark" : "light");
  });
})();
