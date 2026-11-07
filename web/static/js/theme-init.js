/**
 * AegisAgent Theme Initializer
 * Loads in <head> before first paint to prevent theme flash.
 * data-theme on <html> + localStorage in try/catch, honours prefers-color-scheme when nothing saved.
 */
(function () {
  "use strict";
  try {
    var storedTheme = localStorage.getItem("aegis_theme");
    var theme;
    if (storedTheme === "dark" || storedTheme === "light") {
      theme = storedTheme;
    } else {
      var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      theme = prefersDark ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", theme);
    if (document.documentElement.style && document.documentElement.style.setProperty) {
      document.documentElement.style.setProperty("color-scheme", theme);
    }
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
