/**
 * AegisAgent Theme Initializer
 * Loads in <head> before first paint to prevent theme flash.
 */
(function () {
  try {
    var storedTheme = localStorage.getItem("aegis_theme");
    var theme = "light";
    if (storedTheme === "dark") {
      theme = "dark";
    } else {
      theme = "light"; // Light is default
    }
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.style.setProperty("color-scheme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }

  // Restore sidebar collapsed state
  try {
    var sidebarState = localStorage.getItem("aegis_sidebar");
    if (sidebarState === "collapsed") {
      document.documentElement.setAttribute("data-sidebar", "collapsed");
    }
  } catch (e) {}
})();
