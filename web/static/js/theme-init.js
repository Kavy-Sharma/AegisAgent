/**
 * AegisAgent Theme Initializer
 * Loads in <head> before first paint to prevent theme flash.
 * Default is light when nothing is saved; ignores OS prefers-color-scheme.
 */
(function () {
  try {
    var storedTheme = localStorage.getItem("aegis_theme");
    // If no saved theme or stored as system/empty, default strictly to light (ignoring OS dark setting)
    var theme = (storedTheme === "dark") ? "dark" : "light";
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
