/**
 * AegisAgent Global Keyboard Shortcuts
 * Handles Ctrl+K palette, navigation sequences (g then o/c/a), '/' input focus, and 't' theme toggle.
 */
(function () {
  var gPressed = false;
  var gTimeout = null;

  document.addEventListener("keydown", function (e) {
    // 1. Ctrl+K or Cmd+K: Command Palette
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (app && app.openPalette) {
        app.openPalette();
      }
      return;
    }

    // 2. Escape: Close palette, ledger modal, or alert drawer
    if (e.key === "Escape") {
      if (typeof app !== "undefined" && app && app.closePalette) {
        app.closePalette();
      }
      if (typeof app !== "undefined" && app && app.closeLedgerModal) {
        app.closeLedgerModal();
      }
      var ledgerModal = document.getElementById("ledger-verification-modal");
      if (ledgerModal) ledgerModal.classList.remove("is-open");
      var alertDrawerBackdrop = document.getElementById("alert-drawer-backdrop");
      if (alertDrawerBackdrop) alertDrawerBackdrop.classList.remove("is-open");
      var alertDrawer = document.getElementById("alert-drawer");
      if (alertDrawer) alertDrawer.classList.remove("is-open");
      return;
    }

    // Ignore single-key shortcuts if inside an input or textarea
    var activeTag = (document.activeElement && document.activeElement.tagName) || "";
    var isInput = activeTag === "INPUT" || activeTag === "TEXTAREA" || (document.activeElement && document.activeElement.isContentEditable);
    if (isInput) return;

    // 3. 't': Toggle Theme
    if (e.key === "t" && !e.ctrlKey && !e.altKey && !e.metaKey) {
      e.preventDefault();
      var current = document.documentElement.getAttribute("data-theme");
      var next = current === "dark" ? "light" : "dark";
      if (app && app.applyTheme) {
        app.applyTheme(next);
        app.showToast("Theme changed", "Switched to " + next + " mode.", "info", 1500);
      }
      return;
    }

    // 4. '/': Focus chat composer input
    if (e.key === "/" && !e.ctrlKey && !e.altKey && !e.metaKey) {
      var composerInput = document.getElementById("chat-textarea");
      if (composerInput) {
        e.preventDefault();
        composerInput.focus();
      }
      return;
    }

    // 5. 'g' sequences: g then o, g then c, g then a
    if (e.key.toLowerCase() === "g" && !gPressed && !e.ctrlKey && !e.altKey && !e.metaKey) {
      gPressed = true;
      clearTimeout(gTimeout);
      gTimeout = setTimeout(function () {
        gPressed = false;
      }, 1000);
      return;
    }

    if (gPressed) {
      var key = e.key.toLowerCase();
      gPressed = false;
      clearTimeout(gTimeout);

      if (key === "o") {
        e.preventDefault();
        window.location.href = "/overview";
      } else if (key === "c") {
        e.preventDefault();
        window.location.href = "/console";
      } else if (key === "a") {
        e.preventDefault();
        window.location.href = "/approvals";
      }
    }
  });
})();
