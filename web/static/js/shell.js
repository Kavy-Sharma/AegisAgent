/**
 * AegisAgent Shell Controller (v2 top bar, user menu, theme toggle)
 * Strictly zero innerHTML, zero inline styles.
 */
(function () {
  "use strict";

  function init() {
    initUserMenu();
    initThemeButton();
    initHealthPolling();
  }

  function initUserMenu() {
    var btn = document.getElementById("user-menu-btn");
    var menu = document.getElementById("user-dropdown");
    if (!btn || !menu) return;

    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var isHidden = menu.hasAttribute("hidden");
      if (isHidden) {
        menu.removeAttribute("hidden");
        btn.setAttribute("aria-expanded", "true");
      } else {
        menu.setAttribute("hidden", "");
        btn.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("click", function (e) {
      if (!menu.hasAttribute("hidden") && !menu.contains(e.target) && e.target !== btn) {
        menu.setAttribute("hidden", "");
        btn.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !menu.hasAttribute("hidden")) {
        menu.setAttribute("hidden", "");
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
      }
    });
  }

  function updateThemeLabels() {
    var btn = document.getElementById("theme");
    if (!btn) return;
    var current = document.documentElement.getAttribute("data-theme") || "light";
    var label = current === "dark" ? "Switch to light theme" : "Switch to dark theme";
    btn.setAttribute("aria-label", label);
    btn.setAttribute("title", label);
  }

  function initThemeButton() {
    var btn = document.getElementById("theme");
    if (!btn) return;

    updateThemeLabels();

    btn.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") || "light";
      var next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      if (document.documentElement.style && document.documentElement.style.setProperty) {
        document.documentElement.style.setProperty("color-scheme", next);
      }
      try {
        localStorage.setItem("aegis_theme", next);
      } catch (e) {}
      updateThemeLabels();
    });
  }

  function initHealthPolling() {
    function updateHealth() {
      if (typeof api === "undefined" || !api.get) return;
      api.get("/api/health")
        .then(function (health) {
          if (!health) return;
          var workerEl = document.getElementById("health-status-worker");
          if (workerEl) {
            workerEl.textContent = health.worker && health.worker.alive ? (health.worker.busy ? "Busy" : "Online") : "Offline";
          }
          var deviceEl = document.getElementById("health-status-device");
          if (deviceEl) {
            if (health.environment === "office" || health.hardware_mode === "virtual" || (health.device && health.device.transport === "virtual")) {
              deviceEl.textContent = "Simulated";
            } else {
              deviceEl.textContent = health.device && health.device.connected ? "Connected" : "Offline";
            }
          }
          var ollamaEl = document.getElementById("health-status-ollama");
          if (ollamaEl) {
            ollamaEl.textContent = health.ollama && health.ollama.available ? "Online" : "Offline";
          }
          var auditEl = document.getElementById("health-status-audit");
          if (auditEl) {
            auditEl.textContent = health.audit && health.audit.valid ? "Verified" : "Tampered";
          }
          var simEl = document.getElementById("sim");
          if (simEl) {
            if (health.environment === "office") {
              simEl.textContent = "Office sandbox (simulation)";
            } else {
              simEl.textContent = "Virtual Home (simulation)";
            }
          }
        })
        .catch(function () {});
    }

    updateHealth();
    setInterval(updateHealth, 5000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
