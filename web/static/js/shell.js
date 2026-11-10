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
          var envName = health.environment || "smart_home";
          var isOffice = (envName === "office");
          var hwStatus = health.hardware_status || (
            (health.hardware_mode === "virtual" || (health.device && health.device.transport === "virtual"))
              ? "virtual"
              : (health.device && (health.device.status === "online" || health.device.connected) ? "connected" : "unreachable")
          );

          if (document.body && document.body.dataset) {
            document.body.dataset.env = envName;
            document.body.dataset.hwStatus = hwStatus;
          }

          var workerEl = document.getElementById("health-status-worker");
          if (workerEl) {
            workerEl.textContent = health.worker && health.worker.alive ? (health.worker.busy ? "Busy" : "Online") : "Offline";
          }
          var deviceEl = document.getElementById("health-status-device");
          if (deviceEl) {
            if (isOffice || hwStatus === "virtual") {
              deviceEl.textContent = "Simulated";
            } else if (hwStatus === "connected") {
              deviceEl.textContent = "Connected";
            } else {
              deviceEl.textContent = "Unreachable";
            }
          }
          var ollamaEl = document.getElementById("health-status-ollama");
          if (ollamaEl) {
            ollamaEl.textContent = health.ollama && (health.ollama.ok || health.ollama.available) ? "Online" : "Offline";
          }
          var auditEl = document.getElementById("health-status-audit");
          if (auditEl) {
            auditEl.textContent = health.audit_chain && health.audit_chain.intact ? "Verified" : (health.audit && health.audit.valid ? "Verified" : "Tampered");
          }

          var chipText;
          if (isOffice) {
            chipText = "Office sandbox (simulation)";
          } else if (hwStatus === "connected") {
            chipText = "Hardware connected";
          } else if (hwStatus === "unreachable") {
            chipText = "Hardware unreachable";
          } else {
            chipText = "Virtual Home (simulation)";
          }
          var simEl = document.getElementById("sim");
          if (simEl) {
            simEl.textContent = chipText;
          }
          var simChip = document.getElementById("sim-chip") || (simEl ? simEl.closest(".sim-chip") : null);
          if (simChip) {
            simChip.classList.toggle("is-connected", !isOffice && hwStatus === "connected");
            simChip.classList.toggle("is-unreachable", !isOffice && hwStatus === "unreachable");
          }
          var consoleHwEl = document.getElementById("console-hw-label");
          if (consoleHwEl) {
            consoleHwEl.textContent = chipText;
          }

          try {
            window.dispatchEvent(new CustomEvent("aegis:health", { detail: health }));
          } catch (_evErr) {}
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
