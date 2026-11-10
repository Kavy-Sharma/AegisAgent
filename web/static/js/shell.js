/**
 * AegisAgent Shell Controller (v2 top bar, user menu, theme toggle)
 * Strictly zero innerHTML, zero inline styles.
 */
(function () {
  "use strict";

  function init() {
    initUserMenu();
    initEnvMenu();
    initThemeButton();
    initHealthPolling();
  }

  function initEnvMenu() {
    var wrap = document.getElementById("env-menu-wrap");
    var btn = document.getElementById("sim-chip");
    var dropdown = document.getElementById("env-dropdown");
    var switchBtn = document.getElementById("btn-env-switch");
    var currentLabel = document.getElementById("env-current-label");
    var confirmModal = document.getElementById("env-confirm-modal");
    var confirmDesc = document.getElementById("env-confirm-desc");
    var confirmCancel = document.getElementById("env-confirm-cancel");
    var confirmProceed = document.getElementById("env-confirm-proceed");
    var restartModal = document.getElementById("env-restarting-modal");
    var restartTitle = document.getElementById("env-restart-title");
    var restartDesc = document.getElementById("env-restart-desc");
    var restartActions = document.getElementById("env-restart-actions");
    var restartCloseBtn = document.getElementById("env-restart-close-btn");

    if (!wrap || !btn || !dropdown || btn.tagName !== "BUTTON") return;

    var pendingTargetEnv = null;

    function closeMenu() {
      dropdown.setAttribute("hidden", "");
      btn.setAttribute("aria-expanded", "false");
    }

    function openMenu() {
      var userMenu = document.getElementById("user-dropdown");
      var userBtn = document.getElementById("user-menu-btn");
      if (userMenu) userMenu.setAttribute("hidden", "");
      if (userBtn) userBtn.setAttribute("aria-expanded", "false");
      dropdown.removeAttribute("hidden");
      btn.setAttribute("aria-expanded", "true");
    }

    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      if (dropdown.hasAttribute("hidden")) openMenu();
      else closeMenu();
    });

    document.addEventListener("click", function (e) {
      if (!dropdown.hasAttribute("hidden") && !wrap.contains(e.target)) {
        closeMenu();
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        if (!dropdown.hasAttribute("hidden")) {
          closeMenu();
          btn.focus();
        } else if (confirmModal && !confirmModal.hasAttribute("hidden")) {
          confirmModal.setAttribute("hidden", "");
        }
      }
    });

    window.addEventListener("aegis:health", function (ev) {
      var d = ev && ev.detail;
      if (!d) return;
      var envName = d.environment || "smart_home";
      var nextTarget = (envName === "office") ? "smart_home" : "office";
      if (currentLabel) {
        currentLabel.textContent = (envName === "office") ? "Office sandbox (office)" : "Virtual Home (smart_home)";
      }
      if (switchBtn) {
        switchBtn.setAttribute("data-target-env", nextTarget);
        switchBtn.textContent = (nextTarget === "office") ? "Switch to Office" : "Switch to Smart Home";
      }
    });

    function showNotice(title, msg, kind) {
      if (window.app && window.app.showToast) {
        window.app.showToast(title, msg, kind || "danger", 5000);
      } else if (window.showToast) {
        window.showToast(title, msg, kind || "danger", 5000);
      }
    }

    if (switchBtn && confirmModal) {
      switchBtn.addEventListener("click", function () {
        pendingTargetEnv = switchBtn.getAttribute("data-target-env") || "office";
        var targetLabel = pendingTargetEnv === "office" ? "Office" : "Smart Home";
        if (confirmDesc) {
          confirmDesc.textContent = "Switch to " + targetLabel + "? Switching restarts the guard, clears pending requests, and may require signing in again. Continue?";
        }
        closeMenu();
        confirmModal.removeAttribute("hidden");
        if (confirmProceed) confirmProceed.focus();
      });
    }

    if (confirmCancel && confirmModal) {
      confirmCancel.addEventListener("click", function () {
        confirmModal.setAttribute("hidden", "");
      });
    }

    if (restartCloseBtn && restartModal) {
      restartCloseBtn.addEventListener("click", function () {
        restartModal.setAttribute("hidden", "");
      });
    }

    function pollUntilReady(targetEnv) {
      window.__aegisRestarting = true;
      var startMs = Date.now();
      var sawDownOrSwitching = false;

      function tick() {
        if (Date.now() - startMs > 40000) {
          if (restartTitle) restartTitle.textContent = "Restart timed out";
          if (restartDesc) restartDesc.textContent = "Could not restart. Run python start.py again.";
          if (restartActions) restartActions.removeAttribute("hidden");
          return;
        }

        fetch("/api/health", {
          method: "GET",
          credentials: "same-origin",
          headers: { "Accept": "application/json" }
        })
          .then(function (resp) {
            if (resp.status === 401 && sawDownOrSwitching) {
              window.location.reload();
              return null;
            }
            if (!resp.ok) throw new Error("not_ready");
            return resp.json();
          })
          .then(function (health) {
            if (!health) return;
            if (health.environment === targetEnv) {
              window.location.reload();
              return;
            }
            setTimeout(tick, 450);
          })
          .catch(function () {
            sawDownOrSwitching = true;
            setTimeout(tick, 450);
          });
      }

      setTimeout(tick, 1200);
    }

    if (confirmProceed && confirmModal) {
      confirmProceed.addEventListener("click", function () {
        if (!pendingTargetEnv || typeof api === "undefined" || !api.switchEnvironment) return;
        confirmProceed.disabled = true;

        api.switchEnvironment(pendingTargetEnv)
          .then(function (res) {
            confirmModal.setAttribute("hidden", "");
            confirmProceed.disabled = false;
            if (!res || res.restarting === false) {
              showNotice("Environment", (res && res.message) || "Already active.", "info");
              return;
            }
            if (restartModal) {
              if (restartTitle) restartTitle.textContent = "Restarting...";
              if (restartDesc) restartDesc.textContent = "Switching guard and worker to " + (pendingTargetEnv === "office" ? "Office" : "Smart Home") + "...";
              if (restartActions) restartActions.setAttribute("hidden", "");
              restartModal.removeAttribute("hidden");
            }
            pollUntilReady(pendingTargetEnv);
          })
          .catch(function (err) {
            confirmModal.setAttribute("hidden", "");
            confirmProceed.disabled = false;
            showNotice("Cannot Switch Environment", (err && err.message) || "Switch refused.", "danger");
          });
      });
    }
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
      if (window.__aegisRestarting) return;
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
