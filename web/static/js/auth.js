/**
 * AegisAgent Auth Page Controller
 * Show/hide password toggling, credential autofill management, client validation,
 * and lockout countdown timer without native browser popups.
 */

(function () {
  "use strict";

  function init() {
    initCredentialInputs();
    initPasswordToggle();
    initSetupValidation();
    initThemeToggle();
    initAuthRipples();
  }

  // Allows standard credential autofill so both username and password fill together on click
  function initCredentialInputs() {
    const userField = document.getElementById("username");
    const passField = document.getElementById("password");
    if (!userField || !passField) return;

    // Ensure fields have no readonly restrictions that prevent dual autofill
    userField.removeAttribute("readonly");
    passField.removeAttribute("readonly");
  }

  function initPasswordToggle() {
    const toggleBtn = document.getElementById("toggle-password-btn");
    const passwordInput = document.getElementById("password");
    if (!toggleBtn || !passwordInput) return;

    toggleBtn.addEventListener("click", () => {
      const isPassword = passwordInput.getAttribute("type") === "password";
      passwordInput.setAttribute("type", isPassword ? "text" : "password");
    });
  }

  function showAuthAlert(message, type) {
    type = type || "danger";
    let alertEl = document.getElementById("auth-dynamic-alert");
    const form = document.getElementById("setup-form") || document.getElementById("login-form");
    if (!form) return;

    if (!alertEl) {
      alertEl = document.createElement("div");
      alertEl.id = "auth-dynamic-alert";
      form.parentNode.insertBefore(alertEl, form);
    }

    alertEl.className = "auth-alert alert-" + type + " auth-alert-animated";
    alertEl.replaceChildren();
    const svgEl = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svgEl.setAttribute("class", "icon");
    const useEl = document.createElementNS("http://www.w3.org/2000/svg", "use");
    useEl.setAttribute("href", "/static/icons.svg#icon-" + (type === "ok" ? "check-circle" : "alert-triangle"));
    svgEl.appendChild(useEl);
    const spanEl = document.createElement("span");
    spanEl.className = "auth-alert-text";
    spanEl.textContent = message;
    alertEl.appendChild(svgEl);
    alertEl.appendChild(spanEl);

    // Restart shake animation
    alertEl.classList.remove("auth-alert-animated");
    void alertEl.offsetWidth;
    alertEl.classList.add("auth-alert-animated");
  }

  function initLockoutTimer() {
    const alertEl = document.getElementById("auth-error-alert");
    if (!alertEl) return;

    const alertTextEl = alertEl.querySelector(".auth-alert-text");
    if (!alertTextEl) return;

    const match = alertTextEl.textContent.match(/Try again in (\d+) seconds/i);
    if (!match) return;

    let secondsRemaining = parseInt(match[1], 10);
    const submitBtn = document.getElementById("login-submit-btn");
    if (submitBtn) submitBtn.disabled = true;

    const timer = setInterval(() => {
      secondsRemaining -= 1;
      if (secondsRemaining <= 0) {
        clearInterval(timer);
        alertTextEl.textContent = "Lockout window has expired. You may attempt to sign in again.";
        alertEl.className = "auth-alert alert-ok";
        if (submitBtn) submitBtn.disabled = false;
      } else {
        alertTextEl.textContent = `Account is locked. Try again in ${secondsRemaining} seconds.`;
      }
    }, 1000);
  }

  function initSetupValidation() {
    const form = document.getElementById("setup-form");
    if (!form) return;

    const passInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm_password");

    form.addEventListener("submit", (e) => {
      if (passInput && passInput.value.length < 10) {
        e.preventDefault();
        showAuthAlert("Password must be at least 10 characters long.");
        passInput.focus();
        return;
      }
      if (passInput && confirmInput && passInput.value !== confirmInput.value) {
        e.preventDefault();
        showAuthAlert("Passwords do not match. Please re-enter matching passwords.");
        confirmInput.focus();
        return;
      }
    });
  }

  function initThemeToggle() {
    const btn = document.getElementById("theme-toggle-btn");
    if (!btn) return;

    btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try {
        localStorage.setItem("aegis_theme", next);
      } catch (e) {}
    });
  }

  function initAuthRipples() {
    document.addEventListener("click", function (e) {
      const btn = e.target.closest(".auth-submit-btn, .theme-toggle-btn");
      if (!btn) return;

      const rect = btn.getBoundingClientRect();
      const ripple = document.createElement("span");
      ripple.className = "aegis-shield-ripple";

      const size = Math.max(rect.width, rect.height) * 1.5;
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;

      ripple.style.width = size + "px";
      ripple.style.height = size + "px";
      ripple.style.left = x + "px";
      ripple.style.top = y + "px";

      btn.style.position = btn.style.position || "relative";
      btn.style.overflow = "hidden";
      btn.appendChild(ripple);

      setTimeout(() => {
        if (ripple.parentNode) ripple.parentNode.removeChild(ripple);
      }, 500);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
