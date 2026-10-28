/**
 * AegisAgent Overview Page Controller
 * Polls /api/overview every 2 seconds, updates KPI metrics, pure SVG charts,
 * recent alerts list, and drawer inspection.
 */

(function () {
  "use strict";

  let pollTimer = null;
  let lastData = null;

  function init() {
    initDrawer();
    initHardwareControls();
    pollOverview();
    pollTimer = setInterval(pollOverview, 2000);

    // Re-render charts on theme change
    window.addEventListener("aegis:themechange", () => {
      if (lastData) {
        renderCharts(lastData);
      }
    });

    // Re-poll immediately when returning to tab
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) {
        pollOverview();
      }
    });
  }

  async function pollOverview() {
    if (document.hidden) return;
    try {
      const data = await AegisAPI.getOverview();
      if (!data) return;
      lastData = data;
      updateKpis(data.kpis);
      renderCharts(data);
      updateAlerts(data.recent_alerts);
      updateLastRequest(data.last_request);
    } catch (err) {
      console.warn("Overview polling error:", err);
    }
  }

  function updateKpis(kpis) {
    if (!kpis) return;

    // Requests
    if (kpis.requests_last_hour) {
      updateNumberWithFade("kpi-reqs-val", kpis.requests_last_hour.value);
      setText("kpi-reqs-delta", kpis.requests_last_hour.delta || "0 vs prev hr");
      const sparkSvg = document.getElementById("sparkline-reqs");
      if (sparkSvg && kpis.requests_last_hour.sparkline && window.charts) {
        window.charts.renderSparkline(sparkSvg, kpis.requests_last_hour.sparkline, "var(--accent)");
      }
    }

    // Blocks
    if (kpis.blocked_attacks) {
      updateNumberWithFade("kpi-blocks-val", kpis.blocked_attacks.value);
      setText("kpi-blocks-delta", kpis.blocked_attacks.delta || "0 vs prev hr");
      const sparkSvg = document.getElementById("sparkline-blocks");
      if (sparkSvg && kpis.blocked_attacks.sparkline && window.charts) {
        window.charts.renderSparkline(sparkSvg, kpis.blocked_attacks.sparkline, "var(--danger)");
      }
    }

    // Pending Approvals
    if (kpis.pending_approvals) {
      updateNumberWithFade("kpi-pending-val", kpis.pending_approvals.value);
      setText("kpi-pending-delta", kpis.pending_approvals.delta || "Real-time queue");
    }

    // Device Status
    if (kpis.device_status) {
      const dot = document.getElementById("kpi-device-dot");
      const val = document.getElementById("kpi-device-val");
      const hint = document.getElementById("kpi-device-hint");
      const st = kpis.device_status.status;

      if (dot) dot.className = `pulse-dot ${st === "online" ? "live" : (st === "offline" ? "offline" : "unknown")}`;
      if (val) val.textContent = st === "online" ? "Online" : (st === "offline" ? "Offline" : "Unknown");
      if (hint) hint.textContent = kpis.device_status.hint || "Hardware Link";
    }
  }

  function updateNumberWithFade(elemId, newVal) {
    const el = document.getElementById(elemId);
    if (!el) return;
    if (el.textContent !== String(newVal)) {
      el.classList.add("fade-out");
      setTimeout(() => {
        el.textContent = newVal;
        el.classList.remove("fade-out");
      }, 150);
    }
  }

  function setText(elemId, text) {
    const el = document.getElementById(elemId);
    if (el) el.textContent = text;
  }

  function renderCharts(data) {
    if (!window.charts) return;

    if (data.timeline) {
      window.charts.renderDecisionTimeline("timeline-chart-container", data.timeline);
    }

    if (data.top_rules) {
      window.charts.renderTopRules("top-rules-container", data.top_rules);
    }
  }

  function updateAlerts(alerts) {
    const container = document.getElementById("recent-alerts-list");
    if (!container) return;

    if (!alerts || alerts.length === 0) {
      container.innerHTML = "";
      const empty = document.createElement("div");
      empty.className = "empty-state";
      const t1 = document.createElement("div");
      t1.className = "empty-title";
      t1.textContent = "Clean Inspection State";
      const t2 = document.createElement("div");
      t2.className = "empty-hint";
      t2.textContent = "No recent security alerts recorded. Operating in clean state.";
      empty.appendChild(t1);
      empty.appendChild(t2);
      container.appendChild(empty);
      return;
    }

    container.innerHTML = "";
    alerts.forEach((alert) => {
      const row = document.createElement("div");
      row.className = "alert-row flex items-center justify-between";
      row.addEventListener("click", () => openDrawer(alert.event));

      const left = document.createElement("div");
      left.className = "flex items-center gap-sm";

      const pill = document.createElement("span");
      const dec = (alert.decision || "BLOCK").toUpperCase();
      pill.className = dec === "BLOCK" ? "pill pill-danger text-xs" : "pill pill-warn text-xs";
      pill.textContent = dec;
      left.appendChild(pill);

      const rule = document.createElement("span");
      rule.className = "font-mono text-xs font-semibold";
      rule.textContent = alert.rule_id || "--";
      left.appendChild(rule);

      const reason = document.createElement("span");
      reason.className = "alert-reason text-xs text-muted";
      reason.textContent = alert.reason || "Rule triggered";
      left.appendChild(reason);

      row.appendChild(left);

      const timeSpan = document.createElement("span");
      timeSpan.className = "font-mono text-xs text-muted";
      timeSpan.textContent = alert.time_ist || "--";
      row.appendChild(timeSpan);

      container.appendChild(row);
    });
  }

  function updateLastRequest(req) {
    const idEl = document.getElementById("last-req-id");
    const stEl = document.getElementById("last-req-status");

    if (!req) {
      if (idEl) idEl.textContent = "No requests yet";
      if (stEl) {
        stEl.textContent = "Idle";
        stEl.className = "pill pill-muted text-xs";
      }
      return;
    }

    if (idEl) idEl.textContent = `Req: ${(req.id || "").slice(0, 16)} (${req.tool || "action"})`;
    if (stEl) {
      stEl.textContent = req.decision || "--";
      stEl.className = req.decision === "BLOCK" ? "pill pill-danger text-xs" : "pill pill-ok text-xs";
    }
  }

  function initDrawer() {
    const backdrop = document.getElementById("alert-drawer-backdrop");
    const closeBtn = document.getElementById("drawer-close-btn");

    if (closeBtn) {
      closeBtn.addEventListener("click", closeDrawer);
    }
    if (backdrop) {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeDrawer();
      });
    }
  }

  function openDrawer(eventObj) {
    const backdrop = document.getElementById("alert-drawer-backdrop");
    const pre = document.getElementById("drawer-json-pre");
    if (!backdrop || !pre) return;

    pre.textContent = JSON.stringify(eventObj || {}, null, 2);
    backdrop.classList.add("is-open");
  }

  function closeDrawer() {
    const backdrop = document.getElementById("alert-drawer-backdrop");
    if (backdrop) backdrop.classList.remove("is-open");
  }

  function initHardwareControls() {
    const buttons = document.querySelectorAll(".hw-actuate-btn");
    buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const cmd = btn.dataset.cmd;
        if (!cmd) return;
        btn.disabled = true;
        const liveMsg = document.getElementById("hw-live-msg");
        const latTag = document.getElementById("hw-latency-tag");
        if (liveMsg) liveMsg.textContent = `Dispatching command "${cmd}" to hardware...`;

        try {
          const res = await AegisAPI.actuateHardware(cmd);
          if (res && res.ok) {
            if (liveMsg) liveMsg.textContent = `[SUCCESS] Command "${cmd}" actuated on ESP32 in ${res.latency_ms}ms.`;
            if (latTag) latTag.textContent = `${res.latency_ms}ms latency`;
            if (window.AegisApp && window.AegisApp.showToast) {
              window.AegisApp.showToast("Hardware Actuation", `Hardware command '${cmd}' executed (${res.latency_ms}ms)`, "ok");
            }
          } else {
            const err = (res && res.error) || "Command rejected";
            if (liveMsg) liveMsg.textContent = `[ERROR] ${err}`;
            if (window.AegisApp && window.AegisApp.showToast) {
              window.AegisApp.showToast("Hardware Error", err, "danger");
            }
          }
        } catch (err) {
          if (liveMsg) liveMsg.textContent = `[ERROR] ${err.message}`;
          if (window.AegisApp && window.AegisApp.showToast) {
            window.AegisApp.showToast("Hardware Error", err.message, "danger");
          }
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
