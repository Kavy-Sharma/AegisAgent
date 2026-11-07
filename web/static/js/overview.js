/**
 * AegisAgent Overview Page Controller — Formal Security Ledger
 *
 * Polls /api/overview and audit records.
 * Renders:
 * - Live summary subtitle sentence
 * - 3 stat figures (Decisions, Stopped, Waiting for approval)
 * - Expandable "Latest decisions" list with inline Decision Rail
 * - Most triggered detection rules ranked list
 * - Bottom collapsed simulation controls
 *
 * Strict CSP: 0 innerHTML, DOM APIs only (replaceChildren, createElement, textContent)
 */

(function () {
  "use strict";

  let pollTimer = null;
  let expandedRowId = null;
  let activeEnv = "smart_home";
  let activeHwMode = "virtual";

  function init() {
    initHardwareControls();
    pollData();
    pollTimer = setInterval(pollData, 2000);

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) {
        pollData();
      }
    });
  }

  async function pollData() {
    if (document.hidden) return;
    try {
      const overviewData = await AegisAPI.getOverview();
      if (!overviewData) return;

      if (overviewData.show_hardware_panel === false || overviewData.office_sandbox) {
        activeEnv = "office";
      } else {
        activeEnv = "smart_home";
      }
      activeHwMode = overviewData.hardware_mode || "virtual";

      // Try fetching audit entries (admin gets full historical stream)
      let auditData = null;
      try {
        const auditRes = await fetch("/api/audit/entries?limit=15");
        if (auditRes.ok) {
          auditData = await auditRes.json();
        }
      } catch (_e) {
        // Guest or unpermitted; fall back to overview telemetry
      }

      let blockedCountData = null;
      try {
        const blockedRes = await fetch("/api/audit/entries?decision=BLOCKED&limit=1");
        if (blockedRes.ok) {
          blockedCountData = await blockedRes.json();
        }
      } catch (_e) {}

      updateTelemetry(overviewData, auditData, blockedCountData);
    } catch (err) {
      console.warn("Overview polling error:", err);
    }
  }

  function formatTime(isoStr) {
    if (!isoStr) return "--:--:-- IST";
    try {
      const dt = new Date(isoStr);
      if (isNaN(dt.getTime())) return isoStr;
      return dt.toLocaleTimeString("en-IN", {
        timeZone: "Asia/Kolkata",
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }) + " IST";
    } catch (_e) {
      return isoStr;
    }
  }

  function getPlainSummary(entry) {
    if (entry.plain_summary) return entry.plain_summary;
    if (entry.prompt) {
      const p = String(entry.prompt).trim();
      if (p.length > 55) return p.slice(0, 52) + "...";
      return p;
    }
    if (entry.reason) return entry.reason;
    if (entry.tool) {
      const t = String(entry.tool);
      if (t === "light_on") return "Turned on living room light";
      if (t === "light_off") return "Turned off living room light";
      if (t === "unlock_door") return "Unlocked door solenoid";
      if (t === "alarm_on") return "Sounded siren alarm";
      if (t === "alert_blocked") return "Triggered blocked alert LED";
      return "Executed tool: " + t;
    }
    return "Gateway decision logged";
  }

  function getOutcomeChip(decisionStr, stoppedAt) {
    const dec = String(decisionStr || "").toUpperCase();
    const chip = document.createElement("span");

    if (dec === "ALLOW" || dec === "ALLOWED" || dec === "EXECUTE") {
      chip.className = "pill pill-ok text-xs";
      chip.textContent = "Allowed";
    } else if (dec === "WAITING" || dec === "REVIEW" || dec === "PENDING") {
      chip.className = "pill pill-warn text-xs";
      chip.textContent = "Waiting for approval";
    } else {
      chip.className = "pill pill-danger text-xs";
      if (stoppedAt) {
        const s = String(stoppedAt).toLowerCase();
        if (s.includes("output")) chip.textContent = "Blocked at Output Scan";
        else if (s.includes("detect") || s.includes("injection")) chip.textContent = "Blocked at Detection";
        else if (s.includes("intent")) chip.textContent = "Blocked at Intent Lock";
        else if (s.includes("role") || s.includes("rbac")) chip.textContent = "Blocked at Role";
        else if (s.includes("rate")) chip.textContent = "Blocked at Rate Limit";
        else if (s.includes("approval")) chip.textContent = "Denied by Operator";
        else chip.textContent = "Blocked";
      } else {
        chip.textContent = "Blocked";
      }
    }
    return chip;
  }

  function updateTelemetry(overview, audit, blockedData) {
    const kpis = overview.kpis || {};

    // 1. Calculate counts
    let totalDecisions = 0;
    let stoppedDecisions = 0;
    let isAllTime = false;

    if (audit && audit.total_lines !== undefined && audit.total_lines > 0) {
      totalDecisions = audit.total_lines;
      isAllTime = true;
      if (blockedData && blockedData.total_matching !== undefined) {
        stoppedDecisions = blockedData.total_matching;
      } else if (kpis.blocked_attacks) {
        stoppedDecisions = kpis.blocked_attacks.value || 0;
      }
    } else if (kpis.requests_last_hour) {
      totalDecisions = kpis.requests_last_hour.value || 0;
      stoppedDecisions = (kpis.blocked_attacks && kpis.blocked_attacks.value) || 0;
      isAllTime = false;
    }

    const pendingCount = (kpis.pending_approvals && kpis.pending_approvals.value) || 0;

    // 2. Update Live Subtitle Sentence
    const summaryEl = document.getElementById("overview-live-summary");
    if (summaryEl) {
      if (totalDecisions === 0) {
        summaryEl.textContent = "No data yet.";
      } else {
        const envName = activeEnv === "office" ? "Office Assistant" : "simulated Smart Home";
        summaryEl.textContent = "Protecting a " + envName + ". " + stoppedDecisions + " of " + totalDecisions + " logged decisions were stopped.";
      }
    }

    // 3. Update 3 Stat Figures
    const decLabel = document.getElementById("stat-decisions-label");
    const stoppedLabel = document.getElementById("stat-stopped-label");
    if (decLabel) decLabel.textContent = isAllTime ? "Decisions (All time)" : "Decisions (Last hour)";
    if (stoppedLabel) stoppedLabel.textContent = isAllTime ? "Stopped (All time)" : "Stopped (Last hour)";

    setText("stat-decisions-val", totalDecisions);
    setText("stat-stopped-val", stoppedDecisions);
    setText("stat-waiting-val", pendingCount);

    const waitingCard = document.getElementById("stat-waiting-card");
    if (waitingCard) {
      if (pendingCount > 0) {
        waitingCard.classList.add("stat-card-active-warn");
      } else {
        waitingCard.classList.remove("stat-card-active-warn");
      }
    }

    // 4. Update Decisions List
    let decisions = [];
    if (audit && audit.entries && audit.entries.length > 0) {
      decisions = audit.entries;
    } else if (overview.recent_alerts && overview.recent_alerts.length > 0) {
      decisions = overview.recent_alerts.map(function (a) {
        return {
          id: a.id,
          timestamp: a.timestamp,
          decision: a.decision,
          rule_id: a.rule_id,
          reason: a.reason,
          tool: (a.event && a.event.tool) || "--",
          role: (a.event && a.event.role) || "guest",
          plain_summary: a.reason || "Security policy event"
        };
      });
    } else if (overview.last_request) {
      const lr = overview.last_request;
      decisions = [{
        id: lr.id,
        timestamp: new Date().toISOString(),
        decision: lr.decision,
        rule_id: lr.rule_id || "--",
        reason: lr.reason || "",
        tool: lr.tool || "action",
        role: lr.role || "guest",
        plain_summary: lr.prompt || lr.reason || ("Tool: " + lr.tool)
      }];
    }

    renderDecisionsList(decisions);

    // 5. Update Ranked Detection Rules
    renderTopRules(overview.top_rules || []);

    // 6. Update Office Sandbox counters if applicable
    if (overview.office_sandbox) {
      const sb = overview.office_sandbox;
      setText("sandbox-metric-outbox", sb.outbox !== undefined ? sb.outbox : (sb.outbox_count || 0));
      setText("sandbox-metric-files", sb.files !== undefined ? sb.files : (sb.files_count || 0));
      setText("sandbox-metric-sql", sb.sql_rows !== undefined ? sb.sql_rows : (sb.sql_rows_count || 0));
    }
  }

  function renderDecisionsList(decisions) {
    const listEl = document.getElementById("decisions-list");
    const loadingEl = document.getElementById("decisions-loading");
    const emptyEl = document.getElementById("decisions-empty");
    if (!listEl) return;

    if (loadingEl) loadingEl.hidden = true;

    if (!decisions || decisions.length === 0) {
      if (emptyEl) emptyEl.hidden = false;
      if (listEl.replaceChildren) {
        listEl.replaceChildren();
      } else {
        listEl.textContent = "";
      }
      return;
    }

    if (emptyEl) emptyEl.hidden = true;

    const fragment = document.createDocumentFragment();

    decisions.forEach(function (dec, idx) {
      const rowId = "decision-row-" + (dec.id || idx);
      const isExpanded = (expandedRowId === rowId);

      const row = document.createElement("div");
      row.className = "decision-item" + (isExpanded ? " is-expanded" : "");
      row.id = rowId;

      // Clickable Row Header
      const header = document.createElement("div");
      header.className = "decision-row-header flex items-center justify-between";
      header.setAttribute("tabindex", "0");
      header.setAttribute("role", "button");
      header.setAttribute("aria-expanded", isExpanded ? "true" : "false");
      header.setAttribute("aria-controls", rowId + "-details");

      const left = document.createElement("div");
      left.className = "flex items-center gap-md min-w-0";

      const timeEl = document.createElement("span");
      timeEl.className = "font-mono text-xs text-muted flex-shrink-0";
      timeEl.textContent = formatTime(dec.timestamp);
      left.appendChild(timeEl);

      const summaryEl = document.createElement("span");
      summaryEl.className = "decision-summary text-sm font-medium text-ellipsis overflow-hidden whitespace-nowrap";
      summaryEl.textContent = getPlainSummary(dec);
      left.appendChild(summaryEl);

      header.appendChild(left);

      const right = document.createElement("div");
      right.className = "flex items-center gap-sm flex-shrink-0";

      const chip = getOutcomeChip(dec.decision, dec.stopped_at);
      right.appendChild(chip);

      const expandIcon = document.createElement("span");
      expandIcon.className = "expand-indicator text-muted text-xs font-mono";
      expandIcon.textContent = isExpanded ? "\u25B2" : "\u25BC";
      right.appendChild(expandIcon);

      header.appendChild(right);
      row.appendChild(header);

      // Expandable Details Body
      const details = document.createElement("div");
      details.className = "decision-row-details" + (isExpanded ? "" : " is-hidden");
      details.id = rowId + "-details";
      if (!isExpanded) details.hidden = true;

      // Mounted Decision Rail
      const railContainer = document.createElement("div");
      railContainer.className = "decision-rail-wrap p-sm bg-subtle rounded border mb-sm";
      if (window.renderDecisionRail) {
        window.renderDecisionRail(railContainer, dec, { env: activeEnv, hardwareMode: activeHwMode });
      }
      details.appendChild(railContainer);

      // Meta attributes
      const metaGrid = document.createElement("div");
      metaGrid.className = "decision-meta-grid flex gap-md text-xs text-muted";

      const roleSpan = document.createElement("span");
      roleSpan.textContent = "Role: " + (dec.role || dec.username || "guest");
      metaGrid.appendChild(roleSpan);

      const toolSpan = document.createElement("span");
      toolSpan.textContent = "Tool: " + (dec.tool || "chat");
      metaGrid.appendChild(toolSpan);

      if (dec.rule_id && dec.rule_id !== "--") {
        const ruleSpan = document.createElement("span");
        ruleSpan.className = "font-mono";
        ruleSpan.textContent = "Rule: " + dec.rule_id;
        metaGrid.appendChild(ruleSpan);
      }

      if (dec.reason) {
        const reasonSpan = document.createElement("span");
        reasonSpan.textContent = "Reason: " + dec.reason;
        metaGrid.appendChild(reasonSpan);
      }

      details.appendChild(metaGrid);
      row.appendChild(details);

      // Toggle interaction (click or Enter key)
      function toggleRow() {
        if (expandedRowId === rowId) {
          expandedRowId = null;
          row.classList.remove("is-expanded");
          details.hidden = true;
          details.classList.add("is-hidden");
          header.setAttribute("aria-expanded", "false");
          expandIcon.textContent = "\u25BC";
        } else {
          // Close previously open
          if (expandedRowId) {
            const prev = document.getElementById(expandedRowId);
            if (prev) {
              prev.classList.remove("is-expanded");
              const prevDetails = prev.querySelector(".decision-row-details");
              const prevIcon = prev.querySelector(".expand-indicator");
              const prevHeader = prev.querySelector(".decision-row-header");
              if (prevDetails) {
                prevDetails.hidden = true;
                prevDetails.classList.add("is-hidden");
              }
              if (prevIcon) prevIcon.textContent = "\u25BC";
              if (prevHeader) prevHeader.setAttribute("aria-expanded", "false");
            }
          }
          expandedRowId = rowId;
          row.classList.add("is-expanded");
          details.hidden = false;
          details.classList.remove("is-hidden");
          header.setAttribute("aria-expanded", "true");
          expandIcon.textContent = "\u25B2";
        }
      }

      header.addEventListener("click", toggleRow);
      header.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggleRow();
        }
      });

      fragment.appendChild(row);
    });

    if (listEl.replaceChildren) {
      listEl.replaceChildren(fragment);
    } else {
      listEl.textContent = "";
      listEl.appendChild(fragment);
    }
  }

  function renderTopRules(rules) {
    const listEl = document.getElementById("ranked-rules-list");
    const loadingEl = document.getElementById("rules-loading");
    const emptyEl = document.getElementById("rules-empty");
    if (!listEl) return;

    if (loadingEl) loadingEl.hidden = true;

    if (!rules || rules.length === 0) {
      if (emptyEl) emptyEl.hidden = false;
      if (listEl.replaceChildren) {
        listEl.replaceChildren();
      } else {
        listEl.textContent = "";
      }
      return;
    }

    if (emptyEl) emptyEl.hidden = true;

    const fragment = document.createDocumentFragment();

    rules.forEach(function (item, index) {
      const li = document.createElement("li");
      li.className = "ranked-rule-item flex items-center justify-between p-xs border-bottom";

      const left = document.createElement("div");
      left.className = "flex items-center gap-sm min-w-0";

      const rank = document.createElement("span");
      rank.className = "rank-num text-xs font-mono font-semibold text-muted";
      rank.textContent = (index + 1) + ".";
      left.appendChild(rank);

      const ruleId = document.createElement("span");
      ruleId.className = "rule-id font-mono text-xs font-semibold";
      ruleId.textContent = item.id;
      left.appendChild(ruleId);

      const desc = document.createElement("span");
      desc.className = "rule-desc text-xs text-muted text-ellipsis overflow-hidden whitespace-nowrap";
      desc.textContent = item.description || "Pattern matched";
      left.appendChild(desc);

      li.appendChild(left);

      const count = document.createElement("span");
      count.className = "rule-count font-mono text-xs font-bold text-accent flex-shrink-0";
      count.textContent = item.count + " hits";
      li.appendChild(count);

      fragment.appendChild(li);
    });

    if (listEl.replaceChildren) {
      listEl.replaceChildren(fragment);
    } else {
      listEl.textContent = "";
      listEl.appendChild(fragment);
    }
  }

  function setText(elemId, text) {
    const el = document.getElementById(elemId);
    if (el) el.textContent = String(text);
  }

  function initHardwareControls() {
    const buttons = document.querySelectorAll(".hw-actuate-btn");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", async function () {
        const cmd = btn.dataset.cmd;
        if (!cmd) return;
        btn.disabled = true;
        const liveMsg = document.getElementById("hw-live-msg");
        const latTag = document.getElementById("hw-latency-tag");
        if (liveMsg) liveMsg.textContent = "Dispatching command \"" + cmd + "\" to simulation...";

        try {
          const res = await AegisAPI.actuateHardware(cmd);
          if (res && res.ok) {
            const targetName = (activeHwMode === "virtual") ? "Virtual Home" : "ESP32";
            if (liveMsg) liveMsg.textContent = "[SUCCESS] Command \"" + cmd + "\" actuated in " + targetName + " in " + res.latency_ms + "ms.";
            if (latTag) latTag.textContent = res.latency_ms + "ms latency";
            if (window.AegisApp && window.AegisApp.showToast) {
              window.AegisApp.showToast("Hardware Actuation", "Command '" + cmd + "' executed in " + targetName + " (" + res.latency_ms + "ms)", "ok");
            }
          } else {
            const err = (res && res.error) || "Command rejected";
            if (liveMsg) liveMsg.textContent = "[ERROR] " + err;
            if (window.AegisApp && window.AegisApp.showToast) {
              window.AegisApp.showToast("Hardware Error", err, "danger");
            }
          }
        } catch (err) {
          if (liveMsg) liveMsg.textContent = "[ERROR] " + err.message;
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
