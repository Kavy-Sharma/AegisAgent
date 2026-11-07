/**
  AegisAgent Decision Rail Component
  Visualizes the 9-stage security pipeline for any decision:
  1. Detection -> 2. Intent lock -> 3. Model -> 4. Role -> 5. Parameters ->
  6. Rate limit -> 7. Approval -> 8. Tool / Device -> 9. Output scan

  Strictly CSP-compliant: no innerHTML, pure DOM APIs.
  Keyboard accessible: tab and arrow key navigation, explicit aria labels.
*/

(function () {
  "use strict";

  const STAGE_DEFS = [
    { id: "detection", label: "Detection", short: "Detect" },
    { id: "intent", label: "Intent lock", short: "Intent" },
    { id: "model", label: "Model", short: "Model" },
    { id: "role", label: "Role", short: "Role" },
    { id: "parameters", label: "Parameters", short: "Params" },
    { id: "rate_limit", label: "Rate limit", short: "Rate" },
    { id: "approval", label: "Approval", short: "Approval" },
    { id: "tool", label: "Tool / Device", short: "Tool" },
    { id: "output_scan", label: "Output scan", short: "Output" }
  ];

  function resolveStageStatus(decision, stageIdx, totalStages, stoppedIdx) {
    const dec = String(decision.decision || "").toUpperCase();

    if (dec === "ALLOW" || dec === "ALLOWED" || dec === "EXECUTE") {
      return "passed";
    }

    if (dec === "WAITING" || dec === "REVIEW" || dec === "PENDING") {
      if (stageIdx < 6) return "passed";
      if (stageIdx === 6) return "waiting";
      return "not_reached";
    }

    // Stopped/Blocked
    if (stageIdx < stoppedIdx) {
      return "passed";
    }
    if (stageIdx === stoppedIdx) {
      return "stopped";
    }
    return "not_reached";
  }

  function detectStoppedIndex(decision) {
    const stoppedAt = String(decision.stopped_at || decision.stage || "").toLowerCase();
    const reason = String(decision.reason || decision.error || "").toLowerCase();
    const ruleId = String(decision.rule_id || "");

    if (stoppedAt.includes("output") || reason.includes("output") || reason.includes("leak") || reason.includes("exfiltration")) {
      return 8; // Output scan
    }
    if (stoppedAt.includes("hw") || stoppedAt.includes("device") || stoppedAt.includes("hardware") || stoppedAt.includes("tool") || stoppedAt.includes("sandbox")) {
      return 7; // Tool / Device
    }
    if (stoppedAt.includes("approval") || reason.includes("denied by") || reason.includes("approval") || decision.approved === false) {
      return 6; // Approval
    }
    if (stoppedAt.includes("rate") || reason.includes("rate limit") || reason.includes("too many requests")) {
      return 5; // Rate limit
    }
    if (stoppedAt.includes("param") || stoppedAt.includes("schema") || reason.includes("parameter") || reason.includes("validation")) {
      return 4; // Parameters
    }
    if (stoppedAt.includes("rbac") || stoppedAt.includes("role") || reason.includes("role") || reason.includes("permission") || reason.includes("unauthorized") || reason.includes("guest")) {
      return 3; // Role
    }
    if (stoppedAt.includes("model") || stoppedAt.includes("llm") || stoppedAt.includes("inference")) {
      return 2; // Model
    }
    if (stoppedAt.includes("intent") || reason.includes("intent") || reason.includes("scope")) {
      return 1; // Intent lock
    }
    if (stoppedAt.includes("detect") || stoppedAt.includes("injection") || ruleId.startsWith("INJ") || reason.includes("injection") || decision.event === "injection_check") {
      return 0; // Detection
    }

    return 0;
  }

  function getDeviceStageLabel(decision, options) {
    const env = (options && options.env) || (window.AegisApp && window.AegisApp.env) || "smart_home";
    const hwMode = (options && options.hardwareMode) || (window.AegisApp && window.AegisApp.hardwareMode) || "virtual";
    if (env === "office") {
      return "Tool";
    }
    if (hwMode === "virtual" || hwMode === "simulated") {
      return "Device (simulated)";
    }
    return "Device";
  }

  /**
   * Renders the 9-stage Decision Rail inside container.
   * @param {HTMLElement} container DOM element to mount the rail inside.
   * @param {Object} decision Decision or audit event record.
   * @param {Object} [options] Optional config: { env, hardwareMode, orientation: 'horizontal'|'vertical' }
   */
  function renderDecisionRail(container, decision, options) {
    if (!container) return;
    options = options || {};

    const dec = decision || {};
    const stoppedIdx = detectStoppedIndex(dec);
    const deviceLabel = getDeviceStageLabel(dec, options);

    const rail = document.createElement("div");
    rail.className = "decision-rail" + (options.orientation === "vertical" ? " decision-rail--vertical" : "");
    rail.setAttribute("role", "list");
    rail.setAttribute("aria-label", "Decision Pipeline Rail");

    STAGE_DEFS.forEach(function (def, idx) {
      const stageName = idx === 7 ? deviceLabel : def.label;
      const status = resolveStageStatus(dec, idx, STAGE_DEFS.length, stoppedIdx);

      const stageItem = document.createElement("div");
      stageItem.className = "rail-stage rail-stage--" + status;
      stageItem.setAttribute("role", "listitem");
      stageItem.setAttribute("tabindex", "0");

      let statusDescription = "passed";
      if (status === "stopped") {
        statusDescription = "stopped here: " + (dec.reason || "Policy block");
      } else if (status === "waiting") {
        statusDescription = "waiting for human approval";
      } else if (status === "not_reached") {
        statusDescription = "not reached";
      }
      stageItem.setAttribute("aria-label", "Stage " + (idx + 1) + ": " + stageName + " (" + statusDescription + ")");

      // Stage Node (Circle dot)
      const dot = document.createElement("span");
      dot.className = "rail-dot rail-dot--" + status;
      dot.setAttribute("aria-hidden", "true");

      if (status === "passed") {
        dot.textContent = "\u2713"; // checkmark
      } else if (status === "stopped") {
        dot.textContent = "\u2715"; // X
      } else if (status === "waiting") {
        dot.textContent = "\u2022";
      } else {
        dot.textContent = String(idx + 1);
      }

      // Stage Label
      const label = document.createElement("span");
      label.className = "rail-label";
      label.textContent = stageName;

      stageItem.appendChild(dot);
      stageItem.appendChild(label);

      // Callout for stopped stage
      if (status === "stopped") {
        const callout = document.createElement("div");
        callout.className = "rail-callout";
        const reasonText = dec.reason || dec.error || "Blocked by security pipeline";
        callout.textContent = reasonText;
        stageItem.appendChild(callout);
      }

      rail.appendChild(stageItem);

      // Connector line between stages
      if (idx < STAGE_DEFS.length - 1) {
        const connector = document.createElement("div");
        connector.className = "rail-connector" + (status === "passed" && resolveStageStatus(dec, idx + 1, STAGE_DEFS.length, stoppedIdx) !== "not_reached" ? " rail-connector--active" : "");
        connector.setAttribute("aria-hidden", "true");
        rail.appendChild(connector);
      }
    });

    // Keyboard navigation (Left / Right / Up / Down)
    rail.addEventListener("keydown", function (e) {
      const stages = Array.from(rail.querySelectorAll(".rail-stage"));
      const currentIdx = stages.indexOf(document.activeElement);
      if (currentIdx === -1) return;

      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        e.preventDefault();
        const next = stages[(currentIdx + 1) % stages.length];
        if (next) next.focus();
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        e.preventDefault();
        const prev = stages[(currentIdx - 1 + stages.length) % stages.length];
        if (prev) prev.focus();
      }
    });

    if (container.replaceChildren) {
      container.replaceChildren(rail);
    } else {
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      container.appendChild(rail);
    }
  }

  window.renderDecisionRail = renderDecisionRail;
})();

