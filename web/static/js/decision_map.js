/**
 * AegisDecisionMap
 * Shared audit layer -> gate index mapping.
 * Canonical 0-based indexing (0..8) across Overview, Console, and Attack Lab.
 * Strictly honest: no session_id guessing.
 */
(function () {
  "use strict";

  var STAGE_MAP = {
    // Gate 0: Detection
    detection: 0,
    injection: 0,
    quarantine: 0,

    // Gate 1: Intent Lock
    intent: 1,
    intent_lock: 1,
    scope: 1,

    // Gate 2: Model
    llm: 2,
    model: 2,

    // Gate 3: Role (RBAC)
    rbac: 3,
    role: 3,

    // Gate 4: Parameters (Param Guard)
    param_guard: 4,
    parameters: 4,
    parameter: 4,

    // Gate 5: Rate limit
    rate_limit: 5,
    rate: 5,

    // Gate 6: Approval
    approval: 6,
    human: 6,

    // Gate 7: Device / Tool
    hardware: 7,
    device: 7,
    tool: 7,

    // Gate 8: Output scan
    output_scan: 8,
    output: 8
  };

  function getGateLabels(isOffice, hardwareStatus) {
    var toolLabel;
    if (isOffice) {
      toolLabel = "Tool";
    } else if (hardwareStatus && hardwareStatus !== "virtual") {
      toolLabel = "Device";
    } else {
      toolLabel = "Device (simulated)";
    }
    return [
      "Detection",
      "Intent lock",
      "Model",
      "Role",
      "Parameters",
      "Rate limit",
      "Approval",
      toolLabel,
      "Output scan"
    ];
  }

  function layerToGateIndex(layer) {
    if (!layer) return -1;
    var l = String(layer).toLowerCase().trim();
    if (l in STAGE_MAP) return STAGE_MAP[l];
    for (var k in STAGE_MAP) {
      if (l.indexOf(k) !== -1) return STAGE_MAP[k];
    }
    return -1;
  }

  function gateIndexToName(idx, isOffice, hardwareStatus) {
    var labels = getGateLabels(isOffice, hardwareStatus);
    if (idx >= 0 && idx < labels.length) return labels[idx];
    return null;
  }

  window.AegisDecisionMap = {
    STAGE_MAP: STAGE_MAP,
    getGateLabels: getGateLabels,
    layerToGateIndex: layerToGateIndex,
    gateIndexToName: gateIndexToName
  };
})();
