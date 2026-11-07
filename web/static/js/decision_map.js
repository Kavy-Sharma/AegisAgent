/**
 * AegisDecisionMap
 * Shared audit layer -> gate index mapping.
 * Used across Overview, Console, and Attack Lab.
 */
(function () {
  "use strict";

  var STAGE_MAP = {
    detection: 0,
    injection: 0,
    quarantine: 0,
    inj: 0,
    direct_override: 0,
    override: 0,
    intent: 1,
    intent_lock: 1,
    scope: 1,
    memo_subtle: 1,
    hidden: 1,
    llm: 2,
    model: 2,
    rbac: 3,
    role: 3,
    guest: 3,
    honey: 3,
    honeypot: 3,
    param_guard: 4,
    parameters: 4,
    parameter: 4,
    path: 4,
    sql: 4,
    param: 4,
    rate_limit: 5,
    rate: 5,
    approval: 6,
    human: 6,
    hardware: 7,
    device: 7,
    tool: 7,
    output_scan: 8,
    output: 8,
    poison: 8,
    memo_obvious: 8
  };

  function getGateLabels(isOffice) {
    var toolLabel = isOffice ? "Tool" : "Device (simulated)";
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

  function gateIndexToName(idx, isOffice) {
    var labels = getGateLabels(isOffice);
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
