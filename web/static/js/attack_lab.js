/**
 * AegisAgent Attack Lab Controller (v2)
 * Dual-lane execution (Without Aegis harm lane vs With Aegis 9-gate rail).
 * Pure DOM, zero innerHTML, zero inline styles.
 */
(function () {
  "use strict";

  var GL = window.AegisGateLine || {};
  var h = GL.h || function (tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var kids = [].concat(arguments[i]);
      kids.forEach(function (c) { if (c == null || c === false) return; e.append(c.nodeType ? c : document.createTextNode(c)); });
    }
    return e;
  };
  var clear = GL.clear || function (el) { el.replaceChildren(); return el; };
  var sleep = GL.sleep || function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  var DM = window.AegisDecisionMap || {};
  var speed = 1;
  var scenarios = [];
  var selectedIndex = 0;
  var isRunning = false;
  var isOffice = (document.body && document.body.dataset ? document.body.dataset.env === "office" : false);
  var hwStatus = (document.body && document.body.dataset ? (document.body.dataset.hwStatus || "virtual") : "virtual");
  var stageLabels = (DM.getGateLabels && DM.getGateLabels(isOffice, hwStatus)) || ["Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval", "Device (simulated)", "Output scan"];

  var tally = { runs: 0, open: 0, held: 0 };
  var runHistory = [];

  var railA = null;
  var railB = null;
  var sbNodesA = [];
  var sbNodesB = [];

  function getBaseSandbox() {
    if (isOffice) {
      return [
        { label: "Outbox", safe: "0 sent", harm: "Email sent" },
        { label: "Files", safe: "3 intact", harm: "File exfiltrated" },
        { label: "Database", safe: "12 rows", harm: "Table dropped" },
        { label: "Exports", safe: "0 leaked", harm: "Decoy exported" }
      ];
    }
    return [
      { label: "Front Door", safe: "Locked", harm: "Unlocked" },
      { label: "Security Alarm", safe: "Disarmed", harm: "Sounding" },
      { label: "Living Room Light", safe: "Off", harm: "On" },
      { label: "Thermostat", safe: "22°C", harm: "Overridden" }
    ];
  }

  function renderSandbox(container) {
    clear(container);
    var base = getBaseSandbox();
    var nodes = [];
    base.forEach(function (item) {
      var node = h("div", { class: "sb safe" },
        h("span", { text: item.label }),
        h("b", { text: item.safe })
      );
      container.append(node);
      nodes.push(node);
    });
    return nodes;
  }

  function resetSandbox(nodes) {
    var base = getBaseSandbox();
    nodes.forEach(function (n, idx) {
      n.className = "sb safe";
      var val = base[idx] ? base[idx].safe : "Safe";
      n.querySelector("b").textContent = val;
    });
  }

  function setSandboxHarm(nodes, targetIndex, harmVal) {
    if (!nodes[targetIndex]) return;
    var n = nodes[targetIndex];
    n.className = "sb harm";
    n.querySelector("b").textContent = harmVal;
  }

  function updateScoreboard() {
    var openEl = document.getElementById("s-open");
    var heldEl = document.getElementById("s-held");
    if (!openEl || !heldEl) return;

    if (tally.runs === 0) {
      openEl.textContent = "No runs yet";
      heldEl.textContent = "No runs yet";
    } else {
      openEl.textContent = tally.open + " of " + tally.runs;
      heldEl.textContent = (tally.runs - tally.held) + " of " + tally.runs;
    }
  }

  function renderHistory() {
    var ul = document.getElementById("hist");
    if (!ul) return;
    clear(ul);

    if (!runHistory.length) {
      ul.append(h("li", { class: "empty", text: "Run history appears here. Pick an attack and press Run attack." }));
      return;
    }

    runHistory.slice(0, 10).forEach(function (item) {
      ul.append(h("li", null,
        h("span", { class: "mono text-muted", text: item.time }),
        h("span", { text: item.title + ": " + item.result })
      ));
    });
  }

  function selectScenario(idx, userSelected) {
    selectedIndex = idx;
    var list = document.getElementById("scenario-list");
    if (list) {
      list.querySelectorAll(".scn").forEach(function (btn, i) {
        btn.setAttribute("aria-pressed", String(i === idx));
      });
    }

    var s = scenarios[idx];
    if (!s) return;

    var titleEl = document.getElementById("current-scenario-title");
    var promptEl = document.getElementById("attack-prompt");
    if (titleEl) titleEl.textContent = s.title;
    if (promptEl) promptEl.textContent = s.prompt;

    var mediaBox = document.getElementById("lab-media");
    var videoEl = document.getElementById("lab-video");

    var videoMap = {
      "direct_override": "/static/videos/attack_lab/unprotected_direct_override.mp4",
      "memo_subtle": "/static/videos/attack_lab/unprotected_memo_subtle.mp4",
      "memo_obvious": "/static/videos/attack_lab/unprotected_memo_obvious.mp4",
      "guest_alarm": "/static/videos/attack_lab/unprotected_guest_alarm.mp4",
      "admin_unlock": "/static/videos/attack_lab/unprotected_admin_unlock.mp4"
    };

    var videoSrc = videoMap[s.id];
    if (mediaBox && videoEl) {
      if (videoSrc) {
        mediaBox.removeAttribute("hidden");
        if (videoEl.getAttribute("data-current-src") !== videoSrc) {
          videoEl.setAttribute("data-current-src", videoSrc);
          videoEl.src = videoSrc;
          videoEl.load();
        }
        var prefersReduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        if (userSelected && !prefersReduced) {
          videoEl.play().catch(function () {});
        } else {
          videoEl.pause();
        }
      } else {
        mediaBox.setAttribute("hidden", "");
        videoEl.pause();
      }
    }

    if (railA) railA.idle();
    if (railB) railB.idle();
    resetSandbox(sbNodesA);
    resetSandbox(sbNodesB);
  }

  function renderScenarioList() {
    var list = document.getElementById("scenario-list");
    var runAllBtn = document.getElementById("btn-run-all");
    if (!list) return;
    clear(list);

    if (runAllBtn) {
      runAllBtn.textContent = "Run all " + scenarios.length;
    }

    scenarios.forEach(function (s, i) {
      var cat = s.category || (isOffice ? "Office Security" : "Smart Home");
      var btn = h("button", {
        class: "scn",
        type: "button",
        "aria-pressed": String(i === selectedIndex),
        onclick: function () {
          if (!isRunning) selectScenario(i, true);
        }
      },
        h("small", { text: cat }),
        h("b", { text: s.title }),
        h("span", { text: s.desc || s.prompt.slice(0, 60) + "…" })
      );
      list.append(h("li", null, btn));
    });

    selectScenario(selectedIndex, false);
  }

  async function runSingleAttack(s) {
    var titleEl = document.getElementById("current-scenario-title");
    var promptEl = document.getElementById("attack-prompt");
    if (titleEl) titleEl.textContent = s.title;
    if (promptEl) promptEl.textContent = s.prompt;

    resetSandbox(sbNodesA);
    resetSandbox(sbNodesB);

    if (typeof api !== "undefined" && api.post) {
      try {
        await api.post("/api/console/new_session", {});
      } catch (e) {}
    }

    var runRes;
    try {
      runRes = await api.post("/api/attack_lab/run", { scenario_id: s.id });
    } catch (e) {
      console.warn("Lab run request failed:", e);
      return;
    }

    if (!runRes || !runRes.req_id) return;
    var reqId = runRes.req_id;

    var pollStart = Date.now();
    var resultData = null;

    while (Date.now() - pollStart < 60000) {
      await sleep(500 / speed);
      try {
        var pollRes = await api.get("/api/attack_lab/result/" + encodeURIComponent(reqId));
        if (pollRes && pollRes.status === "completed" && pollRes.result) {
          resultData = pollRes.result;
          break;
        }
      } catch (err) {
        console.warn("Lab result polling error:", err);
      }
    }

    if (!resultData) return;

    // 1. Without Aegis Execution
    var unprotOutcome = resultData.unprotected_outcome || "Executed without guard";
    var harmIdx = 0;
    if (s.id.indexOf("alarm") !== -1) harmIdx = 1;
    else if (s.id.indexOf("light") !== -1) harmIdx = 2;
    else if (s.id.indexOf("sql") !== -1) harmIdx = 2;
    else if (s.id.indexOf("path") !== -1) harmIdx = 1;
    else if (s.id.indexOf("honey") !== -1) harmIdx = 3;

    var base = getBaseSandbox();
    var harmText = base[harmIdx] ? base[harmIdx].harm : "Compromised";

    var unprotPromise = railA.play({
      kind: "allow",
      stop: -1,
      why: "Unprotected agent called tool directly."
    }, { speed: speed });

    await sleep(700 / speed);
    setSandboxHarm(sbNodesA, harmIdx, harmText);
    await unprotPromise;

    // 2. With Aegis Execution
    var stoppedLayer = resultData.stopped_layer || (resultData.protected && (resultData.protected.stopped_layer || resultData.protected.stopped_at)) || "detection";
    var stopIdx = DM.layerToGateIndex ? DM.layerToGateIndex(stoppedLayer) : 0;
    if (stopIdx === -1) stopIdx = 0;
    var gateName = stageLabels[stopIdx] || "Detection";

    await railB.play({
      kind: "stop",
      stop: stopIdx,
      why: "Stopped at " + gateName + ". Guard blocked execution."
    }, { speed: speed });

    // Update tally & history
    tally.runs++;
    tally.open++;
    tally.held++;
    updateScoreboard();

    var now = new Date();
    var timeStr = now.toTimeString().slice(0, 8);
    runHistory.unshift({
      time: timeStr,
      title: s.title,
      result: "harm without Aegis, stopped at " + gateName + " with Aegis"
    });
    renderHistory();
  }

  function scrollToElement(sel, block) {
    var el = document.querySelector(sel);
    if (el && el.scrollIntoView) {
      var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: block || "start" });
    }
  }

  async function handleRunOne() {
    if (isRunning || !scenarios.length) return;
    isRunning = true;
    setButtonsDisabled(true);
    scrollToElement(".lanes", "start");

    try {
      await runSingleAttack(scenarios[selectedIndex]);
      scrollToElement(".score", "nearest");
    } finally {
      isRunning = false;
      setButtonsDisabled(false);
    }
  }

  async function handleRunAll() {
    if (isRunning || !scenarios.length) return;
    isRunning = true;
    setButtonsDisabled(true);
    scrollToElement(".lanes", "start");

    try {
      for (var i = 0; i < scenarios.length; i++) {
        selectScenario(i, true);
        await runSingleAttack(scenarios[i]);
        await sleep(1000 / speed);
      }
      scrollToElement(".score", "nearest");
    } finally {
      isRunning = false;
      setButtonsDisabled(false);
    }
  }

  function setButtonsDisabled(disabled) {
    var runBtn = document.getElementById("btn-run-one");
    var allBtn = document.getElementById("btn-run-all");
    if (runBtn) runBtn.disabled = disabled;
    if (allBtn) allBtn.disabled = disabled;
  }

  function initSpeedSeg() {
    var seg = document.getElementById("speed-seg");
    if (!seg) return;
    seg.querySelectorAll("button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var spdVal = parseInt(btn.getAttribute("data-speed") || "1", 10);
        speed = spdVal;
        seg.querySelectorAll("button").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b.getAttribute("data-speed") === String(spdVal)));
        });
      });
    });
  }

  async function loadScenarios() {
    if (typeof api === "undefined" || !api.get) return;
    try {
      var res = await api.get("/api/attack_lab/scenarios");
      if (res && res.scenarios) {
        scenarios = res.scenarios;
        isOffice = (res.environment === "office");
        hwStatus = res.hardware_status || (document.body && document.body.dataset ? document.body.dataset.hwStatus : "virtual") || "virtual";
        stageLabels = (DM.getGateLabels && DM.getGateLabels(isOffice, hwStatus)) || stageLabels;

        if (railA) railA.setLabels([isOffice ? "Tool" : (hwStatus !== "virtual" ? "Device" : "Device (simulated)")]);
        if (railB) railB.setLabels(stageLabels);

        sbNodesA = renderSandbox(document.getElementById("sandbox-without"));
        sbNodesB = renderSandbox(document.getElementById("sandbox-with"));

        renderScenarioList();
      }
    } catch (err) {
      console.warn("Failed to load attack lab scenarios:", err);
    }
  }

  function init() {
    var hostA = document.getElementById("rail-without");
    var hostB = document.getElementById("rail-with");

    if (hostA && GL.createRail) {
      railA = GL.createRail(hostA, {
        harm: true,
        labels: [isOffice ? "Tool" : (hwStatus !== "virtual" ? "Device" : "Device (simulated)")],
        idle: "Ready to run.",
        captionOverride: function () {
          return [
            { text: "Nothing checked it. ", tone: "stop" },
            { text: "The agent's command went straight to the tool." }
          ];
        }
      });
    }

    if (hostB && GL.createRail) {
      railB = GL.createRail(hostB, {
        idle: "Ready to run."
      });
    }

    initSpeedSeg();

    var runOneBtn = document.getElementById("btn-run-one");
    if (runOneBtn) runOneBtn.addEventListener("click", handleRunOne);

    var runAllBtn = document.getElementById("btn-run-all");
    if (runAllBtn) runAllBtn.addEventListener("click", handleRunAll);

    loadScenarios();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
