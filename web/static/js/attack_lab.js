/**
 * AegisAgent Attack Lab Controller (v2)
 * Dual-lane side-by-side execution (Without Aegis vs With Aegis 9-gate rail)
 * with synchronized scenario clips, smart one-shot scroll, and plain audit reasons.
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
      kids.forEach(function (c) {
        if (c == null || c === false) return;
        e.append(c.nodeType ? c : document.createTextNode(c));
      });
    }
    return e;
  };
  var clear = GL.clear || function (el) { el.replaceChildren(); return el; };
  var sleep = GL.sleep || function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  var DM = window.AegisDecisionMap || {};
  var speed = 1;
  var scenarios = [];
  var selectedIndex = 0;
  var runningScenarioIndex = -1;
  var isRunning = false;
  var isOffice = (document.body && document.body.dataset ? document.body.dataset.env === "office" : false);
  var hwStatus = (document.body && document.body.dataset ? (document.body.dataset.hwStatus || "virtual") : "virtual");
  var stageLabels = (DM.getGateLabels && DM.getGateLabels(isOffice, hwStatus)) || [
    "Detection", "Intent lock", "Model", "Role", "Parameters",
    "Rate limit", "Approval", "Device (simulated)", "Output scan"
  ];

  var tally = { runs: 0, open: 0, breached: 0 };
  var runHistory = [];

  var railA = null;
  var railB = null;
  var sbNodesA = [];
  var sbNodesB = [];

  var CLIP_IDS = {
    direct_override: true,
    memo_subtle: true,
    memo_obvious: true,
    guest_alarm: true,
    admin_unlock: true
  };

  function prefersReducedMotion() {
    return Boolean(
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function getHeaderBottom() {
    var hdr = document.querySelector("header.top");
    return hdr ? Math.ceil(hdr.getBoundingClientRect().bottom) : 61;
  }

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
    if (!container) return [];
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
      var b = n.querySelector("b");
      if (b) b.textContent = val;
    });
  }

  function setSandboxHarm(nodes, targetIndex, harmVal) {
    if (!nodes[targetIndex]) return;
    var n = nodes[targetIndex];
    n.className = "sb harm";
    var b = n.querySelector("b");
    if (b) b.textContent = harmVal;
  }

  function updateScoreboard() {
    var openEl = document.getElementById("s-open");
    var heldEl = document.getElementById("s-held");
    var totalOpenEl = document.getElementById("s-total-open");
    var totalHeldEl = document.getElementById("s-total-held");
    if (openEl) openEl.textContent = String(tally.open);
    if (totalOpenEl) totalOpenEl.textContent = String(tally.runs);
    if (heldEl) heldEl.textContent = String(tally.breached);
    if (totalHeldEl) totalHeldEl.textContent = String(tally.runs);
  }

  function renderHistory() {
    var ul = document.getElementById("hist");
    if (!ul) return;
    clear(ul);

    if (!runHistory.length) {
      ul.append(h("li", { class: "empty", text: "Run history appears here. Pick an attack and press Run attack." }));
      return;
    }

    runHistory.slice(0, 5).forEach(function (item) {
      ul.append(h("li", null,
        h("span", { class: "mono text-muted", text: item.time }),
        h("span", { text: item.title + ": " + item.result })
      ));
    });
  }

  function syncPlayButtonState(videoEl, btnEl, laneLabel) {
    if (!videoEl || !btnEl) return;
    var playing = !videoEl.paused && !videoEl.ended;
    btnEl.classList.toggle("is-playing", playing);
    var act = playing ? "Pause " : "Play ";
    btnEl.setAttribute("aria-label", act + laneLabel + " clip");
    btnEl.setAttribute("title", playing ? "Pause" : "Play");
  }

  function bindVideoControls(videoId, playBtnId, replayBtnId, laneLabel) {
    var videoEl = document.getElementById(videoId);
    var playBtn = document.getElementById(playBtnId);
    var replayBtn = document.getElementById(replayBtnId);
    if (!videoEl) return;

    function sync() {
      syncPlayButtonState(videoEl, playBtn, laneLabel);
    }

    ["play", "pause", "ended", "loadeddata"].forEach(function (ev) {
      videoEl.addEventListener(ev, sync);
    });

    if (playBtn) {
      playBtn.addEventListener("click", function () {
        if (!videoEl.getAttribute("src")) return;
        if (videoEl.paused || videoEl.ended) {
          if (videoEl.ended) {
            try { videoEl.currentTime = 0; } catch (e) {}
          }
          videoEl.playbackRate = speed;
          videoEl.play().catch(function () {});
        } else {
          videoEl.pause();
        }
      });
    }

    if (replayBtn) {
      replayBtn.addEventListener("click", function () {
        if (!videoEl.getAttribute("src")) return;
        try { videoEl.currentTime = 0; } catch (e) {}
        videoEl.playbackRate = speed;
        videoEl.play().catch(function () {});
      });
    }
  }

  function setupLaneVideo(mediaId, videoId, playBtnId, src, laneLabel) {
    var box = document.getElementById(mediaId);
    var videoEl = document.getElementById(videoId);
    var playBtn = document.getElementById(playBtnId);
    if (!box || !videoEl) return;

    if (!src) {
      box.setAttribute("hidden", "");
      try { videoEl.pause(); } catch (e) {}
      videoEl.removeAttribute("src");
      videoEl.removeAttribute("data-current-src");
      videoEl.load();
      syncPlayButtonState(videoEl, playBtn, laneLabel);
      return;
    }

    box.removeAttribute("hidden");
    videoEl.loop = false;
    videoEl.muted = true;
    videoEl.playsInline = true;
    videoEl.playbackRate = speed;

    if (videoEl.getAttribute("data-current-src") !== src) {
      videoEl.setAttribute("data-current-src", src);
      videoEl.src = src;
      videoEl.load();
    } else {
      try { videoEl.currentTime = 0; } catch (e) {}
    }
    try { videoEl.pause(); } catch (e) {}
    syncPlayButtonState(videoEl, playBtn, laneLabel);
  }

  function loadScenarioMediaPaused(scenario) {
    var hasClip = Boolean(scenario && !isOffice && CLIP_IDS[scenario.id]);
    var unprotSrc = hasClip ? ("/static/videos/attack_lab/unprotected_" + scenario.id + ".mp4") : "";
    var protSrc = hasClip ? ("/static/videos/attack_lab/protected_" + scenario.id + ".mp4") : "";

    setupLaneVideo("media-without", "video-without", "btn-play-without", unprotSrc, "Without Aegis");
    setupLaneVideo("media-with", "video-with", "btn-play-with", protSrc, "With Aegis");

    var noteEl = document.getElementById("lab-video-note");
    if (noteEl) {
      if (hasClip) noteEl.removeAttribute("hidden");
      else noteEl.setAttribute("hidden", "");
    }
  }

  function startVideosForRun(scenario) {
    if (prefersReducedMotion()) return;
    if (!scenario || isOffice || !CLIP_IDS[scenario.id]) return;

    ["video-without", "video-with"].forEach(function (id) {
      var v = document.getElementById(id);
      if (!v || !v.getAttribute("src")) return;
      v.loop = false;
      v.muted = true;
      v.playsInline = true;
      v.playbackRate = speed;
      try { v.currentTime = 0; } catch (e) {}
      v.play().catch(function () {});
    });
  }

  function updateScenarioListHighlight() {
    var list = document.getElementById("scenario-list");
    if (!list) return;
    list.querySelectorAll(".scn").forEach(function (btn, i) {
      btn.setAttribute("aria-pressed", String(i === selectedIndex));
      var activeRun = (runningScenarioIndex === i);
      btn.classList.toggle("is-running", activeRun);
      if (activeRun) btn.setAttribute("aria-current", "step");
      else btn.removeAttribute("aria-current");
    });
  }

  function selectScenario(idx) {
    selectedIndex = idx;
    updateScenarioListHighlight();

    var s = scenarios[idx];
    if (!s) return;

    var titleEl = document.getElementById("current-scenario-title");
    var promptEl = document.getElementById("attack-prompt");
    if (titleEl) titleEl.textContent = s.title;
    if (promptEl) promptEl.textContent = s.prompt;

    loadScenarioMediaPaused(s);

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
          if (!isRunning) selectScenario(i);
        }
      },
        h("small", { text: cat }),
        h("b", { text: s.title }),
        h("span", { text: s.desc || (s.prompt ? s.prompt.slice(0, 60) + "…" : "") })
      );
      list.append(h("li", null, btn));
    });

    selectScenario(selectedIndex);
  }

  function deriveProtectedCaption(resultData, gateName) {
    var prot = (resultData && resultData.protected) || {};
    var fin = prot.final || {};
    if (prot.plain_reason) return String(prot.plain_reason);
    if (fin.reply && fin.reply !== "[tool output withheld by AegisAgent]") return String(fin.reply);
    var steps = Array.isArray(prot.steps) ? prot.steps : [];
    for (var i = 0; i < steps.length; i++) {
      var st = steps[i];
      if (st && (st.status === "block" || st.status === "deny" || st.status === "error")) {
        if (st.detail && st.detail.reason) return String(st.detail.reason);
      }
    }
    return "Stopped at " + gateName + " by security policy.";
  }

  function scrollCardsIntoViewOnce() {
    var lanesEl = document.getElementById("lab-lanes");
    var stageEl = document.getElementById("lab-stage");
    var headEl = document.getElementById("lab-head");
    if (!lanesEl) return;

    var headerBottom = getHeaderBottom();
    var vh = window.innerHeight || document.documentElement.clientHeight || 900;
    var vw = window.innerWidth || document.documentElement.clientWidth || 1360;
    var lanesRect = lanesEl.getBoundingClientRect();

    // Only scroll if the two cards are not already completely inside the visible viewport
    if (lanesRect.top >= headerBottom + 8 && lanesRect.bottom <= vh - 8) {
      return;
    }

    var behavior = prefersReducedMotion() ? "auto" : "smooth";

    // At 1360x900 desktop, never scroll past the scenario title/prompt box
    if (vw >= 960 && headEl && stageEl) {
      var headRect = headEl.getBoundingClientRect();
      var combinedHeight = lanesRect.bottom - headRect.top;
      if (combinedHeight <= (vh - headerBottom - 20)) {
        stageEl.scrollIntoView({ behavior: behavior, block: "start" });
        return;
      }
      var maxAllowedScroll = Math.max(0, headRect.top - (headerBottom + 16));
      var minNeededScroll = Math.max(0, lanesRect.bottom - (vh - 16));
      if (minNeededScroll <= maxAllowedScroll && minNeededScroll > 0) {
        window.scrollBy({ top: minNeededScroll, behavior: behavior });
        return;
      }
    }

    lanesEl.scrollIntoView({ behavior: behavior, block: "start" });
  }

  function nudgeScoreboardIfHidden() {
    var scoreEl = document.getElementById("lab-score");
    if (!scoreEl) return;
    var headerBottom = getHeaderBottom();
    var vh = window.innerHeight || document.documentElement.clientHeight || 900;
    var vw = window.innerWidth || document.documentElement.clientWidth || 1360;
    var r = scoreEl.getBoundingClientRect();
    if (r.top >= headerBottom + 4 && r.bottom <= vh - 4) return;
    var behavior = prefersReducedMotion() ? "auto" : "smooth";
    if (r.bottom > vh - 4) {
      var delta = Math.ceil(r.bottom - vh + 16);
      if (vw >= 960) {
        var headEl = document.getElementById("lab-head");
        if (headEl) {
          var maxAllowed = Math.max(0, Math.floor(headEl.getBoundingClientRect().top - (headerBottom + 12)));
          delta = Math.min(delta, maxAllowed);
        }
      }
      if (delta > 0) window.scrollBy({ top: delta, behavior: behavior });
    } else if (r.top < headerBottom + 4) {
      window.scrollBy({ top: Math.floor(r.top - headerBottom - 16), behavior: behavior });
    }
  }

  async function runSingleAttack(s) {
    var titleEl = document.getElementById("current-scenario-title");
    var promptEl = document.getElementById("attack-prompt");
    if (titleEl) titleEl.textContent = s.title;
    if (promptEl) promptEl.textContent = s.prompt;

    resetSandbox(sbNodesA);
    resetSandbox(sbNodesB);
    startVideosForRun(s);

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
      try {
        var pollRes = await api.get("/api/attack_lab/result/" + encodeURIComponent(reqId));
        if (pollRes && pollRes.status === "completed" && pollRes.result) {
          resultData = pollRes.result;
          break;
        }
      } catch (err) {
        console.warn("Lab result polling error:", err);
      }
      await sleep(250 / speed);
    }

    if (!resultData) return;

    var harmIdx = 0;
    if (s.id.indexOf("alarm") !== -1) harmIdx = 1;
    else if (s.id.indexOf("light") !== -1) harmIdx = 2;
    else if (s.id.indexOf("sql") !== -1) harmIdx = 2;
    else if (s.id.indexOf("path") !== -1) harmIdx = 1;
    else if (s.id.indexOf("honey") !== -1) harmIdx = 3;

    var base = getBaseSandbox();
    var harmText = base[harmIdx] ? base[harmIdx].harm : "Compromised";

    var prot = resultData.protected || {};
    var protFin = prot.final || {};
    var protDec = String(protFin.decision || "BLOCK").toUpperCase();
    var isAllow = (protDec === "ALLOW" || protDec === "DIRECT_ALLOW");
    var isWait = (protDec === "REVIEW" || protDec === "WAITING");

    var stoppedLayer = resultData.stopped_layer || prot.stopped_layer || prot.stopped_at || "detection";
    var stopIdx = isAllow ? -1 : (DM.layerToGateIndex ? DM.layerToGateIndex(stoppedLayer) : 0);
    if (!isAllow && stopIdx < 0) stopIdx = 0;
    var gateName = (stopIdx >= 0 && stageLabels[stopIdx]) ? stageLabels[stopIdx] : "Detection";
    var plainReason = deriveProtectedCaption(resultData, gateName);

    var unprotTask = (async function () {
      var p = railA.play({
        kind: "allow",
        stop: -1,
        why: "Nothing checked it. The agent's command went straight to the tool."
      }, { speed: speed });
      await sleep(550 / speed);
      setSandboxHarm(sbNodesA, harmIdx, harmText);
      await p;
    })();

    var protTask = railB.play({
      kind: isAllow ? "allow" : (isWait ? "wait" : "stop"),
      stop: stopIdx,
      say: plainReason,
      why: plainReason
    }, { speed: speed });

    await Promise.all([unprotTask, protTask]);

    var unprotFin = (resultData.unprotected && resultData.unprotected.final) || {};
    var unprotSucceeded = unprotFin.decision
      ? (String(unprotFin.decision).toUpperCase() !== "BLOCK")
      : (String(resultData.unprotected_outcome || "").toLowerCase().indexOf("block") === -1);

    tally.runs++;
    if (unprotSucceeded) tally.open++;
    if (isAllow) tally.breached++;
    updateScoreboard();

    var now = new Date();
    var timeStr = now.toTimeString().slice(0, 8);
    runHistory.unshift({
      time: timeStr,
      title: s.title,
      result: (unprotSucceeded ? "harm without Aegis, " : "stopped without Aegis, ") +
        (isAllow ? "allowed by Aegis" : ("stopped at " + gateName + " with Aegis"))
    });
    renderHistory();
  }

  async function handleRunOne() {
    if (isRunning || !scenarios.length) return;
    isRunning = true;
    runningScenarioIndex = selectedIndex;
    updateScenarioListHighlight();
    setButtonsDisabled(true);
    scrollCardsIntoViewOnce();

    try {
      await runSingleAttack(scenarios[selectedIndex]);
      nudgeScoreboardIfHidden();
    } finally {
      runningScenarioIndex = -1;
      isRunning = false;
      updateScenarioListHighlight();
      setButtonsDisabled(false);
    }
  }

  async function handleRunAll() {
    if (isRunning || !scenarios.length) return;
    isRunning = true;
    setButtonsDisabled(true);
    scrollCardsIntoViewOnce();

    try {
      for (var i = 0; i < scenarios.length; i++) {
        runningScenarioIndex = i;
        selectScenario(i);
        var activeBtn = document.querySelector("#scenario-list .scn.is-running");
        if (activeBtn && activeBtn.scrollIntoView) {
          activeBtn.scrollIntoView({ block: "nearest", behavior: "auto" });
        }
        await runSingleAttack(scenarios[i]);
        await sleep(900 / speed);
      }
      nudgeScoreboardIfHidden();
    } finally {
      runningScenarioIndex = -1;
      isRunning = false;
      updateScenarioListHighlight();
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
        ["video-without", "video-with"].forEach(function (id) {
          var v = document.getElementById(id);
          if (v) v.playbackRate = speed;
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
        compact: true,
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
        compact: true,
        idle: "Ready to run."
      });
    }

    bindVideoControls("video-without", "btn-play-without", "btn-replay-without", "Without Aegis");
    bindVideoControls("video-with", "btn-play-with", "btn-replay-with", "With Aegis");
    initSpeedSeg();
    updateScoreboard();

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
