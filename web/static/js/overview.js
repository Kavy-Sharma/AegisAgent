/**
 * AegisAgent Overview Controller (v2)
 * Pure DOM via window.AegisGateLine (h, clear, sleep, svgIcon).
 * Zero innerHTML, zero inline styles.
 */
(function () {
  "use strict";

  var GL = window.AegisGateLine || {};
  var h = GL.h;
  var clear = GL.clear;
  var svgIcon = GL.svgIcon;

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var ICON_REPLAY = ["M3 12a9 9 0 1 0 3-6.7", "M3 4v5h5"];

  var rail = null;
  var headTitle = null;
  var headMeta = null;
  var allDecisions = [];
  var currentFilter = "all";
  var visibleCount = 8;
  var pageSize = 8;
  var lastTouch = 0;
  var timer = null;
  var envName = (document.body && document.body.dataset ? document.body.dataset.env : "smart_home") || "smart_home";
  var hwStatus = (document.body && document.body.dataset ? document.body.dataset.hwStatus : "virtual") || "virtual";
  var stageLabels = (window.AegisDecisionMap && window.AegisDecisionMap.getGateLabels(envName === "office", hwStatus)) || ["Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval", "Device (simulated)", "Output scan"];

  function railPlay(d) {
    if (headTitle && d) {
      headTitle.textContent = d.say || d.text || "Latest decision";
      headMeta.textContent = (d.t || "") + " · " + (d.tool || "none") + " · " + (d.role || "unknown");
    }
    if (rail && d) rail.play(d, { speed: 1.5 });
  }

  function findLatestDecision(kind, stopGate) {
    for (var i = 0; i < allDecisions.length; i++) {
      var d = allDecisions[i];
      if (kind === "allow" && d.kind === "allow") return d;
      if (kind === "wait" && (d.kind === "wait" || d.stop === 6)) return d;
      if (kind === "stop" && d.kind === "stop") {
        if (stopGate === undefined || stopGate === null || d.stop === stopGate) return d;
      }
    }
    return null;
  }

  function updateReplayChips() {
    var container = document.getElementById("rail-replay-chips");
    if (!container) return;

    var mappings = {
      "allow": function () { return findLatestDecision("allow"); },
      "detection": function () { return findLatestDecision("stop", 0); },
      "role": function () { return findLatestDecision("stop", 3); },
      "approval": function () { return findLatestDecision("wait"); },
      "output_scan": function () { return findLatestDecision("stop", 8); }
    };

    container.querySelectorAll(".chip").forEach(function (btn) {
      var type = btn.getAttribute("data-replay");
      var fn = mappings[type];
      var hasMatch = fn && fn() !== null;
      btn.disabled = !hasMatch;
      if (!hasMatch) {
        btn.classList.add("disabled");
        btn.setAttribute("aria-disabled", "true");
      } else {
        btn.classList.remove("disabled");
        btn.removeAttribute("aria-disabled");
      }
    });
  }

  function initReplayChips() {
    var container = document.getElementById("rail-replay-chips");
    if (!container) return;

    var mappings = {
      "allow": function () { return findLatestDecision("allow"); },
      "detection": function () { return findLatestDecision("stop", 0); },
      "role": function () { return findLatestDecision("stop", 3); },
      "approval": function () { return findLatestDecision("wait"); },
      "output_scan": function () { return findLatestDecision("stop", 8); }
    };

    container.querySelectorAll(".chip").forEach(function (btn) {
      var type = btn.getAttribute("data-replay");
      var fn = mappings[type];
      btn.addEventListener("click", function () {
        if (fn) {
          var target = fn();
          if (target && rail) {
            touch();
            railPlay(target);
            var host = document.getElementById("rail-host");
            if (host && host.scrollIntoView) {
              host.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
            }
          }
        }
      });
    });
  }

  function renderGateChart(bars) {
    var chartEl = document.getElementById("gate-chart");
    if (!chartEl || !bars || !bars.length) return;
    clear(chartEl);

    var maxCount = 0;
    bars.forEach(function (b) {
      if (b.count > maxCount) maxCount = b.count;
    });

    bars.forEach(function (item) {
      var pct = maxCount > 0 ? Math.round((item.count / maxCount) * 100) : 0;
      var label = item.index >= 0 ? (item.index + 1) + ". " + item.gate : item.gate;
      var fillEl = h("div", { class: "gate-chart-fill" + (item.index === -1 ? " unrecorded" : (item.count > 0 ? " has-stops" : "")) });
      fillEl.style.width = Math.max(pct, (item.count > 0 ? 3 : 0)) + "%";

      var row = h("div", { class: "gate-chart-row" },
        h("span", { class: "gate-chart-label", text: label }),
        h("div", { class: "gate-chart-track" }, fillEl),
        h("span", { class: "gate-chart-count mono", text: String(item.count) })
      );
      chartEl.append(row);
    });
  }

  function renderBenchmark(bench) {
    if (!bench) return;
    var attEl = document.getElementById("bench-attacks");
    var reachEl = document.getElementById("bench-reached");
    var benEl = document.getElementById("bench-benign");

    var attTried = bench.attacks_tried != null ? bench.attacks_tried : 110;
    var attTotal = bench.attacks_total != null ? bench.attacks_total : attTried;
    var reachCount = bench.reached_door_alarm != null ? bench.reached_door_alarm : 0;
    var benAllowed = bench.benign_allowed != null ? bench.benign_allowed : 87;
    var benTotal = bench.benign_total != null ? bench.benign_total : 116;

    if (attEl) attEl.textContent = attTried + " of " + attTotal;
    if (reachEl) reachEl.textContent = reachCount + " of " + attTotal;
    if (benEl) benEl.textContent = benAllowed + " of " + benTotal;
  }

  function touch() {
    lastTouch = Date.now();
  }

  function countUp(el, to) {
    if (!el) return;
    if (reduce) {
      el.textContent = Number(to).toLocaleString();
      return;
    }
    var t0 = performance.now();
    var dur = 900;
    (function tick(t) {
      var p = Math.min(1, (t - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(to * e).toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }

  function outcomeNode(d) {
    var cls = d.kind === "allow" ? "ok" : d.kind;
    var text;
    if (d.kind === "allow") {
      text = "Allowed";
    } else if (d.kind === "wait") {
      text = "Waiting · Approval";
    } else {
      var sName = d.stage_name || ((d.stop >= 0 && d.stop < stageLabels.length) ? stageLabels[d.stop] : null);
      text = sName ? "Stopped · " + sName : "Stopped";
    }
    return h("span", { class: "out " + cls }, h("i"), text);
  }

  function getFilteredList() {
    return allDecisions.filter(function (d) {
      if (currentFilter === "all") return true;
      return d.kind === currentFilter;
    });
  }

  function renderFeed() {
    var feedEl = document.getElementById("decisions-feed");
    var moreWrap = document.getElementById("feed-more-wrap");
    if (!feedEl) return;
    clear(feedEl);

    var filtered = getFilteredList();
    if (!filtered.length) {
      var emptyLi = h("li", null, h("p", { class: "empty", text: "No decisions yet. Send a request in the Console or run an attack in the Attack Lab." }));
      feedEl.append(emptyLi);
      if (moreWrap) moreWrap.setAttribute("hidden", "");
      return;
    }

    var visible = filtered.slice(0, visibleCount);
    visible.forEach(function (d, i) {
      var li = h("li", null);
      var row = h("button", {
        class: "row",
        type: "button",
        "aria-expanded": "false",
        onclick: function () {
          touch();
          toggleDetail(i, li, d);
        }
      },
        h("span", { class: "t mono", text: d.t || "--" }),
        outcomeNode(d),
        h("span", { class: "txt", text: d.text || "" }),
        h("span", { class: "tool mono", text: d.tool || "none" })
      );
      li.append(row);
      feedEl.append(li);
    });

    if (moreWrap) {
      if (filtered.length > visibleCount) {
        moreWrap.removeAttribute("hidden");
      } else {
        moreWrap.setAttribute("hidden", "");
      }
    }
  }

  function toggleDetail(i, li, d) {
    var feedEl = document.getElementById("decisions-feed");
    var row = li.querySelector(".row");
    if (!row) return;

    var open = row.getAttribute("aria-expanded") === "true";
    if (feedEl) {
      feedEl.querySelectorAll(".detail").forEach(function (x) { x.remove(); });
      feedEl.querySelectorAll(".row").forEach(function (r) { r.setAttribute("aria-expanded", "false"); });
    }

    if (!open) {
      row.setAttribute("aria-expanded", "true");
      var detailEl = h("div", { class: "detail" },
        h("dl", null,
          h("div", null, h("dt", { text: "Reason" }), h("dd", { text: d.why || "Security check" })),
          h("div", null, h("dt", { text: "Role" }), h("dd", { text: d.role || "admin" })),
          h("div", null, h("dt", { text: "Tool" }), h("dd", { class: "mono", text: d.tool || "none" })),
          h("div", null, h("dt", { text: "Rule" }), h("dd", { class: "mono", text: d.rule || "none" }))
        ),
        h("div", null,
          h("button", {
            class: "btn",
            type: "button",
            onclick: function () {
              if (rail) {
                railPlay(d);
                var host = document.getElementById("rail-host");
                if (host && host.scrollIntoView) {
                  host.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
                }
              }
            }
          },
            svgIcon(ICON_REPLAY),
            "Replay on the gate line"
          )
        )
      );
      li.append(detailEl);
    }
    if (rail) {
      railPlay(d);
      markLive(i);
    }
  }

  function playIndex(i) {
    var filtered = getFilteredList();
    var d = filtered[i];
    if (d && rail) {
      railPlay(d);
      markLive(i);
    }
  }

  function markLive(i) {
    var feedEl = document.getElementById("decisions-feed");
    var rows = feedEl ? feedEl.querySelectorAll(".row") : [];
    rows.forEach(function (r) { r.classList.remove("is-live"); });
    if (rows[i]) {
      void rows[i].offsetWidth;
      rows[i].classList.add("is-live");
    }
  }


  function initFilterChips() {
    var chipsContainer = document.getElementById("filter-chips");
    if (!chipsContainer) return;

    chipsContainer.querySelectorAll(".chip").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var filter = btn.getAttribute("data-filter") || "all";
        currentFilter = filter;
        visibleCount = 8;
        chipsContainer.querySelectorAll(".chip").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b.getAttribute("data-filter") === filter));
        });
        renderFeed();
        playIndex(0);
      });
    });
  }

  function initPagination() {
    var moreBtn = document.getElementById("btn-show-more");
    if (moreBtn) {
      moreBtn.addEventListener("click", function () {
        visibleCount += 8;
        renderFeed();
      });
    }
  }

  function setSandboxFeedback(kind, text, linkHref, linkLabel) {
    var fb = document.getElementById("sandbox-feedback");
    if (!fb) return;
    fb.className = "sandbox-feedback";
    if (kind === "ok") fb.classList.add("is-ok");
    else if (kind === "wait") fb.classList.add("is-wait");
    else if (kind === "bad") fb.classList.add("is-bad");
    while (fb.firstChild) fb.removeChild(fb.firstChild);
    fb.appendChild(document.createTextNode(text));
    if (linkHref && linkLabel) {
      var a = document.createElement("a");
      a.className = "sandbox-feedback-link";
      a.href = linkHref;
      a.textContent = linkLabel;
      fb.appendChild(a);
    }
  }

  function applyHardwareStatusUI(st) {
    if (!st) return;
    var summaryEl = document.getElementById("sandbox-details-summary");
    var statusBar = document.getElementById("hw-status-bar");
    var envName = (statusBar && statusBar.dataset && statusBar.dataset.env) || "smart_home";
    var hwStatus = st.hardware_status || (st.simulated || st.hardware_mode === "virtual" ? "virtual" : (st.online ? "connected" : "unreachable"));

    if (summaryEl && envName !== "office") {
      summaryEl.textContent = hwStatus === "virtual" ? "Virtual Home controls (testing)" : "Hardware controls (testing)";
    }

    var pill = document.getElementById("hw-conn-pill");
    if (pill) {
      pill.className = "hw-state-badge";
      if (hwStatus === "virtual") {
        pill.textContent = "Virtual Home (simulation)";
      } else if (hwStatus === "connected") {
        pill.classList.add("is-ok");
        var portTxt = st.port && st.port !== "virtual" && st.port !== "unknown" ? " · " + st.port : "";
        pill.textContent = (st.hardware_mode === "usb" ? "USB Serial" : "Hardware") + portTxt + " (online)";
      } else {
        pill.classList.add("is-bad");
        var offPort = st.port && st.port !== "virtual" && st.port !== "unknown" ? " · " + st.port : "";
        pill.textContent = (st.hardware_mode === "usb" ? "USB Serial" : "Hardware") + offPort + " (unreachable)";
      }
    }

    var chips = document.getElementById("hw-state-chips");
    if (chips) {
      if (st.simulated && st.device_state) {
        chips.classList.remove("is-hidden");
        var lightEl = document.getElementById("hw-state-light");
        if (lightEl) {
          var lOn = !!st.device_state.light_on;
          lightEl.textContent = "Light: " + (lOn ? "On" : "Off");
          lightEl.className = "hw-state-badge" + (lOn ? " is-ok" : "");
        }
        var doorEl = document.getElementById("hw-state-door");
        if (doorEl) {
          var dOpen = st.device_state.door_locked === false || st.device_state.door === "unlocked";
          doorEl.textContent = "Door: " + (dOpen ? "Unlocked" : "Locked");
          doorEl.className = "hw-state-badge" + (dOpen ? " is-warn" : "");
        }
        var alarmEl = document.getElementById("hw-state-alarm");
        if (alarmEl) {
          var aOn = !!st.device_state.alarm_on;
          alarmEl.textContent = "Alarm: " + (aOn ? "Sounding" : "Off");
          alarmEl.className = "hw-state-badge" + (aOn ? " is-bad" : "");
        }
      } else {
        chips.classList.add("is-hidden");
      }
    }

    var useVirtBtn = document.getElementById("hw-use-virtual-btn");
    if (useVirtBtn) {
      useVirtBtn.classList.toggle("is-hidden", hwStatus === "virtual");
    }
    var detectUsbBtn = document.getElementById("hw-detect-usb-btn");
    if (detectUsbBtn) {
      detectUsbBtn.classList.toggle("is-hidden", hwStatus !== "virtual");
    }
  }

  function refreshHardwareStatus() {
    if (typeof api === "undefined" || !api.get) return Promise.resolve();
    if (!document.getElementById("hw-status-bar")) return Promise.resolve();
    return api.get("/api/hardware/status")
      .then(applyHardwareStatusUI)
      .catch(function () {});
  }

  function initSandboxControls() {
    var detailsEl = document.getElementById("sandbox-details");
    if (detailsEl) {
      var hwButtons = detailsEl.querySelectorAll("[data-hw-cmd]");
      Array.prototype.forEach.call(hwButtons, function (btn) {
        btn.addEventListener("click", function () {
          if (typeof api === "undefined" || !api.post) return;
          var cmd = btn.getAttribute("data-hw-cmd");
          var body = { command: cmd };
          var blinkRaw = btn.getAttribute("data-blink-count");
          var durRaw = btn.getAttribute("data-duration-seconds");
          if (blinkRaw) {
            body.args = { blink_count: parseInt(blinkRaw, 10) };
          } else if (durRaw) {
            body.args = { duration_seconds: parseInt(durRaw, 10) };
          }

          btn.disabled = true;
          api.post("/api/hardware/actuate", body)
            .then(function (res) {
              btn.disabled = false;
              if (res && res.status === "pending_approval") {
                var waitMsg = "Approval required for '" + cmd + "' (" + (res.request_id || "pending") + "). ";
                setSandboxFeedback("wait", waitMsg, "/approvals", "Review in Approvals \u2192");
                if (typeof showToast === "function") showToast("Approval Required", res.message || waitMsg, "warn");
              } else {
                var okMsg = (res && res.message) || ("Command '" + cmd + "' executed.");
                setSandboxFeedback("ok", okMsg);
                if (res && res.device_state) {
                  applyHardwareStatusUI({ simulated: true, hardware_mode: "virtual", hardware_status: "virtual", device_state: res.device_state });
                } else {
                  refreshHardwareStatus();
                }
                if (typeof showToast === "function") showToast("Hardware Action", okMsg, "info");
              }
            })
            .catch(function (err) {
              btn.disabled = false;
              var errMsg = (err && err.message) || "Hardware actuation failed.";
              setSandboxFeedback("bad", errMsg);
              if (typeof showToast === "function") showToast("Action Failed", errMsg, "error");
            });
        });
      });
    }

    var refreshBtn = document.getElementById("hw-refresh-btn");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        refreshBtn.disabled = true;
        refreshHardwareStatus().then(function () {
          refreshBtn.disabled = false;
          setSandboxFeedback("ok", "Device status refreshed.");
        });
      });
    }

    ["hw-use-virtual-btn", "hw-detect-usb-btn"].forEach(function (btnId) {
      var modeBtn = document.getElementById(btnId);
      if (!modeBtn) return;
      modeBtn.addEventListener("click", function () {
        if (typeof api === "undefined" || !api.post) return;
        var mode = modeBtn.getAttribute("data-hw-mode") || "virtual";
        modeBtn.disabled = true;
        api.post("/api/hardware/mode", { mode: mode })
          .then(function (res) {
            modeBtn.disabled = false;
            applyHardwareStatusUI(res);
            if (typeof window.__aegisRefreshHealth === "function") window.__aegisRefreshHealth();
            var msg = (res && res.hardware_status === "connected")
              ? ("Connected to USB hardware on " + (res.port || "USB") + ".")
              : (res && res.hardware_status === "virtual"
                ? (mode === "auto" ? "No USB hardware detected; running Virtual Home (simulation)." : "Switched to Virtual Home (simulation).")
                : "Hardware status updated.");
            setSandboxFeedback("ok", msg);
            if (typeof showToast === "function") showToast("Hardware Mode", msg, "info");
          })
          .catch(function (err) {
            modeBtn.disabled = false;
            var errMsg = (err && err.message) || "Could not switch hardware mode.";
            setSandboxFeedback("bad", errMsg);
            if (typeof showToast === "function") showToast("Mode Switch Failed", errMsg, "error");
          });
      });
    });

    var resetBtn = document.getElementById("reset-sandbox-btn");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        if (typeof api !== "undefined" && api.post) {
          api.post("/api/console/new_session", {})
            .then(function () { if (typeof showToast === "function") showToast("Sandbox", "Sandbox state reset.", "info"); })
            .catch(function () {});
        }
      });
    }

    window.addEventListener("aegis:health", function () {
      refreshHardwareStatus();
    });
    refreshHardwareStatus();
  }

  function loadData() {
    if (typeof api === "undefined" || !api.get) return;

    api.get("/api/overview")
      .then(function (data) {
        if (!data) return;

        // Stage labels from environment
        if (data.v2_stage_labels && rail) {
          stageLabels = data.v2_stage_labels;
          rail.setLabels(stageLabels);
        }

        // Figures
        var figs = data.v2_figures || {};
        countUp(document.getElementById("f-total"), figs.total || 0);
        countUp(document.getElementById("f-stop"), figs.stopped || 0);
        var waitEl = document.getElementById("f-wait");
        if (waitEl) waitEl.textContent = String(figs.waiting || 0);

        // Where requests stop
        if (data.v2_where_requests_stop) {
          renderGateChart(data.v2_where_requests_stop);
        }

        // Benchmark
        if (data.v2_benchmark) {
          renderBenchmark(data.v2_benchmark);
        }

        // Decisions
        allDecisions = data.v2_decisions || [];
        updateReplayChips();
        renderFeed();

        // Play the latest real decision on load and rest on final state
        if (allDecisions.length > 0 && rail) {
          setTimeout(function () {
            playIndex(0);
          }, 150);
        } else if (rail) {
          rail.idle();
        }
      })
      .catch(function (err) {
        var feedEl = document.getElementById("decisions-feed");
        if (feedEl) {
          clear(feedEl);
          feedEl.append(h("li", null, h("p", { class: "empty", text: "Failed to load decisions telemetry." })));
        }
      });
  }

  function init() {
    var host = document.getElementById("rail-host");
    if (host && GL.createRail) {
      clear(host);
      headTitle = h("h2", { text: "Latest decision" });
      headMeta = h("span", { class: "mono", text: "" });
      host.append(h("div", { class: "rail-head" }, headTitle, headMeta));
      rail = GL.createRail(host, { idle: "Loading the latest decision…" });
    }

    initFilterChips();
    initPagination();
    initReplayChips();
    initSandboxControls();
    loadData();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
