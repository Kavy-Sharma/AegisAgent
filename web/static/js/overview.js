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
  var allDecisions = [];
  var currentFilter = "all";
  var lastTouch = 0;
  var timer = null;
  var stageLabels = ["Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval", "Device (simulated)", "Output scan"];

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
      text = d.stage_name ? "Stopped · " + d.stage_name : "Stopped";
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
    if (!feedEl) return;
    clear(feedEl);

    var filtered = getFilteredList();
    if (!filtered.length) {
      var emptyLi = h("li", null, h("p", { class: "empty", text: "No decisions yet. Send a request in the Console or run an attack in the Attack Lab." }));
      feedEl.append(emptyLi);
      return;
    }

    filtered.forEach(function (d, i) {
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
                rail.play(d);
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
      if (rail) {
        rail.play(d);
        markLive(i);
      }
    }
  }

  function playIndex(i) {
    var filtered = getFilteredList();
    var d = filtered[i];
    if (d && rail) {
      rail.play(d);
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

  function startCycle() {
    var idx = 0;
    clearInterval(timer);
    timer = setInterval(function () {
      if (document.hidden || reduce) return;
      if (Date.now() - lastTouch < 25000) return;
      var filtered = getFilteredList();
      if (!filtered.length) return;
      idx = (idx + 1) % filtered.length;
      playIndex(idx);
    }, 7000);
  }

  function initFilterChips() {
    var chipsContainer = document.getElementById("filter-chips");
    if (!chipsContainer) return;

    chipsContainer.querySelectorAll(".chip").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var filter = btn.getAttribute("data-filter") || "all";
        currentFilter = filter;
        chipsContainer.querySelectorAll(".chip").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b.getAttribute("data-filter") === filter));
        });
        renderFeed();
        playIndex(0);
      });
    });
  }

  function initSandboxControls() {
    var doorBtn = document.getElementById("toggle-door-btn");
    if (doorBtn) {
      doorBtn.addEventListener("click", function () {
        if (typeof api !== "undefined" && api.post) {
          api.post("/api/hardware/actuate", { command: "TOGGLE_DOOR" })
            .then(function () { if (typeof showToast === "function") showToast("Door Action", "Front door command dispatched.", "info"); })
            .catch(function () {});
        }
      });
    }

    var alarmBtn = document.getElementById("toggle-alarm-btn");
    if (alarmBtn) {
      alarmBtn.addEventListener("click", function () {
        if (typeof api !== "undefined" && api.post) {
          api.post("/api/hardware/actuate", { command: "TOGGLE_ALARM" })
            .then(function () { if (typeof showToast === "function") showToast("Alarm Action", "Security alarm command dispatched.", "warn"); })
            .catch(function () {});
        }
      });
    }

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

        // Decisions
        allDecisions = data.v2_decisions || [];
        renderFeed();

        // Play the latest real decision on load
        if (allDecisions.length > 0 && rail) {
          setTimeout(function () {
            playIndex(0);
          }, 300);
        } else if (rail) {
          rail.idle();
        }

        startCycle();
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
      rail = GL.createRail(host, { idle: "Loading the latest decision…" });
    }

    initFilterChips();
    initSandboxControls();
    loadData();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
