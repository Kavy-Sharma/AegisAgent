/* AegisGateLine Component
   Extracted from design_v2/proto.js.
   No data in this file. Exposed as window.AegisGateLine.
   DOM and class names kept exactly. */
(function () {
  "use strict";

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, reduce ? 0 : ms); }); }
  function h(tag, attrs) {
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
  }
  function clear(el) { el.replaceChildren(); return el; }
  function svgIcon(d, extra) {
    var ns = "http://www.w3.org/2000/svg";
    var s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
    s.setAttribute("stroke-width", "2"); s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
    s.setAttribute("aria-hidden", "true");
    [].concat(d).forEach(function (p) { var path = document.createElementNS(ns, "path"); path.setAttribute("d", p); s.append(path); });
    return s;
  }

  /* ---------- gate line ---------- */
  function createRail(host, opts) {
    opts = opts || {};
    var el = h("div", { class: "rail" + (opts.compact ? " compact" : "") + (opts.harm ? " harm" : "") });
    var track = h("div", { class: "rail-track" }, h("div", { class: "rail-fill" }));
    var fill = track.firstChild;
    var gatesEl = h("ol", { class: "rail-gates", "aria-label": "Security gates" });
    var token = h("span", { class: "token" });
    var cap = h("p", { class: "rail-caption", role: "status" });
    el.append(h("div", { class: "rail-stage" }, track, gatesEl, token), cap);
    host.append(el);
    var gates = [], labels = [], runId = 0;

    function cleanSay(str) {
      if (!str) return "";
      var s = String(str).trim();
      s = s.replace(/^Gate rule:\s*/i, "");
      s = s.replace(/^Guard blocked execution\.?\s*/i, "");
      s = s.replace(/^Stopped(\s+at\s+[^.]+)?\.\s*/i, "");
      return s.trim();
    }

    function setCaption(parts) {
      clear(cap);
      parts.forEach(function (p) { cap.append(p.tone ? h("span", { class: "tone-" + p.tone }, p.text) : p.strong ? h("strong", { text: p.text }) : document.createTextNode(p.text)); });
    }
    function xOf(i) { return gates[i].offsetLeft + gates[i].offsetWidth / 2; }
    function move(x) {
      var maxLimit = Math.max(0, gatesEl.offsetWidth - 10);
      var limit = maxLimit || x;
      var clamped = Math.min(x, limit);
      token.style.transform = "translateX(" + clamped + "px)";
      fill.style.width = clamped + "px";
    }
    function resetVisual() {
      gates.forEach(function (g) { g.className = "gate"; });
      el.classList.remove("is-stopped", "is-waiting", "is-not-done");
      token.className = "token";
      token.style.transition = "none"; move(0); void token.offsetWidth; token.style.transition = "";
      fill.style.width = "0px";
    }
    function captionFor(d) {
      if (opts.captionOverride) return opts.captionOverride(d);
      var name = (d.stop >= 0 && d.stop < labels.length) ? labels[d.stop] : "";
      var plain = cleanSay(d.say || d.text || d.why);

      if (d.kind === "allow") {
        return [
          { text: "Allowed. ", tone: "ok", strong: false },
          { text: plain || ("Passed all " + labels.length + " gates.") }
        ];
      }
      if (d.kind === "not_done") {
        return [
          { text: "Not done. ", tone: "not-done", strong: false },
          { text: plain || "Could not complete request." }
        ];
      }
      if (d.kind === "wait") {
        return [
          { text: "Waiting" + (name ? " at " + name : "") + ". ", tone: "wait" },
          { text: plain }
        ];
      }
      if (d.stop === -1 || d.stop === null || d.stop === undefined || !name) {
        return [
          { text: "Stopped. ", tone: "stop" },
          { text: "The layer was not recorded for this older entry." }
        ];
      }
      return [
        { text: "Stopped at " + name + ". ", tone: "stop" },
        { text: plain }
      ];
    }
    function paintFinal(d) {
      var isAllow = (d.kind === "allow");
      var isNotDone = (d.kind === "not_done");
      var stopIdx = (d.stop >= 0 && d.stop < gates.length) ? d.stop : (isNotDone ? Math.min(7, gates.length - 1) : -1);
      var hasStop = (stopIdx >= 0 && stopIdx < gates.length);

      gates.forEach(function (g) { g.className = "gate"; });
      el.classList.remove("is-stopped", "is-waiting", "is-not-done");

      if (isAllow) {
        gates.forEach(function (g) { g.classList.add("is-pass"); });
      } else if (hasStop) {
        gates.forEach(function (g, i) {
          if (i < stopIdx) g.classList.add("is-pass");
          else if (i === stopIdx) g.classList.add(isNotDone ? "is-not-done" : (d.kind === "wait" ? "is-wait" : "is-stop"));
          else g.classList.add("is-skip");
        });
        el.classList.add(isNotDone ? "is-not-done" : (d.kind === "wait" ? "is-waiting" : "is-stopped"));
      } else {
        // Block without recorded layer: no gate highlighted
        gates.forEach(function (g) { g.classList.add("is-skip"); });
        el.classList.add(isNotDone ? "is-not-done" : (d.kind === "wait" ? "is-waiting" : "is-stopped"));
      }
    }
    function show(d) {
      resetVisual(); paintFinal(d);
      var endX = Math.max(0, gatesEl.offsetWidth - 10);
      var tokCls = d.kind === "allow" ? "is-ok" : d.kind === "not_done" ? "is-not-done" : d.kind === "wait" ? "is-wait" : "is-stop";
      token.classList.add("on", tokCls);
      token.style.transition = "none";
      var stopIdx = (d.stop >= 0 && d.stop < gates.length) ? d.stop : (d.kind === "not_done" ? Math.min(7, gates.length - 1) : -1);
      var targetX = d.kind === "allow" ? endX : (stopIdx >= 0 ? xOf(stopIdx) : 0);
      move(targetX);
      void token.offsetWidth; token.style.transition = "";
      setCaption(captionFor(d));
    }
    function syncLive(state) {
      state = state || {};
      runId++;
      var completed = Array.isArray(state.completedGates) ? state.completedGates : [];
      var activeGate = (typeof state.activeGate === "number") ? state.activeGate : -1;
      var waiting = Boolean(state.waiting);

      var completedMap = {};
      var maxCompleted = -1;
      completed.forEach(function (idx) {
        if (typeof idx === "number" && idx >= 0 && idx < gates.length) {
          completedMap[idx] = true;
          if (idx > maxCompleted) maxCompleted = idx;
        }
      });

      el.classList.remove("is-stopped", "is-waiting", "is-not-done");
      if (waiting) el.classList.add("is-waiting");

      gates.forEach(function (g, i) {
        g.className = "gate";
        if (i === activeGate) {
          g.classList.add(waiting ? "is-wait" : "is-running");
        } else if (completedMap[i] || (activeGate >= 0 && i < activeGate)) {
          g.classList.add("is-pass");
        }
      });

      token.className = "token";
      if (activeGate >= 0 && activeGate < gates.length) {
        token.classList.add("on");
        if (waiting) token.classList.add("is-wait");
        move(xOf(activeGate));
      } else if (maxCompleted >= 0 && maxCompleted < gates.length) {
        token.classList.add("on");
        move(xOf(maxCompleted));
      } else {
        token.style.transition = "none";
        move(0);
        void token.offsetWidth;
        token.style.transition = "";
        fill.style.width = "0px";
      }

      if (state.captionParts) {
        setCaption(state.captionParts);
      } else if (state.caption) {
        setCaption([{ text: String(state.caption) }]);
      }
    }
    function settle(d) {
      d = d || {};
      runId++;
      paintFinal(d);
      token.className = "token on " + (d.kind === "allow" ? "is-ok" : d.kind === "not_done" ? "is-not-done" : d.kind === "wait" ? "is-wait" : "is-stop");
      var endX = Math.max(0, gatesEl.offsetWidth - 10);
      var stopIdx = (d.stop >= 0 && d.stop < gates.length) ? d.stop : (d.kind === "not_done" ? Math.min(7, gates.length - 1) : -1);
      var targetX = d.kind === "allow" ? endX : (stopIdx >= 0 ? xOf(stopIdx) : 0);
      move(targetX);
      setCaption(captionFor(d));
    }
    async function play(d, o) {
      o = o || {};
      var id = ++runId, speed = o.speed || 1;
      reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduce) { show(d); return; }
      resetVisual();
      setCaption([{ text: "Checking…" }]);
      token.classList.add("on");
      await sleep(80); if (id !== runId) return;
      var last = d.kind === "allow" ? gates.length - 1 : d.stop;
      if (last >= 0) {
        for (var i = 0; i <= last; i++) {
          move(xOf(i));
          await sleep(400 / speed); if (id !== runId) return;
          if (d.kind === "allow" || i < last) gates[i].classList.add("is-pass");
        }
      }
      if (d.kind === "allow") {
        var endX = Math.max(0, gatesEl.offsetWidth - 10);
        move(endX); token.classList.add("is-ok");
        await sleep(380 / speed); if (id !== runId) return;
      } else {
        if (last >= 0) {
          gates[last].classList.add(d.kind === "wait" ? "is-wait" : "is-stop");
          token.classList.add(d.kind === "wait" ? "is-wait" : "is-stop");
          for (var j = last + 1; j < gates.length; j++) gates[j].classList.add("is-skip");
        } else {
          token.classList.add(d.kind === "wait" ? "is-wait" : "is-stop");
          for (var k = 0; k < gates.length; k++) gates[k].classList.add("is-skip");
        }
        el.classList.add(d.kind === "wait" ? "is-waiting" : "is-stopped");
      }
      setCaption(captionFor(d));
    }
    function setLabels(ls) {
      labels = ls; clear(gatesEl);
      gates = ls.map(function (l, i) {
        var label = h("span", { class: "gate-label" }, ls.length > 1 ? h("span", { class: "gate-n", text: String(i + 1) }) : null, l);
        var g = h("li", { class: "gate" }, h("span", { class: "gate-bar" }), label);
        g.style.setProperty("--i", i); gatesEl.append(g); return g;
      });
      el.style.setProperty("--n", ls.length);
      resetVisual();
      setCaption([{ text: opts.idle || "Pick a decision to watch it travel through the gates." }]);
    }
    function idle() { runId++; resetVisual(); setCaption([{ text: opts.idle || "Ready." }]); }
    window.addEventListener("resize", function () {
      if (token.classList.contains("on") && el.isConnected) {
        var cur = gates.findIndex(function (g) { return g.classList.contains("is-stop") || g.classList.contains("is-wait") || g.classList.contains("is-not-done") || g.classList.contains("is-running"); });
        token.style.transition = "none";
        if (cur >= 0) {
          move(xOf(cur));
        } else if (token.classList.contains("is-ok")) {
          move(gatesEl.offsetWidth);
        }
        void token.offsetWidth;
        token.style.transition = "";
      }
    });
    var defaultLabels = ["Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval", "Device (simulated)", "Output scan"];
    setLabels(opts.labels || defaultLabels);
    return { el: el, play: play, show: show, syncLive: syncLive, settle: settle, setLabels: setLabels, setCaption: setCaption, idle: idle };
  }

  window.AegisGateLine = {
    createRail: createRail,
    h: h,
    sleep: sleep,
    clear: clear,
    svgIcon: svgIcon
  };
})();

