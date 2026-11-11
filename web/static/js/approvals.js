/**
 * AegisAgent Approvals Controller (v2)
 * Pure DOM, zero innerHTML, zero inline styles.
 * Polls pending queue & decision history with live server countdowns.
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

  var currentPending = [];
  var currentHistory = [];
  var activeFilter = "all";
  var countdownMap = {};
  var pollTimer = null;
  var tickTimer = null;

  function renderPending(items) {
    var container = document.getElementById("pending-container");
    if (!container) return;
    clear(container);

    if (!items || !items.length) {
      container.append(h("p", { class: "empty", id: "pending-empty", text: "Nothing is waiting for approval." }));
      return;
    }

    items.forEach(function (p) {
      var reqId = p.request_id;
      var tool = String(p.tool || "action");
      var total = p.timeout_seconds || 60;
      var remaining = Math.max(0, Math.round(p.expires_in_seconds != null ? p.expires_in_seconds : total));
      countdownMap[reqId] = { rem: remaining, total: total };

      var barFill = h("i");
      barFill.style.setProperty("--p", String(remaining / total));
      var bar = h("div", { class: "bar" }, barFill);

      var timerText = h("p", {
        class: "mono",
        id: "timer-" + reqId,
        text: "Waiting for a human OK. Expires in " + remaining + " s."
      });

      var plainDesc = p.plain_summary || ("Operation '" + tool.replace(/_/g, " ") + "' held for supervisor confirmation.");

      var rawArgs = (p.args && typeof p.args === "object" && !Array.isArray(p.args)) ? p.args : {};
      var argKeys = Object.keys(rawArgs).slice(0, 6);
      var argLines = argKeys.length
        ? argKeys.map(function (k) {
            var v = rawArgs[k];
            var vStr = (v !== null && typeof v === "object") ? JSON.stringify(v) : String(v == null ? "" : v);
            if (vStr.length > 60) vStr = vStr.slice(0, 60);
            return h("div", { class: "mono", text: k + ": " + vStr });
          })
        : [h("div", { class: "mono", text: "No parameters" })];
      var argsBox = h("div", null, argLines);

      var card = h("div", { class: "approve", id: "approve-card-" + reqId },
        h("div", { class: "flex justify-between items-center" },
          h("h3", { text: tool.replace(/_/g, " ") }),
          timerText
        ),
        h("p", { text: plainDesc }),
        argsBox,
        bar,
        h("div", { class: "btns" },
          h("button", {
            class: "btn good",
            type: "button",
            onclick: function () { decideRequest(p, true); }
          }, "Approve"),
          h("button", {
            class: "btn danger",
            type: "button",
            onclick: function () { decideRequest(p, false); }
          }, "Deny")
        )
      );

      container.append(card);
    });
  }

  async function decideRequest(p, approved) {
    var card = document.getElementById("approve-card-" + p.request_id);
    var btns = card ? Array.prototype.slice.call(card.querySelectorAll("button")) : [];
    btns.forEach(function (b) { b.disabled = true; });
    if (card) {
      var prevErr = document.getElementById("err-" + p.request_id);
      if (prevErr) prevErr.remove();
    }

    if (typeof api !== "undefined" && api.post) {
      try {
        await api.post("/api/approvals/decide", {
          request_id: p.request_id,
          request_hash: p.request_hash,
          approved: approved
        });
        if (card) {
          clear(card).append(h("p", {
            text: approved ? "Approved. Sent to the pipeline." : "Denied."
          }));
        }
        setTimeout(poll, 300);
      } catch (err) {
        console.warn("Decide error:", err);
        btns.forEach(function (b) { b.disabled = false; });
        if (card) {
          card.append(h("p", {
            id: "err-" + p.request_id,
            text: "Decision failed. Try again."
          }));
        }
      }
    } else {
      btns.forEach(function (b) { b.disabled = false; });
    }
  }

  function renderHistory(items) {
    var feed = document.getElementById("history-feed");
    if (!feed) return;
    clear(feed);

    var filtered = (items || []).filter(function (it) {
      if (activeFilter === "all") return true;
      var d = String(it.decision || "").toLowerCase();
      if (activeFilter === "approved") return d === "approved" || it.approved === true;
      if (activeFilter === "denied") return d === "denied" || (d !== "timed_out" && it.approved === false);
      if (activeFilter === "timed_out") return d === "timed_out" || it.timed_out === true;
      return true;
    });

    if (!filtered.length) {
      feed.append(h("li", null, h("p", { class: "empty", text: "No approval history recorded." })));
      return;
    }

    filtered.forEach(function (it) {
      var d = String(it.decision || (it.approved ? "Approved" : (it.timed_out ? "Timed Out" : "Denied")));
      var isOk = (d.toLowerCase() === "approved");
      var isWait = (d.toLowerCase() === "timed out" || d.toLowerCase() === "timed_out");
      var outCls = isOk ? "ok" : (isWait ? "wait" : "stop");

      var tStr = it.time_ist || it.timestamp || "--";
      if (tStr.length > 8 && tStr.indexOf("T") !== -1) {
        tStr = tStr.split("T")[1].slice(0, 8);
      }

      var toolStr = it.tool || "action";
      var summaryStr = it.plain_summary || (toolStr + ": " + (it.reason || d));
      var deciderStr = it.decided_by || it.role || "supervisor";

      var row = h("li", { class: "row" },
        h("span", { class: "t mono", text: tStr }),
        h("span", { class: "out " + outCls }, h("i"), d),
        h("span", { class: "txt", text: summaryStr }),
        h("span", { class: "tool mono", text: deciderStr })
      );

      feed.append(row);
    });
  }

  function tickCountdowns() {
    Object.keys(countdownMap).forEach(function (reqId) {
      var item = countdownMap[reqId];
      if (!item) return;
      item.rem--;
      if (item.rem <= 0) {
        delete countdownMap[reqId];
        poll();
        return;
      }
      var textEl = document.getElementById("timer-" + reqId);
      if (textEl) {
        textEl.textContent = "Waiting for a human OK. Expires in " + item.rem + " s.";
      }
      var card = document.getElementById("approve-card-" + reqId);
      if (card) {
        var barFill = card.querySelector(".bar i");
        if (barFill) barFill.style.setProperty("--p", String(item.rem / item.total));
      }
    });
  }

  async function poll() {
    if (typeof api === "undefined" || !api.get) return;
    try {
      var pendingRes = await api.get("/api/approvals/pending");
      if (pendingRes && pendingRes.pending !== undefined) {
        currentPending = pendingRes.pending || [];
        renderPending(currentPending);
      }

      var historyRes = await api.get("/api/approvals/history");
      if (historyRes && historyRes.history !== undefined) {
        currentHistory = historyRes.history || [];
        renderHistory(currentHistory);
      }
    } catch (err) {
      console.warn("Approvals polling error:", err);
    }
  }

  function initFilters() {
    var chips = document.getElementById("history-filter-chips");
    if (!chips) return;
    chips.querySelectorAll(".chip").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var f = btn.getAttribute("data-filter") || "all";
        activeFilter = f;
        chips.querySelectorAll(".chip").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b.getAttribute("data-filter") === f));
        });
        renderHistory(currentHistory);
      });
    });
  }

  function init() {
    initFilters();
    poll();
    pollTimer = setInterval(poll, 2000);
    tickTimer = setInterval(tickCountdowns, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
