/**
 * AegisAgent Console Controller (v2)
 * Pure DOM, compact gate line playback, real backend polling, and HMAC approval flow.
 * Zero innerHTML, zero inline styles.
 */
(function () {
  "use strict";

  var GL = window.AegisGateLine || {};
  var h = GL.h;
  var clear = GL.clear;
  var svgIcon = GL.svgIcon;

  var DM = window.AegisDecisionMap || {};
  var stageLabels = (DM.getGateLabels && DM.getGateLabels(false)) || [
    "Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval", "Device (simulated)", "Output scan"
  ];

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var ICON_SHIELD = ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"];
  var isTurnRunning = false;
  var currentApprovalCountdown = null;

  function setTurnRunning(running) {
    isTurnRunning = running;
    var sendBtn = document.getElementById("send-btn");
    var askInput = document.getElementById("ask");
    if (sendBtn) sendBtn.disabled = running;
    if (askInput) askInput.disabled = running;
  }

  function scrollThreadToBottom() {
    var thread = document.getElementById("chat-thread");
    if (!thread) return;
    thread.scrollTop = thread.scrollHeight;
  }

  function addMessage(node) {
    var thread = document.getElementById("chat-thread");
    if (!thread) return;
    thread.append(node);
    scrollThreadToBottom();
  }

  function renderApprovalCard(container, rail, reqId, reqHash, toolName) {
    var secs = 60;
    var barFill = h("i");
    var bar = h("div", { class: "bar" }, barFill);
    var label = h("p", { text: "Waiting for a human OK. Expires in 60 s." });
    var card = h("div", { class: "approve" }, label, bar);
    var done = false;

    function finish(ok) {
      if (done) return;
      done = true;
      if (currentApprovalCountdown) clearInterval(currentApprovalCountdown);

      clear(card);
      card.className = "approve " + (ok ? "ok" : "stop");
      card.append(h("p", { text: ok ? "Approved by supervisor. Action dispatched." : "Denied by supervisor. Nothing was executed." }));

      if (typeof api !== "undefined" && api.post && reqId) {
        api.post("/api/approvals/decide", {
          request_id: reqId,
          request_hash: reqHash,
          approved: ok
        }).catch(function (err) {
          console.log("Approval submit notice:", (err && err.message) || err);
        });
      }

      if (ok) {
        rail.show({
          kind: "allow",
          stop: -1,
          say: "Approved by supervisor. Action dispatched.",
          why: "Human operator confirmed the request."
        });
      } else {
        rail.show({
          kind: "stop",
          stop: 6,
          say: "Denied by supervisor. Nothing was executed.",
          why: "Supervisor declined authorization."
        });
      }
    }

    var btns = h("div", { class: "btns" },
      h("button", {
        class: "btn good",
        type: "button",
        onclick: function () { finish(true); }
      }, "Approve"),
      h("button", {
        class: "btn danger",
        type: "button",
        onclick: function () { finish(false); }
      }, "Deny")
    );

    card.append(btns);
    container.append(card);
    barFill.style.setProperty("--p", "1");

    if (currentApprovalCountdown) clearInterval(currentApprovalCountdown);
    currentApprovalCountdown = setInterval(function () {
      secs--;
      label.textContent = "Waiting for a human OK. Expires in " + secs + " s.";
      barFill.style.setProperty("--p", String(secs / 60));
      if (secs <= 0) {
        clearInterval(currentApprovalCountdown);
        if (!done) {
          done = true;
          clear(card);
          card.className = "approve stop";
          card.append(h("p", { text: "Timed out. Nothing was executed." }));
          rail.show({
            kind: "stop",
            stop: 6,
            say: "Timed out. Nobody answered in 60 s, so the request failed closed.",
            why: "Approval deadline expired."
          });
        }
      }
    }, 1000);
  }

  function showRetryButton(host, retryText) {
    if (!host) return;
    var btn = h("button", { class: "btn btn-sm", text: "Retry" });
    btn.addEventListener("click", function () {
      btn.remove();
      handleSend(retryText);
    });
    host.append(h("div", { class: "btnrow" }, btn));
  }

  async function handleSend(text) {
    text = (text || "").trim();
    if (!text || isTurnRunning) return;

    setTurnRunning(true);
    addMessage(h("div", { class: "msg user", text: text }));

    var host = h("div");
    var agentMsg = h("div", { class: "msg agent" },
      h("div", { class: "who" }, svgIcon(ICON_SHIELD), "Aegis"),
      host
    );
    addMessage(agentMsg);

    var rail = GL.createRail(host, {
      compact: true,
      labels: stageLabels,
      idle: "Sending request to Aegis gateway…"
    });

    if (typeof api === "undefined" || !api.post) {
      setTurnRunning(false);
      return;
    }

    try {
      var sendRes = await api.post("/api/console/send", { text: text });
      var reqId = sendRes && (sendRes.request_id || sendRes.id || sendRes.req_id);
      if (!sendRes || !reqId) {
        var errSay = (sendRes && sendRes.error) ? sendRes.error : "Something went wrong. Try again.";
        rail.play({
          kind: "stop",
          stop: 0,
          say: errSay,
          why: errSay
        });
        showRetryButton(host, text);
        setTurnRunning(false);
        return;
      }

      var pollStart = Date.now();
      var approvalRendered = false;

      var pollTimer = setInterval(async function () {
        if (Date.now() - pollStart > 120000) {
          clearInterval(pollTimer);
          setTurnRunning(false);
          rail.play({
            kind: "stop",
            stop: 2,
            say: "Agent timed out waiting for execution.",
            why: "Worker service did not respond."
          });
          return;
        }

        try {
          var pollRes = await api.get("/api/console/poll/" + encodeURIComponent(reqId));
          if (!pollRes) return;

          var steps = pollRes.steps || [];
          var final = pollRes.final;

          // Check if waiting for approval
          var approvalStep = steps.find(function (s) { return s.stage === "approval" && s.status === "running"; });
          if (approvalStep && !approvalRendered && !final) {
            approvalRendered = true;
            var detail = approvalStep.detail || {};
            var appId = detail.request_id || reqId;
            rail.show({
              kind: "wait",
              stop: 6,
              say: "Waiting for human supervisor approval.",
              why: "High-risk tool call requires authorization."
            });
            renderApprovalCard(agentMsg, rail, appId, detail.request_hash || "", detail.tool || "action");
          }

          if (final) {
            clearInterval(pollTimer);
            setTurnRunning(false);

            var dec = String(final.decision || "BLOCK").toUpperCase();
            var isAllow = (dec === "ALLOW");
            var isWait = (dec === "REVIEW" || dec === "WAITING");

            var stopStage = pollRes.stopped_stage || final.stopped_at || final.stage;
            if (!stopStage && steps.length > 0) {
              for (var i = 0; i < steps.length; i++) {
                if (steps[i].status === "block" || steps[i].status === "error") {
                  stopStage = steps[i].stage;
                  break;
                }
              }
            }

            var stopIdx = isAllow ? -1 : (DM.layerToGateIndex ? DM.layerToGateIndex(stopStage) : 0);
            if (stopIdx === -1 && !isAllow) stopIdx = 0;

            var say = final.reply || final.error || (isAllow ? "Allowed." : "Request stopped by security policy.");
            var why = final.error || (isAllow ? "All nine gates passed." : "Stopped by security policy.");

            if (!approvalRendered) {
              await rail.play({
                kind: isAllow ? "allow" : (isWait ? "wait" : "stop"),
                stop: stopIdx,
                say: say,
                why: why
              });
              scrollThreadToBottom();
            }

            if (isWait && !approvalRendered) {
              approvalRendered = true;
              var appId = final.request_id || reqId;
              rail.show({
                kind: "wait",
                stop: 6,
                say: "Waiting for human supervisor approval.",
                why: "High-risk tool call requires authorization."
              });
              renderApprovalCard(agentMsg, rail, appId, final.request_hash || "", final.tool_called || "action");
            }
          }
        } catch (pollErr) {
          console.warn("Poll error:", pollErr);
        }
      }, 500);

    } catch (err) {
      console.warn("Console send error:", err);
      var errMsg = (err && err.data && err.data.error) || "Something went wrong. Try again.";
      rail.play({
        kind: "stop",
        stop: 0,
        say: errMsg,
        why: errMsg
      });
      showRetryButton(host, text);
      setTurnRunning(false);
    }
  }

  function initSuggestions() {
    var container = document.getElementById("suggest-chips");
    if (!container) return;
    container.querySelectorAll(".chip").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.textContent;
        var askInput = document.getElementById("ask");
        if (askInput) askInput.value = text;
        handleSend(text);
      });
    });
  }

  function initForm() {
    var form = document.getElementById("console-form");
    var askInput = document.getElementById("ask");
    if (!form || !askInput) return;

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var text = askInput.value;
      askInput.value = "";
      handleSend(text);
    });
  }

  function init() {
    initSuggestions();
    initForm();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
