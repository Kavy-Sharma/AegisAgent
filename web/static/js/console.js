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

  function resolveStageLabels(envName, hwStatus) {
    var env = envName || (document.body && document.body.dataset ? document.body.dataset.env : "smart_home");
    var hw = hwStatus || (document.body && document.body.dataset ? document.body.dataset.hwStatus : "virtual");
    if (DM.getGateLabels) {
      return DM.getGateLabels(env === "office", hw);
    }
    return [
      "Detection", "Intent lock", "Model", "Role", "Parameters", "Rate limit", "Approval",
      env === "office" ? "Tool" : (hw && hw !== "virtual" ? "Device" : "Device (simulated)"),
      "Output scan"
    ];
  }

  var stageLabels = resolveStageLabels();
  var ICON_SHIELD = ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"];
  var isTurnRunning = false;
  var currentApprovalCountdown = null;
  var MODEL_TIMEOUT_MS = 90000;
  var POLL_INTERVAL_MS = 400;

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

  function renderApprovalCard(container, rail, reqId, reqHash, toolName, onDecision) {
    var secs = 60;
    var barFill = h("i");
    var bar = h("div", { class: "bar" }, barFill);
    var label = h("p", { text: "Waiting for a human OK. Expires in 60 s." });
    var card = h("div", { class: "approve" }, label, bar);
    var done = false;

    function finish(ok) {
      if (done) return;
      done = true;
      if (currentApprovalCountdown) {
        clearInterval(currentApprovalCountdown);
        currentApprovalCountdown = null;
      }

      clear(card);
      card.className = "approve " + (ok ? "ok" : "stop");
      card.append(h("p", {
        text: ok ? "Approved by supervisor. Dispatching action…" : "Denied by supervisor. Nothing was executed."
      }));

      if (typeof api !== "undefined" && api.post && reqId) {
        api.post("/api/approvals/decide", {
          request_id: reqId,
          request_hash: reqHash,
          approved: ok
        }).catch(function (err) {
          console.log("Approval submit notice:", (err && err.message) || err);
        });
      }

      if (typeof onDecision === "function") {
        onDecision(ok, false);
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
    scrollThreadToBottom();

    if (currentApprovalCountdown) clearInterval(currentApprovalCountdown);
    currentApprovalCountdown = setInterval(function () {
      secs--;
      label.textContent = "Waiting for a human OK. Expires in " + secs + " s.";
      barFill.style.setProperty("--p", String(Math.max(0, secs) / 60));
      if (secs <= 0) {
        clearInterval(currentApprovalCountdown);
        currentApprovalCountdown = null;
        if (!done) {
          done = true;
          clear(card);
          card.className = "approve stop";
          card.append(h("p", { text: "Timed out. Nothing was executed." }));
          if (typeof onDecision === "function") {
            onDecision(false, true);
          }
        }
      }
    }, 1000);

    return {
      updateFromFinal: function (finalDec, isNotDone, finalText) {
        if (currentApprovalCountdown) {
          clearInterval(currentApprovalCountdown);
          currentApprovalCountdown = null;
        }
        clear(card);
        if (finalDec === "ALLOW" && !isNotDone) {
          card.className = "approve ok";
          card.append(h("p", { text: "Approved by supervisor. Action dispatched." }));
        } else if (finalDec === "ERROR" || isNotDone) {
          card.className = "approve stop";
          card.append(h("p", { text: finalText || "Device could not be reached. Nothing was changed." }));
        } else {
          card.className = "approve stop";
          card.append(h("p", {
            text: (finalText && /timed?\s*out|expired/i.test(finalText))
              ? "Timed out. Nothing was executed."
              : "Denied by supervisor. Nothing was executed."
          }));
        }
      }
    };
  }

  function showRetryButton(host, retryText) {
    if (!host) return;
    var btn = h("button", { class: "btn btn-sm", type: "button", text: "Retry" });
    btn.addEventListener("click", function () {
      var wrap = btn.parentNode;
      if (wrap && wrap.parentNode) wrap.parentNode.removeChild(wrap);
      else btn.remove();
      handleSend(retryText);
    });
    host.append(h("div", { class: "btnrow" }, btn));
    scrollThreadToBottom();
  }

  function _stageCaption(labels, gateIdx, stageName, elapsedSecs) {
    if (stageName === "llm" || gateIdx === 2) {
      return [{ text: "Model is thinking... (" + elapsedSecs + "s)" }];
    }
    if (gateIdx >= 0 && gateIdx < labels.length) {
      return [{ text: "Checking " + labels[gateIdx] + "…" }];
    }
    return [{ text: "Waiting for security worker…" }];
  }

  async function handleSend(text) {
    text = (text || "").trim();
    if (!text || isTurnRunning) return;

    stageLabels = resolveStageLabels();
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

    var pollTimer = null;
    var thinkingTimer = null;
    var settled = false;

    function stopTimers() {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      if (thinkingTimer) {
        clearInterval(thinkingTimer);
        thinkingTimer = null;
      }
      if (currentApprovalCountdown) {
        clearInterval(currentApprovalCountdown);
        currentApprovalCountdown = null;
      }
    }

    try {
      var sendRes = await api.post("/api/console/send", { text: text });
      var reqId = sendRes && (sendRes.request_id || sendRes.id || sendRes.req_id);
      if (!sendRes || !reqId) {
        var errSay = (sendRes && sendRes.error) ? sendRes.error : "Something went wrong. Try again.";
        rail.settle({
          kind: "stop",
          stop: 0,
          say: errSay,
          why: errSay
        });
        showRetryButton(host, text);
        setTurnRunning(false);
        return;
      }

      var activeLabels = stageLabels.slice();
      var waitBudgetMs = 0;
      var lastTickMs = Date.now();
      var waitingForApproval = false;
      var approvalResolvedStop = false;
      var postApprovalStartMs = null;
      var approvalRendered = false;
      var approvalCardCtrl = null;
      var thinkingStartMs = null;
      var currentActiveStage = null;
      var consecutivePollErrors = 0;
      var pollInFlight = false;

      function ensureThinkingTicker() {
        if (thinkingTimer) return;
        thinkingTimer = setInterval(function () {
          if (settled || currentActiveStage !== "llm" || !thinkingStartMs) {
            clearInterval(thinkingTimer);
            thinkingTimer = null;
            return;
          }
          var secs = Math.max(0, Math.floor((Date.now() - thinkingStartMs) / 1000));
          if (rail.setCaption) {
            rail.setCaption([{ text: "Model is thinking... (" + secs + "s)" }]);
          }
        }, 500);
      }

      function stopThinkingTicker() {
        if (thinkingTimer) {
          clearInterval(thinkingTimer);
          thinkingTimer = null;
        }
      }

      function failWithTimeout(msg, why) {
        if (settled) return;
        settled = true;
        stopTimers();
        setTurnRunning(false);
        rail.settle({
          kind: "stop",
          stop: 2,
          say: msg || "No answer from the model. Try again.",
          why: why || "Timed out waiting for response."
        });
        showRetryButton(host, text);
      }

      async function doPoll() {
        if (settled || pollInFlight) return;
        pollInFlight = true;
        try {
          var now = Date.now();
          if (!waitingForApproval) {
            waitBudgetMs += (now - lastTickMs);
          }
          lastTickMs = now;

          if (waitBudgetMs > MODEL_TIMEOUT_MS || (postApprovalStartMs && (now - postApprovalStartMs > 25000))) {
            failWithTimeout("No answer from the model. Try again.", "Timed out waiting for response.");
            return;
          }

          var pollRes = await api.get("/api/console/poll/" + encodeURIComponent(reqId));
          consecutivePollErrors = 0;
          if (!pollRes || settled) return;

          var steps = pollRes.steps || [];
          var final = pollRes.final;
          var completedGates = Array.isArray(pollRes.completed_gates) ? pollRes.completed_gates : [];
          var activeStage = pollRes.active_stage || null;
          var activeGate = (typeof pollRes.active_gate === "number") ? pollRes.active_gate : -1;

          // Check if waiting for human approval
          var approvalStep = steps.find(function (s) {
            return s.stage === "approval" && (s.status === "running" || s.status === "review");
          });
          if (!final && (approvalStep || activeStage === "approval") && !approvalRendered) {
            approvalRendered = true;
            waitingForApproval = true;
            currentActiveStage = "approval";
            stopThinkingTicker();

            var detail = (approvalStep && approvalStep.detail) || {};
            var appId = detail.request_id || reqId;
            rail.syncLive({
              completedGates: completedGates,
              activeGate: 6,
              waiting: true,
              captionParts: [
                { text: "Waiting at " + (activeLabels[6] || "Approval") + ". ", tone: "wait" },
                { text: "Waiting for human supervisor approval." }
              ]
            });

            approvalCardCtrl = renderApprovalCard(
              agentMsg,
              rail,
              appId,
              detail.request_hash || "",
              detail.tool || "action",
              function (ok, timedOut) {
                waitingForApproval = false;
                lastTickMs = Date.now();
                postApprovalStartMs = Date.now();
                if (!settled) {
                  if (ok) {
                    currentActiveStage = "hardware";
                    rail.syncLive({
                      completedGates: [0, 1, 2, 3, 4, 5, 6],
                      activeGate: 7,
                      waiting: false,
                      captionParts: [{ text: "Dispatching to " + (activeLabels[7] || "Device") + "…" }]
                    });
                  } else {
                    approvalResolvedStop = true;
                    currentActiveStage = "approval";
                    rail.settle({
                      kind: "stop",
                      stop: 6,
                      say: timedOut
                        ? "Timed out. Nobody answered in 60 s, so the request failed closed."
                        : "Denied by supervisor. Nothing was executed.",
                      why: timedOut ? "Approval deadline expired." : "Supervisor declined authorization."
                    });
                  }
                }
              }
            );
          } else if (!final && !waitingForApproval && !approvalResolvedStop) {
            currentActiveStage = activeStage;
            if (activeStage === "llm" || activeGate === 2) {
              if (!thinkingStartMs) thinkingStartMs = Date.now();
              var thinkSecs = Math.max(0, Math.floor((Date.now() - thinkingStartMs) / 1000));
              rail.syncLive({
                completedGates: completedGates,
                activeGate: 2,
                waiting: false,
                captionParts: _stageCaption(activeLabels, 2, "llm", thinkSecs)
              });
              ensureThinkingTicker();
            } else {
              stopThinkingTicker();
              if (activeGate >= 0 || completedGates.length > 0) {
                rail.syncLive({
                  completedGates: completedGates,
                  activeGate: activeGate,
                  waiting: false,
                  captionParts: _stageCaption(activeLabels, activeGate, activeStage, 0)
                });
              }
            }
          }

          if (final) {
            settled = true;
            waitingForApproval = false;
            stopTimers();
            setTurnRunning(false);

            var dec = String(final.decision || "BLOCK").toUpperCase();
            var isAllow = (dec === "ALLOW" || dec === "DIRECT_ALLOW");
            var isWait = (dec === "REVIEW" || dec === "WAITING");
            var trStatus = (final.tool_result && typeof final.tool_result === "object")
              ? String(final.tool_result.status || "").toLowerCase()
              : "";
            var isNotDone = isAllow && (trStatus === "error" || trStatus === "refused" || trStatus === "failed");

            var stopStage = pollRes.stopped_stage || final.stopped_at || final.stage;
            if (!stopStage && steps.length > 0) {
              for (var i = 0; i < steps.length; i++) {
                if (steps[i].status === "block" || steps[i].status === "deny" || steps[i].status === "error") {
                  stopStage = steps[i].stage;
                  break;
                }
              }
            }

            var stopIdx = (isAllow && !isNotDone)
              ? -1
              : (typeof pollRes.stopped_gate === "number" && pollRes.stopped_gate >= 0
                ? pollRes.stopped_gate
                : (DM.layerToGateIndex ? DM.layerToGateIndex(stopStage) : 0));

            if (isNotDone && stopIdx < 0) stopIdx = 7;
            if (!isAllow && !isNotDone && stopIdx < 0) stopIdx = 0;

            var trText = (final.tool_result && typeof final.tool_result === "object" && final.tool_result.text)
              ? final.tool_result.text
              : "";
            var say = final.reply || trText || final.error || (isNotDone ? "Could not complete request." : (isAllow ? "Allowed." : "Request stopped by security policy."));
            var why = final.error || trText || (isAllow && !isNotDone ? "All nine gates passed." : "Stopped by security policy.");

            if (approvalCardCtrl) {
              approvalCardCtrl.updateFromFinal(dec, isNotDone, say);
            }

            rail.settle({
              kind: isNotDone ? "not_done" : (isAllow ? "allow" : (isWait ? "wait" : "stop")),
              stop: stopIdx,
              say: say,
              why: why
            });
            if (isNotDone || dec === "ERROR") {
              showRetryButton(host, text);
            }
            scrollThreadToBottom();
          }
        } catch (pollErr) {
          consecutivePollErrors++;
          console.warn("Poll error:", pollErr);
          if (consecutivePollErrors >= 12) {
            failWithTimeout("No answer from the model. Try again.", "Lost connection while checking status.");
          }
        } finally {
          pollInFlight = false;
        }
      }

      pollTimer = setInterval(doPoll, POLL_INTERVAL_MS);
      doPoll();

    } catch (err) {
      console.warn("Console send error:", err);
      stopTimers();
      var errMsg = (err && err.data && err.data.error) || "Something went wrong. Try again.";
      rail.settle({
        kind: "stop",
        stop: 0,
        say: errMsg,
        why: errMsg
      });
      showRetryButton(host, text);
      setTurnRunning(false);
    }
  }

  window.sendConsolePrompt = handleSend;

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
    stageLabels = resolveStageLabels();
    window.addEventListener("aegis:health", function (ev) {
      var detail = ev && ev.detail;
      if (detail) {
        stageLabels = resolveStageLabels(detail.environment, detail.hardware_status);
      }
    });
    initSuggestions();
    initForm();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
