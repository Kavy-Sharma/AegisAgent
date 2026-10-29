/**
 * AegisAgent Console Controller
 * Real-time chat streaming, pipeline stepper progression, inline approvals, and suggestions.
 */
(function () {
  var chatStream = document.getElementById("chat-stream");
  var chatTextarea = document.getElementById("chat-textarea");
  var chatSendBtn = document.getElementById("chat-send-btn");
  var workerBanner = document.getElementById("console-worker-banner");
  var userRole = (document.body && document.body.getAttribute("data-role")) || "guest";

  if (!chatStream || !chatTextarea) return;

  var STAGES = ["detection", "intent", "llm", "rbac", "rate_limit", "approval", "hardware", "output_scan"];
  var STAGE_LABELS = {
    detection: "Detection",
    intent: "Intent",
    llm: "LLM",
    rbac: "RBAC",
    rate_limit: "Rate Limit",
    approval: "Approval",
    hardware: "Hardware",
    output_scan: "Output Scan",
  };

  var isQuarantineActive = false;

  function setQuarantineLockdown(locked) {
    isQuarantineActive = locked;
    var container = document.querySelector(".chat-input-bar") || document.querySelector(".chat-input-wrap");
    var existingBar = document.getElementById("console-quarantine-bar");

    if (locked) {
      if (chatTextarea) {
        chatTextarea.disabled = true;
        chatTextarea.placeholder = "🚨 SESSION QUARANTINED: Hardware protected. Admin release required.";
      }
      if (chatSendBtn) {
        chatSendBtn.disabled = true;
      }
      if (!existingBar && container) {
        var bar = document.createElement("div");
        bar.id = "console-quarantine-bar";
        bar.className = "console-quarantine-bar";
        bar.innerHTML = '<div class="flex items-center gap-xs">' +
          '<svg class="icon text-danger icon-sm"><use href="/static/icons.svg#icon-alert-triangle"></use></svg>' +
          '<strong class="text-danger text-xs uppercase tracking-wider">Air-Gap Containment Active — 3 Injections Exceeded</strong>' +
          '</div>' +
          '<button type="button" class="btn btn-danger btn-xs" id="bar-release-quarantine-btn">' +
          '<span>Admin Override: Instant Release</span>' +
          '</button>';
        container.parentNode.insertBefore(bar, container);

        var btn = document.getElementById("bar-release-quarantine-btn");
        if (btn) {
          btn.addEventListener("click", function () {
            btn.disabled = true;
            btn.textContent = "Releasing...";
            api.releaseQuarantine().then(function () {
              setQuarantineLockdown(false);
              app.showToast("Quarantine Released", "Threat score reset. Console ready for commands.", "ok", 4000);
            }).catch(function (err) {
              app.showToast("Release Error", err.message, "danger");
              btn.disabled = false;
              btn.textContent = "Admin Override: Instant Release";
            });
          });
        }
      }
      if (window.AegisApp && window.AegisApp.openQuarantineModal) {
        window.AegisApp.openQuarantineModal();
      }
    } else {
      if (existingBar && existingBar.parentNode) {
        existingBar.parentNode.removeChild(existingBar);
      }
      if (chatTextarea) {
        chatTextarea.disabled = false;
        chatTextarea.placeholder = "Dispatched command or prompt (e.g. 'Turn on the light', 'What is the temperature?')...";
        chatTextarea.focus();
      }
      if (chatSendBtn) {
        chatSendBtn.disabled = false;
      }
      if (window.AegisApp && window.AegisApp.closeQuarantineModal) {
        window.AegisApp.closeQuarantineModal();
      }
    }
  }

  function setTurnRunning(running) {
    if (isQuarantineActive) {
      if (chatSendBtn) chatSendBtn.disabled = true;
      if (chatTextarea) chatTextarea.disabled = true;
      return;
    }
    if (chatSendBtn) chatSendBtn.disabled = running;
    if (chatTextarea) chatTextarea.disabled = running;
    if (!running && chatTextarea) {
      chatTextarea.focus();
    }
  }

  function scrollToBottom() {
    chatStream.scrollTop = chatStream.scrollHeight;
  }

  function appendUserMessage(text) {
    var msg = document.createElement("div");
    msg.className = "chat-msg user";

    var avatar = document.createElement("div");
    avatar.className = "chat-msg-avatar";
    avatar.innerHTML = '<svg class="icon"><use href="/static/icons.svg#icon-user"></use></svg>';

    var bubble = document.createElement("div");
    bubble.className = "chat-msg-bubble";
    bubble.textContent = text;

    msg.appendChild(avatar);
    msg.appendChild(bubble);
    chatStream.appendChild(msg);
    scrollToBottom();
  }

  function createAssistantTurn() {
    var msg = document.createElement("div");
    msg.className = "chat-msg assistant";

    var avatar = document.createElement("div");
    avatar.className = "chat-msg-avatar";
    avatar.innerHTML = '<svg class="icon"><use href="/static/icons.svg#icon-shield"></use></svg>';

    var bubble = document.createElement("div");
    bubble.className = "chat-msg-bubble";

    // 1. Pipeline stepper container (Rendered ON TOP as requested)
    var stepper = document.createElement("div");
    stepper.className = "pipeline-stepper";

    var nodeMap = {};
    var connectorMap = {};

    STAGES.forEach(function (stage, idx) {
      var node = document.createElement("div");
      node.className = "step-node step-pending";
      node.dataset.stage = stage;
      node.textContent = STAGE_LABELS[stage] || stage;
      stepper.appendChild(node);
      nodeMap[stage] = node;

      if (idx < STAGES.length - 1) {
        var conn = document.createElement("div");
        conn.className = "step-connector";
        stepper.appendChild(conn);
        connectorMap[stage] = conn;
      }
    });

    bubble.appendChild(stepper);

    // 2. Callout container for blocks or warnings
    var callout = document.createElement("div");
    callout.className = "turn-callout";
    callout.style.setProperty("display", "none");
    bubble.appendChild(callout);

    // 3. Catchy Agent Response Card (Rendered BELOW the stepper)
    var responseCard = document.createElement("div");
    responseCard.className = "assistant-response-card";

    var responseHeader = document.createElement("div");
    responseHeader.className = "assistant-response-tag";
    var tagSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    tagSvg.setAttribute("class", "icon icon-xs");
    var tagUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
    tagUse.setAttribute("href", "/static/icons.svg#icon-shield");
    tagSvg.appendChild(tagUse);
    var tagLabel = document.createElement("span");
    tagLabel.textContent = "Agent Response";
    responseHeader.appendChild(tagSvg);
    responseHeader.appendChild(tagLabel);
    responseCard.appendChild(responseHeader);

    var textEl = document.createElement("div");
    textEl.className = "assistant-text";
    textEl.textContent = "Processing request...";
    responseCard.appendChild(textEl);

    bubble.appendChild(responseCard);

    msg.appendChild(avatar);
    msg.appendChild(bubble);
    chatStream.appendChild(msg);
    scrollToBottom();

    return {
      msg: msg,
      textEl: textEl,
      responseCard: responseCard,
      bubble: bubble,
      stepper: stepper,
      nodeMap: nodeMap,
      connectorMap: connectorMap,
      callout: callout,
      pollTimer: null,
    };
  }

  function pollTurn(reqId, turnUi) {
    var pollStartTime = Date.now();

    turnUi.pollTimer = setInterval(function () {
      // 120s poll timeout
      if (Date.now() - pollStartTime >= 120000) {
        clearInterval(turnUi.pollTimer);
        turnUi.pollTimer = null;
        setTurnRunning(false);
        turnUi.textEl.textContent = "Worker not responding";
        return;
      }

      api.get("/api/console/poll/" + encodeURIComponent(reqId))
        .then(function (data) {
          var steps = data.steps || [];
          var final = data.final;

          // Update stages in stepper
          steps.forEach(function (step) {
            var node = turnUi.nodeMap[step.stage];
            if (node) {
              node.className = "step-node step-" + (step.status || "pending");
              if (step.detail && Object.keys(step.detail).length > 0) {
                var detailStr = JSON.stringify(step.detail);
                node.title = detailStr;
              }
            }
            var conn = turnUi.connectorMap[step.stage];
            if (conn && step.status === "pass") {
              conn.classList.add("connector-filled");
            }

            // Provide real-time friendly feedback during LLM reasoning
            if (step.stage === "llm" && step.status === "running" && !final && !turnUi.approvalShown) {
              turnUi.textEl.textContent = "AegisAgent reasoning with Ollama (llama3.1)...";
            }
          });

          // Check if approval is actually pending right now
          var lastApproval = null;
          for (var i = steps.length - 1; i >= 0; i--) {
            if (steps[i].stage === "approval") {
              lastApproval = steps[i];
              break;
            }
          }
          var isApprovalPending = lastApproval && lastApproval.status === "running" && !final;
          if (isApprovalPending && !turnUi.approvalShown) {
            var targetTool = "high_risk_tool";
            var targetArgs = {};
            var targetHash = "";
            var approvalReqId = reqId;

            if (lastApproval && lastApproval.detail) {
              if (lastApproval.detail.tool) targetTool = lastApproval.detail.tool;
              if (lastApproval.detail.args) targetArgs = lastApproval.detail.args;
              if (lastApproval.detail.request_hash) targetHash = lastApproval.detail.request_hash;
              if (lastApproval.detail.request_id) approvalReqId = lastApproval.detail.request_id;
            }

            for (var j = 0; j < steps.length; j++) {
              if (steps[j].detail) {
                if (steps[j].detail.tool) targetTool = steps[j].detail.tool;
                if (steps[j].detail.args && Object.keys(targetArgs).length === 0) targetArgs = steps[j].detail.args;
                if (steps[j].detail.request_hash && !targetHash) targetHash = steps[j].detail.request_hash;
                if (steps[j].detail.request_id && approvalReqId === reqId) approvalReqId = steps[j].detail.request_id;
              }
            }

            if (userRole === "admin" && (!targetHash || Object.keys(targetArgs).length === 0)) {
              api.get("/api/approvals/pending").then(function (res) {
                var items = (res && res.pending) || [];
                for (var k = 0; k < items.length; k++) {
                  if (items[k].tool === targetTool || items[k].request_id === approvalReqId) {
                    approvalReqId = items[k].request_id;
                    targetArgs = items[k].args || targetArgs;
                    targetHash = items[k].request_hash || targetHash;
                    break;
                  }
                }
                showInlineApproval(turnUi, approvalReqId, targetTool, targetArgs, targetHash);
              }).catch(function () {
                showInlineApproval(turnUi, approvalReqId, targetTool, targetArgs, targetHash);
              });
            } else {
              showInlineApproval(turnUi, approvalReqId, targetTool, targetArgs, targetHash);
            }
          } else if (!isApprovalPending && turnUi.approvalCard) {
            if (turnUi.approvalCard.parentNode) {
              turnUi.approvalCard.parentNode.removeChild(turnUi.approvalCard);
            }
            turnUi.approvalCard = null;
            turnUi.approvalShown = false;
          }

          if (final) {
            clearInterval(turnUi.pollTimer);
            turnUi.pollTimer = null;
            setTurnRunning(false);

            if (turnUi.approvalCard && turnUi.approvalCard.parentNode) {
              turnUi.approvalCard.parentNode.removeChild(turnUi.approvalCard);
              turnUi.approvalCard = null;
            }

            if (final.decision === "BLOCK") {
              if (turnUi.responseCard) turnUi.responseCard.style.setProperty("display", "none");
              turnUi.textEl.textContent = "";
              turnUi.callout.className = "callout-blocked";
              turnUi.callout.style.setProperty("display", "block");
              var errDetail = final.error || "Policy violation";
              var isCumulative = errDetail.indexOf("Cumulative suspicion") !== -1;
              var isOutOfScope = errDetail.indexOf("outside intent scope") !== -1;
              var isQuarantine = errDetail.indexOf("SESSION QUARANTINED") !== -1;
              if (isQuarantine) {
                setQuarantineLockdown(true);
              }
              var ruleMatch = errDetail.match(/INJ-[0-9]{3}/);
              var ruleBadge = ruleMatch ? ruleMatch[0] : (isCumulative ? "CTX-WINDOW" : (isOutOfScope ? "OUT-OF-SCOPE" : (isQuarantine ? "QUARANTINE" : "SECURITY-GATE")));

              // Pure DOM creation + textContent
              turnUi.callout.replaceChildren();

              var header = document.createElement("div");
              header.className = "callout-blocked-header";

              var titleWrap = document.createElement("div");
              titleWrap.className = "callout-blocked-title";
              var iconSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
              iconSvg.setAttribute("class", "icon icon-sm text-danger");
              var iconUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
              iconUse.setAttribute("href", "/static/icons.svg#icon-shield-alert");
              iconSvg.appendChild(iconUse);
              var titleSpan = document.createElement("span");
              titleSpan.textContent = "Policy Enforcement: Execution Blocked";
              titleWrap.appendChild(iconSvg);
              titleWrap.appendChild(titleSpan);

              var badgeSpan = document.createElement("span");
              badgeSpan.className = "callout-blocked-badge";
              badgeSpan.textContent = ruleBadge;

              header.appendChild(titleWrap);
              header.appendChild(badgeSpan);
              turnUi.callout.appendChild(header);

              var body = document.createElement("div");
              body.className = "callout-blocked-body";

              var errDiv = document.createElement("div");
              errDiv.className = "text-danger font-medium";
              errDiv.textContent = errDetail;
              body.appendChild(errDiv);

              if (isCumulative) {
                var cumP = document.createElement("p");
                cumP.className = "text-xs text-muted mt-xs";
                cumP.textContent = "Multi-turn protection active: Threat suspicion retained in sliding window to protect IoT hardware from follow-up attacks.";
                body.appendChild(cumP);
              }
              turnUi.callout.appendChild(body);

              if (userRole === "admin") {
                var footer = document.createElement("div");
                footer.className = "callout-blocked-footer";

                var footerSpan = document.createElement("span");
                footerSpan.className = "text-xs text-muted";
                footerSpan.textContent = "Admin Override: Reset threat window without losing chat history";

                var clearBtn = document.createElement("button");
                clearBtn.type = "button";
                clearBtn.className = "btn-clear-threat";
                var clearSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
                clearSvg.setAttribute("class", "icon icon-xs");
                var clearUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
                clearUse.setAttribute("href", "/static/icons.svg#icon-refresh");
                clearSvg.appendChild(clearUse);
                var clearText = document.createElement("span");
                clearText.textContent = isQuarantine ? "Release Session Quarantine" : "Acknowledge & Clear Threat Window";
                if (isQuarantine) {
                  footerSpan.textContent = "Admin Override: Instant release session quarantine";
                }
                clearBtn.appendChild(clearSvg);
                clearBtn.appendChild(clearText);

                clearBtn.addEventListener("click", function () {
                  clearBtn.disabled = true;
                  if (isQuarantine) {
                    clearBtn.textContent = "Releasing quarantine...";
                    api.releaseQuarantine()
                      .then(function () {
                        setQuarantineLockdown(false);
                        app.showToast("Quarantine Released", "Session restored. Normal commands can now execute.", "ok", 5000);
                        var okSpan = document.createElement("span");
                        okSpan.className = "text-xs text-ok font-semibold";
                        okSpan.textContent = "[OK] Quarantine released -- session restored.";
                        clearBtn.replaceWith(okSpan);
                      })
                      .catch(function (err) {
                        app.showToast("Release Error", err.message, "danger");
                        clearBtn.disabled = false;
                        clearBtn.textContent = "Release Session Quarantine";
                      });
                    return;
                  }
                  clearBtn.textContent = "Clearing threat window...";
                  api.clearThreat()
                    .then(function () {
                      app.showToast("Threat Window Cleared", "Sliding window reset. Normal commands can now execute.", "ok", 5000);
                      var okSpan = document.createElement("span");
                      okSpan.className = "text-xs text-ok font-semibold";
                      okSpan.textContent = "[OK] Threat window cleared -- ready for new commands.";
                      clearBtn.replaceWith(okSpan);
                    })
                    .catch(function () {
                      api.newSession()
                        .then(function () {
                          app.showToast("Threat Window Cleared", "Session token refreshed cleanly. Normal commands can now execute.", "ok", 5000);
                          var okSpan = document.createElement("span");
                          okSpan.className = "text-xs text-ok font-semibold";
                          okSpan.textContent = "[OK] Clean session resumed -- ready for new commands.";
                          clearBtn.replaceWith(okSpan);
                        })
                        .catch(function (err2) {
                          app.showToast("Clear Error", err2.message, "danger");
                          clearBtn.disabled = false;
                          clearBtn.textContent = "Acknowledge & Clear Threat Window";
                        });
                    });
                });

                footer.appendChild(footerSpan);
                footer.appendChild(clearBtn);
                turnUi.callout.appendChild(footer);
              }
            } else if (final.decision === "DENY") {
              if (turnUi.responseCard) turnUi.responseCard.style.setProperty("display", "none");
              turnUi.textEl.textContent = "";
              turnUi.callout.className = "callout-warning";
              turnUi.callout.style.setProperty("display", "block");
              turnUi.callout.textContent = "Action denied by human operator.";
            } else {
              if (turnUi.responseCard) turnUi.responseCard.style.setProperty("display", "block");
              turnUi.callout.style.setProperty("display", "none");
              turnUi.textEl.textContent = final.reply || "Done.";
            }

            scrollToBottom();
          }
        })
        .catch(function (err) {
          clearInterval(turnUi.pollTimer);
          turnUi.pollTimer = null;
          setTurnRunning(false);
          turnUi.textEl.textContent = "Error: " + err.message;
        });
    }, 300);
  }

  function showInlineApproval(turnUi, reqId, toolName, toolArgs, requestHash) {
    turnUi.approvalShown = true;
    toolName = toolName || "high_risk_tool";
    toolArgs = toolArgs || {};
    requestHash = requestHash || "";

    app.showToast("Operator Authorization Required", "Action '" + toolName + "' requires human authorization. Click 'Approve Action' below.", "warn", 10000);

    var card = document.createElement("div");
    card.className = "card-approval-inline";
    turnUi.approvalCard = card;

    // 1. Header (Pure DOM)
    var header = document.createElement("div");
    header.className = "approval-card-header";

    var titleGroup = document.createElement("div");
    titleGroup.className = "approval-card-title-group";

    var shieldWrap = document.createElement("div");
    shieldWrap.className = "approval-shield-icon";
    var shieldSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    shieldSvg.setAttribute("class", "icon");
    var shieldUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
    shieldUse.setAttribute("href", "/static/icons.svg#icon-shield-alert");
    shieldSvg.appendChild(shieldUse);
    shieldWrap.appendChild(shieldSvg);

    var titleTextDiv = document.createElement("div");
    var cardTitle = document.createElement("div");
    cardTitle.className = "approval-card-title";
    cardTitle.textContent = "Operator Authorization Required";
    var cardSub = document.createElement("span");
    cardSub.className = "text-xs text-muted";
    cardSub.textContent = "Direct Inline Gate -- No need to leave console";
    titleTextDiv.appendChild(cardTitle);
    titleTextDiv.appendChild(cardSub);

    titleGroup.appendChild(shieldWrap);
    titleGroup.appendChild(titleTextDiv);

    var riskBadge = document.createElement("span");
    riskBadge.className = "badge badge-warn font-mono text-xs";
    riskBadge.textContent = "HIGH RISK";

    header.appendChild(titleGroup);
    header.appendChild(riskBadge);
    card.appendChild(header);

    // 2. Body Details (Pure DOM + textContent + formatted arguments pre)
    var body = document.createElement("div");
    body.className = "approval-card-body";

    var intro = document.createElement("div");
    intro.textContent = "AegisAgent planned a privileged action requiring verified authorization:";
    body.appendChild(intro);

    var metaRow = document.createElement("div");
    metaRow.className = "mt-xs flex items-center justify-between";

    var toolRow = document.createElement("span");
    toolRow.textContent = "Target Action: ";
    var toolStrong = document.createElement("strong");
    toolStrong.className = "approval-tool-highlight";
    toolStrong.textContent = toolName;
    toolRow.appendChild(toolStrong);

    var hashRow = document.createElement("span");
    hashRow.className = "text-xs text-muted font-mono";
    var displayHash = requestHash ? requestHash.slice(0, 12) : (reqId ? reqId.slice(0, 12) : "pending");
    hashRow.textContent = "Hash: " + displayHash;

    metaRow.appendChild(toolRow);
    metaRow.appendChild(hashRow);
    body.appendChild(metaRow);

    // Arguments pre block
    var argsLabel = document.createElement("div");
    argsLabel.className = "text-xs font-semibold text-muted uppercase mt-xs";
    argsLabel.textContent = "Arguments:";
    body.appendChild(argsLabel);

    var argsPre = document.createElement("pre");
    argsPre.className = "code-block font-mono text-xs";
    argsPre.textContent = JSON.stringify(toolArgs, null, 2);
    body.appendChild(argsPre);

    card.appendChild(body);

    // 3. Countdown Progress Bar (Pure DOM)
    var countdownWrap = document.createElement("div");
    countdownWrap.className = "approval-countdown-wrap";

    var cdSpan = document.createElement("span");
    cdSpan.textContent = "Auto-rejects in ";
    var secStrong = document.createElement("strong");
    secStrong.textContent = "60";
    cdSpan.appendChild(secStrong);
    cdSpan.appendChild(document.createTextNode("s"));

    var trackDiv = document.createElement("div");
    trackDiv.className = "approval-progress-track";
    var fillDiv = document.createElement("div");
    fillDiv.className = "approval-progress-fill";
    trackDiv.appendChild(fillDiv);

    countdownWrap.appendChild(cdSpan);
    countdownWrap.appendChild(trackDiv);
    card.appendChild(countdownWrap);

    var secondsLeft = 60;
    var timerInterval = setInterval(function () {
      secondsLeft -= 1;
      secStrong.textContent = String(Math.max(0, secondsLeft));
      fillDiv.style.width = Math.max(0, (secondsLeft / 60) * 100) + "%";
      if (secondsLeft <= 0) {
        clearInterval(timerInterval);
      }
    }, 1000);

    // 4. Action Buttons
    if (userRole === "admin") {
      var actBar = document.createElement("div");
      actBar.className = "approval-action-bar";

      var btnGroup = document.createElement("div");
      btnGroup.className = "approval-btn-group";

      var appBtn = document.createElement("button");
      appBtn.type = "button";
      appBtn.className = "btn btn-sm approval-btn-approve";
      var checkSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      checkSvg.setAttribute("class", "icon icon-sm");
      var checkUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
      checkUse.setAttribute("href", "/static/icons.svg#icon-check-circle");
      checkSvg.appendChild(checkUse);
      var appSpan = document.createElement("span");
      appSpan.textContent = "Approve Action";
      appBtn.appendChild(checkSvg);
      appBtn.appendChild(appSpan);

      appBtn.addEventListener("click", function () {
        clearInterval(timerInterval);
        appBtn.disabled = true;
        denyBtn.disabled = true;
        appSpan.textContent = "Authorizing...";

        api.post("/api/approvals/decide", { request_id: reqId, request_hash: requestHash, approved: true })
          .then(function () {
            if (turnUi && turnUi.textEl) {
              turnUi.textEl.textContent = "Authorized by operator. Executing command...";
            }
            app.showToast("Action Authorized", "Cryptographic HMAC generated. Executing command...", "ok", 4000);
            if (card.parentNode) card.parentNode.removeChild(card);
          })
          .catch(function (err) {
            app.showToast("Approval Error", err.message, "danger");
            appBtn.disabled = false;
            denyBtn.disabled = false;
            appSpan.textContent = "Approve Action";
          });
      });

      var denyBtn = document.createElement("button");
      denyBtn.type = "button";
      denyBtn.className = "btn btn-sm approval-btn-deny";
      var denySvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      denySvg.setAttribute("class", "icon icon-sm");
      var denyUse = document.createElementNS("http://www.w3.org/2000/svg", "use");
      denyUse.setAttribute("href", "/static/icons.svg#icon-x-circle");
      denySvg.appendChild(denyUse);
      var denySpan = document.createElement("span");
      denySpan.textContent = "Deny";
      denyBtn.appendChild(denySvg);
      denyBtn.appendChild(denySpan);

      denyBtn.addEventListener("click", function () {
        clearInterval(timerInterval);
        appBtn.disabled = true;
        denyBtn.disabled = true;
        denySpan.textContent = "Denying...";

        api.post("/api/approvals/decide", { request_id: reqId, request_hash: requestHash, approved: false })
          .then(function () {
            if (turnUi && turnUi.textEl) {
              turnUi.textEl.textContent = "Operator denied action.";
            }
            app.showToast("Action Denied", "Operation blocked and audited.", "warn", 4000);
            if (card.parentNode) card.parentNode.removeChild(card);
          })
          .catch(function (err) {
            app.showToast("Denial Error", err.message, "danger");
            appBtn.disabled = false;
            denyBtn.disabled = false;
            denySpan.textContent = "Deny";
          });
      });

      btnGroup.appendChild(appBtn);
      btnGroup.appendChild(denyBtn);
      actBar.appendChild(btnGroup);

      var queueLink = document.createElement("a");
      queueLink.href = "/approvals";
      queueLink.className = "btn btn-sm btn-outline text-xs";
      queueLink.textContent = "Open Approvals Queue ↗";
      queueLink.title = "View and manage in Approvals queue";
      actBar.appendChild(queueLink);

      card.appendChild(actBar);
    } else {
      var waitText = document.createElement("div");
      waitText.className = "text-xs text-muted flex items-center justify-between";

      var waitSpan = document.createElement("span");
      waitSpan.textContent = "Waiting for an administrator to review this action...";
      var waitLink = document.createElement("a");
      waitLink.href = "/approvals";
      waitLink.target = "_blank";
      waitLink.className = "text-xs text-accent";
      waitLink.textContent = "View Queue ->";

      waitText.appendChild(waitSpan);
      waitText.appendChild(waitLink);
      card.appendChild(waitText);
    }

    turnUi.bubble.appendChild(card);
    scrollToBottom();
  }

  function sendPrompt(text) {
    text = (text || "").trim();
    if (!text) return;

    setTurnRunning(true);
    appendUserMessage(text);
    chatTextarea.value = "";
    chatTextarea.style.height = "auto";

    var turnUi = createAssistantTurn();

    api.post("/api/console/send", { text: text })
      .then(function (res) {
        pollTurn(res.id, turnUi);
      })
      .catch(function (err) {
        setTurnRunning(false);
        turnUi.textEl.textContent = "Failed to dispatch request: " + err.message;
      });
  }

  window.sendConsolePrompt = sendPrompt;

  // Event Listeners
  if (chatSendBtn) {
    chatSendBtn.addEventListener("click", function () {
      sendPrompt(chatTextarea.value);
    });
  }

  chatTextarea.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendPrompt(chatTextarea.value);
    }
  });

  // Suggested prompt chip clicks
  var chips = document.querySelectorAll(".chip-btn");
  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      var prompt = chip.dataset.prompt || chip.textContent.trim();
      sendPrompt(prompt);
    });
  });

  // Start Worker Button on offline banner
  var startWorkerBtn = document.getElementById("btn-start-worker");
  if (startWorkerBtn) {
    startWorkerBtn.addEventListener("click", function () {
      startWorkerBtn.disabled = true;
      startWorkerBtn.classList.add("is-loading");
      api.post("/api/worker/start", {})
        .then(function () {
          app.showToast("Worker Starting", "Worker process initiated.", "ok");
          setTimeout(function () { window.location.reload(); }, 1200);
        })
        .catch(function (err) {
          app.showToast("Worker Error", err.message, "danger");
          startWorkerBtn.disabled = false;
          startWorkerBtn.classList.remove("is-loading");
        });
    });
  }

  // Reset Session Button
  var newSessionBtn = document.getElementById("btn-new-session");
  if (newSessionBtn) {
    newSessionBtn.addEventListener("click", function () {
      newSessionBtn.disabled = true;
      api.post("/api/console/new_session", {})
        .then(function () {
          app.showToast("Session Reset", "Started fresh chat session.", "ok");
          setTimeout(function () { window.location.reload(); }, 500);
        })
        .catch(function (err) {
          app.showToast("Reset Error", err.message, "danger");
          newSessionBtn.disabled = false;
        });
    });
  }

  // Check URL query param for instant prompt
  var urlParams = new URLSearchParams(window.location.search);
  var initialPrompt = urlParams.get("prompt");
  if (initialPrompt) {
    history.replaceState(null, "", window.location.pathname);
    setTimeout(function () {
      sendPrompt(initialPrompt);
    }, 200);
  }

  // Listen for global quarantine release from modal
  window.addEventListener("aegis:quarantine_released", function () {
    setQuarantineLockdown(false);
  });
})();
