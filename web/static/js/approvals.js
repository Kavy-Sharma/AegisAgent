/**
 * AegisAgent Web UI - Approvals Queue & History Controller
 * Strict CSP: No inline event handlers or innerHTML. Pure DOM manipulation.
 */

(function () {
  "use strict";

  let seenPendingIds = new Set();
  let currentPendingData = [];
  let currentHistoryData = [];
  let currentFilter = "all";
  let pollTimer = null;
  let countdownTimer = null;
  const originalTitle = document.title || "Approvals -- AegisAgent";

  function init() {
    setupFilterChips();
    pollApprovals();
    pollTimer = setInterval(pollApprovals, 2000);
    countdownTimer = setInterval(updateCountdowns, 1000);
  }

  function setupFilterChips() {
    const chips = document.querySelectorAll(".history-filter-chip");
    chips.forEach((chip) => {
      chip.addEventListener("click", () => {
        chips.forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        currentFilter = chip.getAttribute("data-filter") || "all";
        renderHistory(currentHistoryData);
      });
    });
  }

  async function pollApprovals() {
    try {
      const [pendingRes, historyRes] = await Promise.all([
        AegisAPI.getPendingApprovals(),
        AegisAPI.getApprovalHistory()
      ]);

      if (pendingRes && pendingRes.pending !== undefined) {
        currentPendingData = pendingRes.pending || [];
        if (pendingRes.timeout_seconds !== undefined) {
          const timeoutValEl = document.getElementById("approvals-timeout-val");
          if (timeoutValEl) {
            timeoutValEl.textContent = String(pendingRes.timeout_seconds);
          }
        }
        renderPending(currentPendingData);
        updateDocumentTitle(currentPendingData.length);
      }

      if (historyRes && historyRes.history !== undefined) {
        currentHistoryData = historyRes.history || [];
        renderHistory(currentHistoryData);
      }
    } catch (err) {
      console.warn("Approvals polling error:", err);
    }
  }

  function updateDocumentTitle(count) {
    if (count > 0) {
      document.title = `(${count}) Approvals -- AegisAgent`;
    } else {
      document.title = originalTitle;
    }
  }

  function renderPending(pendingList) {
    const container = document.getElementById("pending-queue-container");
    if (!container) return;

    // Check for newly arrived approvals to toast
    pendingList.forEach((req) => {
      if (req.request_id && !seenPendingIds.has(req.request_id)) {
        seenPendingIds.add(req.request_id);
        if (window.showToast) {
          window.showToast(`New authorization request for tool: ${req.tool || "action"}`, "warn");
        }
      }
    });

    if (pendingList.length === 0) {
      container.innerHTML = "";
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "empty-state";

      const iconSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      iconSvg.setAttribute("class", "icon empty-icon");
      const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttributeNS("http://www.w3.org/1999/xlink", "href", "/static/icons.svg#icon-check-circle");
      iconSvg.appendChild(use);
      emptyDiv.appendChild(iconSvg);

      const title = document.createElement("div");
      title.className = "empty-title";
      title.textContent = "Queue Clear";
      emptyDiv.appendChild(title);

      const hint = document.createElement("div");
      hint.className = "empty-hint";
      hint.textContent = "No actions currently require cryptographic authorization. All systems operating normally.";
      emptyDiv.appendChild(hint);

      container.appendChild(emptyDiv);
      return;
    }

    // Remove any empty-state placeholder if present
    const existingEmpty = container.querySelector(".empty-state");
    if (existingEmpty) {
      existingEmpty.remove();
    }

    // Build set of current pending IDs
    const newIds = new Set(pendingList.map((r) => r.request_id));

    // Remove cards no longer pending
    const existingCards = container.querySelectorAll(".pending-approval-card");
    existingCards.forEach((card) => {
      const reqId = card.getAttribute("data-request-id");
      if (!newIds.has(reqId)) {
        card.remove();
      }
    });

    // Keyed update: reuse existing cards (keeping button state) or append new
    pendingList.forEach((req) => {
      let card = container.querySelector(`.pending-approval-card[data-request-id="${req.request_id}"]`);
      if (!card) {
        card = createPendingCard(req);
        container.appendChild(card);
      } else {
        card.setAttribute("data-expires-at", req.expires_at || "");
        if (req.expires_in_seconds !== undefined) {
          card.setAttribute("data-expires-in-seconds", String(req.expires_in_seconds));
          card.setAttribute("data-received-at", String(Date.now()));
        }
        if (req.timeout_seconds !== undefined) {
          card.setAttribute("data-total-duration", String(req.timeout_seconds));
        }
      }
    });
  }

  function createPendingCard(req) {
    const card = document.createElement("div");
    card.className = "card pending-approval-card";
    card.setAttribute("data-request-id", req.request_id);
    card.setAttribute("data-expires-at", req.expires_at || "");
    if (req.expires_in_seconds !== undefined) {
      card.setAttribute("data-expires-in-seconds", String(req.expires_in_seconds));
      card.setAttribute("data-received-at", String(Date.now()));
    }

    let totalDuration = 60;
    if (req.timeout_seconds !== undefined) {
      totalDuration = Number(req.timeout_seconds);
    } else if (req.expires_in_seconds !== undefined) {
      totalDuration = Number(req.expires_in_seconds);
    } else if (req.expires_in) {
      totalDuration = Number(req.expires_in);
    } else if (req.timeout) {
      totalDuration = Number(req.timeout);
    } else if (req.expires_at && req.created_at) {
      const diff = (new Date(req.expires_at).getTime() - new Date(req.created_at).getTime()) / 1000;
      if (diff > 0) totalDuration = diff;
    }
    card.setAttribute("data-total-duration", String(totalDuration));

    // Header: Kind & Tool & Risk
    const header = document.createElement("div");
    header.className = "pending-card-header";

    const titleGroup = document.createElement("div");
    titleGroup.className = "flex items-center gap-sm";

    const kindPill = document.createElement("span");
    kindPill.className = "pill pill-info font-mono text-xs";
    kindPill.textContent = req.kind || "tool_call";
    titleGroup.appendChild(kindPill);

    const toolName = document.createElement("h3");
    toolName.className = "font-bold text-lg";
    toolName.textContent = req.tool || "High-Risk Operation";
    titleGroup.appendChild(toolName);

    const riskLevel = (req.risk || "HIGH").toUpperCase();
    const riskPill = document.createElement("span");
    riskPill.className = riskLevel === "CRITICAL" ? "pill pill-danger" : "pill pill-warn";
    riskPill.textContent = riskLevel;
    titleGroup.appendChild(riskPill);

    header.appendChild(titleGroup);

    // ID caption
    const idSpan = document.createElement("span");
    idSpan.className = "text-xs font-mono text-muted";
    idSpan.textContent = `ID: ${(req.request_id || "").slice(0, 16)}...`;
    header.appendChild(idSpan);

    card.appendChild(header);

    // Warning strip if injection or suspicious activity flagged
    const reasons = req.reasons || [];
    const hasWarning = reasons.some((r) => /injection|suspicion|override|malicious/i.test(r)) || req.session_flagged;
    if (hasWarning) {
      const warnBox = document.createElement("div");
      warnBox.className = "warning-strip flex items-center gap-sm";
      
      const warnIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      warnIcon.setAttribute("class", "icon text-danger");
      const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttributeNS("http://www.w3.org/1999/xlink", "href", "/static/icons.svg#icon-alert-triangle");
      warnIcon.appendChild(use);
      warnBox.appendChild(warnIcon);

      const warnText = document.createElement("div");
      warnText.className = "text-sm text-danger font-semibold";
      warnText.textContent = "High Risk: This request was triggered following prompt injection or security suspicion.";
      warnBox.appendChild(warnText);

      card.appendChild(warnBox);
    }

    // Reasons list
    if (reasons.length > 0) {
      const reasonsSection = document.createElement("div");
      reasonsSection.className = "pending-card-reasons";
      const reasonsTitle = document.createElement("div");
      reasonsTitle.className = "text-xs font-semibold text-muted uppercase";
      reasonsTitle.textContent = "Triggered Review Conditions";
      reasonsSection.appendChild(reasonsTitle);

      const ul = document.createElement("ul");
      ul.className = "reasons-list";
      reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        ul.appendChild(li);
      });
      reasonsSection.appendChild(ul);
      card.appendChild(reasonsSection);
    }

    // Arguments block
    const argsSection = document.createElement("div");
    argsSection.className = "pending-card-args";
    const argsTitle = document.createElement("div");
    argsTitle.className = "text-xs font-semibold text-muted uppercase";
    argsTitle.textContent = "Operation Arguments";
    argsSection.appendChild(argsTitle);

    const pre = document.createElement("pre");
    pre.className = "code-block font-mono text-xs";
    pre.textContent = JSON.stringify(req.args || {}, null, 2);
    argsSection.appendChild(pre);
    card.appendChild(argsSection);

    // Footer: Timer countdown ring & Action buttons
    const footer = document.createElement("div");
    footer.className = "pending-card-footer flex items-center justify-between";

    // Countdown ring container
    const ringContainer = document.createElement("div");
    ringContainer.className = "countdown-ring-container flex items-center gap-sm";

    const svgRing = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svgRing.setAttribute("class", "countdown-ring-svg");
    svgRing.setAttribute("width", "36");
    svgRing.setAttribute("height", "36");
    svgRing.setAttribute("viewBox", "0 0 36 36");

    const bgCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    bgCircle.setAttribute("class", "countdown-ring-bg");
    bgCircle.setAttribute("cx", "18");
    bgCircle.setAttribute("cy", "18");
    bgCircle.setAttribute("r", "15");
    bgCircle.setAttribute("fill", "none");
    bgCircle.setAttribute("stroke-width", "3");
    svgRing.appendChild(bgCircle);

    const fillCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    fillCircle.setAttribute("class", "countdown-ring-fill");
    fillCircle.setAttribute("cx", "18");
    fillCircle.setAttribute("cy", "18");
    fillCircle.setAttribute("r", "15");
    fillCircle.setAttribute("fill", "none");
    fillCircle.setAttribute("stroke-width", "3");
    fillCircle.setAttribute("stroke-dasharray", "94.25");
    fillCircle.setAttribute("stroke-dashoffset", "0");
    svgRing.appendChild(fillCircle);

    ringContainer.appendChild(svgRing);

    const countdownText = document.createElement("span");
    countdownText.className = "countdown-text font-mono text-sm font-semibold";
    countdownText.textContent = "--s";
    ringContainer.appendChild(countdownText);

    footer.appendChild(ringContainer);

    // Action buttons
    const actionGroup = document.createElement("div");
    actionGroup.className = "flex items-center gap-sm";

    const denyBtn = document.createElement("button");
    denyBtn.className = "btn btn-danger btn-sm";
    denyBtn.textContent = "Deny";
    denyBtn.addEventListener("click", () => handleDecision(req.request_id, req.request_hash, false, denyBtn, approveBtn));
    actionGroup.appendChild(denyBtn);

    const approveBtn = document.createElement("button");
    approveBtn.className = "btn btn-primary btn-sm";
    approveBtn.textContent = "Authorize Action";
    approveBtn.addEventListener("click", () => handleDecision(req.request_id, req.request_hash, true, approveBtn, denyBtn));
    actionGroup.appendChild(approveBtn);

    footer.appendChild(actionGroup);
    card.appendChild(footer);

    return card;
  }

  function updateCountdowns() {
    const cards = document.querySelectorAll(".pending-approval-card");
    const now = Date.now();

    cards.forEach((card) => {
      let diffSec = null;
      const expInSecStr = card.getAttribute("data-expires-in-seconds");
      const recAtStr = card.getAttribute("data-received-at");

      if (expInSecStr !== null && recAtStr !== null) {
        const expInSec = parseFloat(expInSecStr);
        const recAt = parseFloat(recAtStr);
        const elapsed = Math.floor((now - recAt) / 1000);
        diffSec = Math.max(0, expInSec - elapsed);
      } else {
        const expStr = card.getAttribute("data-expires-at");
        if (!expStr) return;
        const expTime = new Date(expStr).getTime();
        diffSec = Math.max(0, Math.floor((expTime - now) / 1000));
      }

      const textEl = card.querySelector(".countdown-text");
      const ringFill = card.querySelector(".countdown-ring-fill");
      const buttons = card.querySelectorAll("button");

      if (textEl) {
        textEl.textContent = `${diffSec}s remaining`;
      }

      if (ringFill) {
        const totalDuration = parseFloat(card.getAttribute("data-total-duration")) || 60;
        const fraction = Math.max(0, Math.min(1, diffSec / totalDuration));
        const offset = 94.25 * (1 - fraction);
        ringFill.style.strokeDashoffset = offset.toFixed(2);
        if (diffSec <= 5) {
          ringFill.style.stroke = "var(--danger)";
        } else if (diffSec <= 12) {
          ringFill.style.stroke = "var(--warn)";
        } else {
          ringFill.style.stroke = "var(--accent)";
        }
      }

      if (diffSec <= 0) {
        if (textEl) textEl.textContent = "Expired";
        buttons.forEach((b) => {
          b.disabled = true;
          b.classList.add("btn-disabled");
        });
      }
    });
  }

  async function handleDecision(requestId, requestHash, approved, activeBtn, otherBtn) {
    activeBtn.disabled = true;
    otherBtn.disabled = true;
    const origText = activeBtn.textContent;
    activeBtn.textContent = "Submitting...";

    try {
      const res = await AegisAPI.decideApproval(requestId, requestHash, approved);
      if (res && res.status === "ok") {
        if (window.showToast) {
          window.showToast(approved ? "Operation authorized." : "Operation denied.", approved ? "ok" : "warn");
        }
        await pollApprovals();
      } else {
        const msg = (res && res.error) || "Decision submission failed.";
        if (window.showToast) window.showToast(msg, "danger");
        activeBtn.disabled = false;
        otherBtn.disabled = false;
        activeBtn.textContent = origText;
      }
    } catch (err) {
      if (window.showToast) window.showToast(err.message || "Failed to communicate decision.", "danger");
      activeBtn.disabled = false;
      otherBtn.disabled = false;
      activeBtn.textContent = origText;
    }
  }

  function renderHistory(historyList) {
    const tbody = document.getElementById("approval-history-tbody");
    if (!tbody) return;

    let filtered = historyList;
    if (currentFilter === "approved") {
      filtered = historyList.filter((item) => item.approved === true);
    } else if (currentFilter === "denied") {
      filtered = historyList.filter((item) => item.approved === false && !item.timed_out);
    } else if (currentFilter === "timed_out") {
      filtered = historyList.filter((item) => item.timed_out === true);
    }

    tbody.innerHTML = "";

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "text-center text-muted py-lg";
      td.textContent = "No authorization history records match the selected filter.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    filtered.slice(0, 50).forEach((entry) => {
      const tr = document.createElement("tr");

      // Timestamp IST with date + time
      const tdTime = document.createElement("td");
      tdTime.className = "font-mono text-xs whitespace-nowrap text-muted";
      tdTime.textContent = formatIstDateTime(entry.timestamp || entry.decided_at);
      tr.appendChild(tdTime);

      // Tool / Operation
      const tdTool = document.createElement("td");
      tdTool.className = "font-semibold";
      tdTool.textContent = entry.tool || (entry.reason && entry.reason.includes("unlock") ? "unlock_door" : (entry.reason && entry.reason.includes("alarm") ? "activate_alarm" : (entry.kind || "High-Risk Actuation")));
      tr.appendChild(tdTool);

      // Status Pill
      const tdStatus = document.createElement("td");
      const pill = document.createElement("span");
      if (entry.timed_out) {
        pill.className = "pill pill-warn text-xs";
        pill.textContent = "Timed Out";
      } else if (entry.approved) {
        pill.className = "pill pill-ok text-xs";
        pill.textContent = "Approved";
      } else {
        pill.className = "pill pill-danger text-xs";
        pill.textContent = "Denied";
      }
      tdStatus.appendChild(pill);
      tr.appendChild(tdStatus);

      // Operator / Decided By
      const tdBy = document.createElement("td");
      tdBy.className = "text-xs font-mono";
      tdBy.textContent = entry.decided_by || entry.username || "operator";
      tr.appendChild(tdBy);

      // Reason / Detail
      const tdReason = document.createElement("td");
      tdReason.className = "text-xs text-muted";
      tdReason.textContent = entry.reason || "--";
      tr.appendChild(tdReason);

      tbody.appendChild(tr);
    });
  }

  function formatIstDateTime(isoStr) {
    if (!isoStr) return "--";
    try {
      const date = new Date(isoStr);
      return (
        date.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          year: "numeric",
          month: "short",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }) + " IST"
      );
    } catch {
      return isoStr;
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
