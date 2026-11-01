/**
 * AegisAgent — Cryptographic Audit Log & Tamper Demonstration
 * Admin-only UI for verifying tamper-evident hash chains, searching 100k+ entries,
 * exporting formula-protected CSVs, off-site custody anchors, and running sandbox tamper demos.
 *
 * STRICT CSP COMPLIANT:
 * - 0 innerHTML calls (DOM APIs & textContent only)
 * - 0 inline styles or inline scripts
 * - 0 external libraries
 */

(function () {
  "use strict";

  // State Management
  var state = {
    page: 1,
    limit: 50,
    totalPages: 1,
    totalMatching: 0,
    totalLines: 0,
    searchQuery: "",
    decisionFilter: "",
    roleFilter: "",
    sourceFilter: "",
    datePreset: "all",
    expandedRowId: null,
    tamperLabOpen: false,
    anchorDrawerOpen: false,
    selectedAnchorFile: null,
    searchDebounceTimer: null
  };

  // Cached DOM Elements
  var dom = {};

  function initElements() {
    dom.tableBody = document.getElementById("audit-table-body");
    dom.emptyState = document.getElementById("audit-empty-state");
    dom.loadingState = document.getElementById("audit-loading-state");
    dom.recordsCount = document.getElementById("records-count-highlight");
    dom.paginationInfo = document.getElementById("pagination-info");
    dom.currentPageDisplay = document.getElementById("current-page-display");
    dom.btnPagePrev = document.getElementById("btn-page-prev");
    dom.btnPageNext = document.getElementById("btn-page-next");
    dom.selectPageSize = document.getElementById("select-page-size");

    dom.searchInput = document.getElementById("audit-search-input");
    dom.btnClearSearch = document.getElementById("btn-clear-search");
    dom.filterDecision = document.getElementById("filter-decision");
    dom.filterRole = document.getElementById("filter-role");
    dom.filterSource = document.getElementById("filter-source");
    dom.filterDatePreset = document.getElementById("filter-date-preset");
    dom.btnResetFilters = document.getElementById("btn-reset-filters");
    dom.btnEmptyReset = document.getElementById("btn-empty-reset");

    dom.btnVerifyChain = document.getElementById("btn-verify-chain");
    dom.btnVerifyLabel = document.getElementById("btn-verify-label");
    dom.verifyCard = document.getElementById("audit-verify-card");
    dom.verifyCardInner = document.getElementById("verify-card-inner");
    dom.verifyHeadline = document.getElementById("verify-headline");
    dom.verifySubline = document.getElementById("verify-subline");
    dom.verifyMeta = document.getElementById("verify-meta");
    dom.btnCloseVerify = document.getElementById("btn-close-verify");

    dom.btnExportCsv = document.getElementById("btn-export-csv");
    dom.btnExportAnchor = document.getElementById("btn-export-anchor");
    dom.btnToggleAnchorModal = document.getElementById("btn-toggle-anchor-modal");
    dom.anchorDrawer = document.getElementById("anchor-check-drawer");
    dom.btnCloseAnchorDrawer = document.getElementById("btn-close-anchor-drawer");
    dom.anchorPasteBox = document.getElementById("anchor-paste-box");
    dom.anchorDropZone = document.getElementById("anchor-drop-zone");
    dom.anchorFileInput = document.getElementById("anchor-file-input");
    dom.anchorFileName = document.getElementById("anchor-file-name");
    dom.btnSubmitAnchorCheck = document.getElementById("btn-submit-anchor-check");
    dom.anchorCheckFeedback = document.getElementById("anchor-check-feedback");

    dom.btnToggleTamperLab = document.getElementById("btn-toggle-tamper-lab");
    dom.tamperLabToggleText = document.getElementById("tamper-lab-toggle-text");
    dom.tamperPanel = document.getElementById("tamper-demo-panel");
    dom.btnTamperEdit = document.getElementById("btn-tamper-edit");
    dom.btnTamperDelete = document.getElementById("btn-tamper-delete");
    dom.btnTamperTruncate = document.getElementById("btn-tamper-truncate");
    dom.btnTamperRewrite = document.getElementById("btn-tamper-rewrite");
    dom.btnTamperReset = document.getElementById("btn-tamper-reset");
    dom.tamperEduTitle = document.getElementById("tamper-edu-title");
    dom.tamperEduText = document.getElementById("tamper-edu-text");
    dom.chainNodesContainer = document.getElementById("chain-nodes-container");
    dom.tamperChainPill = document.getElementById("tamper-chain-pill");
    dom.tamperAnchorPill = document.getElementById("tamper-anchor-pill");

    dom.csrfToken = document.getElementById("csrf-token-val");
  }

  function getCsrfToken() {
    return dom.csrfToken ? dom.csrfToken.value : "";
  }

  // =========================================================================
  // UTILITY HELPERS
  // =========================================================================

  function formatIstTimestamp(utcIsoString) {
    if (!utcIsoString) return "—";
    try {
      var d = new Date(utcIsoString);
      if (isNaN(d.getTime())) return utcIsoString;

      // Indian Standard Time is UTC + 5:30
      // Format: YYYY-MM-DD HH:mm:ss IST
      var options = {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      };
      var formatted = new Intl.DateTimeFormat("en-IN", options).format(d);
      return formatted.replace(",", "") + " IST";
    } catch (e) {
      return utcIsoString;
    }
  }

  function showToast(title, message, type) {
    if (window.app && window.app.showToast) {
      window.app.showToast(title, message, type || "info");
    } else {
      console.log("[" + (type || "info").toUpperCase() + "] " + title + ": " + message);
    }
  }

  function copyTextToClipboard(text, successMessage) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        showToast("Copied to Clipboard", successMessage || "Text copied.", "ok");
      }).catch(function () {
        fallbackCopy(text, successMessage);
      });
    } else {
      fallbackCopy(text, successMessage);
    }
  }

  function fallbackCopy(text, successMessage) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "file-input-hidden";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      showToast("Copied to Clipboard", successMessage || "Text copied.", "ok");
    } catch (err) {
      showToast("Copy Failed", "Please manually copy the hash.", "warn");
    }
    document.body.removeChild(ta);
  }

  function getDateRangeForPreset(preset) {
    if (!preset || preset === "all") return { start: null, end: null };
    var now = new Date();
    var start = new Date();

    if (preset === "today") {
      start.setHours(0, 0, 0, 0);
    } else if (preset === "7d") {
      start.setDate(now.getDate() - 7);
    } else if (preset === "30d") {
      start.setDate(now.getDate() - 30);
    }

    return {
      start: start.toISOString(),
      end: now.toISOString()
    };
  }

  // =========================================================================
  // DATA FETCHING & TABLE RENDERING
  // =========================================================================

  function fetchAuditEntries() {
    if (dom.loadingState) dom.loadingState.hidden = false;
    if (dom.emptyState) dom.emptyState.hidden = true;
    if (dom.tableBody) {
      while (dom.tableBody.firstChild) {
        dom.tableBody.removeChild(dom.tableBody.firstChild);
      }
    }

    var dates = getDateRangeForPreset(state.datePreset);
    var params = new URLSearchParams({
      page: state.page,
      limit: state.limit
    });

    if (state.searchQuery) params.append("search", state.searchQuery);
    if (state.decisionFilter) params.append("decision", state.decisionFilter);
    if (state.roleFilter) params.append("role", state.roleFilter);
    if (state.sourceFilter) params.append("source", state.sourceFilter);
    if (dates.start) params.append("start_date", dates.start);
    if (dates.end) params.append("end_date", dates.end);

    fetch("/api/audit/entries?" + params.toString())
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        if (dom.loadingState) dom.loadingState.hidden = true;
        if (data.status !== "success") {
          showToast("Query Error", data.message || "Failed to load audit records", "danger");
          return;
        }

        state.totalPages = data.total_pages || 1;
        state.totalMatching = data.total_matching || 0;
        state.totalLines = data.total_lines || 0;

        renderPagination();
        renderTableRows(data.entries || []);
      })
      .catch(function (err) {
        if (dom.loadingState) dom.loadingState.hidden = true;
        showToast("Network Error", "Unable to load audit entries: " + err.message, "danger");
      });
  }

  function renderPagination() {
    if (dom.recordsCount) {
      dom.recordsCount.textContent = "Showing " + state.totalMatching + " matching of " + state.totalLines + " total events";
    }

    if (dom.paginationInfo) {
      dom.paginationInfo.textContent = "Page " + state.page + " of " + state.totalPages + " (" + state.totalMatching + " events)";
    }

    if (dom.currentPageDisplay) {
      dom.currentPageDisplay.textContent = state.page;
    }

    if (dom.btnPagePrev) {
      dom.btnPagePrev.disabled = state.page <= 1;
    }

    if (dom.btnPageNext) {
      dom.btnPageNext.disabled = state.page >= state.totalPages;
    }
  }

  function renderTableRows(entries) {
    if (!entries || entries.length === 0) {
      if (dom.emptyState) dom.emptyState.hidden = false;
      return;
    }
    if (dom.emptyState) dom.emptyState.hidden = true;

    entries.forEach(function (entry, index) {
      var rowId = "entry-" + state.page + "-" + index;
      var mainRow = createMainRow(entry, rowId);
      dom.tableBody.appendChild(mainRow);

      var detailRow = createDetailRow(entry, rowId);
      dom.tableBody.appendChild(detailRow);
    });
  }

  function createMainRow(entry, rowId) {
    var tr = document.createElement("tr");
    tr.className = "audit-row";
    tr.id = "row-" + rowId;
    tr.setAttribute("tabindex", "0");
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-expanded", "false");

    // 1. Time (IST)
    var tdTime = document.createElement("td");
    tdTime.className = "cell-time";
    tdTime.textContent = formatIstTimestamp(entry.timestamp);
    tr.appendChild(tdTime);

    // 2. Who / Actor
    var tdActor = document.createElement("td");
    var actorBadge = document.createElement("span");
    actorBadge.className = "badge-role";
    var actorName = entry.role || entry.decided_by || entry.username || "system";
    actorBadge.textContent = actorName;
    tdActor.appendChild(actorBadge);
    tr.appendChild(tdActor);

    // 3. Plain English Summary
    var tdSummary = document.createElement("td");
    tdSummary.className = "cell-summary";
    tdSummary.textContent = entry.plain_summary || entry.reason || "System event logged";
    tr.appendChild(tdSummary);

    // 4. Decision Badge
    var tdDecision = document.createElement("td");
    var decBadge = document.createElement("span");
    decBadge.className = "badge-decision " + getDecisionClass(entry);
    decBadge.textContent = getDecisionLabel(entry);
    tdDecision.appendChild(decBadge);
    tr.appendChild(tdDecision);

    // 5. Source Badge
    var tdSource = document.createElement("td");
    var srcBadge = document.createElement("span");
    srcBadge.className = "badge-source " + getSourceClass(entry);
    srcBadge.textContent = getSourceLabel(entry);
    tdSource.appendChild(srcBadge);
    tr.appendChild(tdSource);

    // 6. Inspect Action Button
    var tdAction = document.createElement("td");
    var expandBtn = document.createElement("button");
    expandBtn.type = "button";
    expandBtn.className = "btn-row-expand";
    expandBtn.setAttribute("aria-label", "Toggle entry details");

    var chevronSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    chevronSvg.setAttribute("class", "icon");
    var useEl = document.createElementNS("http://www.w3.org/2000/svg", "use");
    useEl.setAttribute("href", "/static/icons.svg#icon-chevron-down");
    chevronSvg.appendChild(useEl);
    expandBtn.appendChild(chevronSvg);

    tdAction.appendChild(expandBtn);
    tr.appendChild(tdAction);

    // Toggle Expand on click
    function handleToggle(e) {
      if (e.target.closest(".btn-copy-hash")) return;
      toggleRowExpansion(rowId);
    }

    tr.addEventListener("click", handleToggle);
    tr.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleToggle(e);
      }
    });

    return tr;
  }

  function createDetailRow(entry, rowId) {
    var tr = document.createElement("tr");
    tr.className = "audit-detail-row";
    tr.id = "detail-" + rowId;
    tr.hidden = true;

    var td = document.createElement("td");
    td.setAttribute("colspan", "6");

    var container = document.createElement("div");
    container.className = "detail-container";

    // Hash Header Deck (Entry Hash & Prev Hash with copy buttons)
    var hashDeck = document.createElement("div");
    hashDeck.className = "detail-hashes-deck";

    var entryHash = entry.entry_hash || "—";
    var prevHash = entry.prev_hash || "0000000000000000000000000000000000000000000000000000000000000000";

    hashDeck.appendChild(createHashPill("Entry Hash (SHA-256):", entryHash));
    hashDeck.appendChild(createHashPill("Previous Hash (Chain Link):", prevHash));
    container.appendChild(hashDeck);

    // Full JSON Box
    var jsonBox = document.createElement("div");
    jsonBox.className = "detail-json-box";

    var pre = document.createElement("pre");
    pre.className = "json-pre";
    pre.textContent = JSON.stringify(entry, null, 2);
    jsonBox.appendChild(pre);
    container.appendChild(jsonBox);

    td.appendChild(container);
    tr.appendChild(td);
    return tr;
  }

  function createHashPill(label, fullHash) {
    var box = document.createElement("div");
    box.className = "hash-pill-box";

    var lbl = document.createElement("span");
    lbl.className = "hash-label";
    lbl.textContent = label;
    box.appendChild(lbl);

    var val = document.createElement("span");
    val.className = "hash-value";
    var truncated = fullHash.length > 18 ? fullHash.substring(0, 10) + "..." + fullHash.substring(fullHash.length - 8) : fullHash;
    val.textContent = truncated;
    val.title = fullHash;
    box.appendChild(val);

    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn-copy-hash";
    copyBtn.textContent = "Copy";
    copyBtn.setAttribute("aria-label", "Copy " + label);

    copyBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      copyTextToClipboard(fullHash, "Full SHA-256 hash copied to clipboard.");
      copyBtn.textContent = "Copied!";
      setTimeout(function () {
        copyBtn.textContent = "Copy";
      }, 2000);
    });

    box.appendChild(copyBtn);
    return box;
  }

  function toggleRowExpansion(rowId) {
    var mainRow = document.getElementById("row-" + rowId);
    var detailRow = document.getElementById("detail-" + rowId);
    if (!mainRow || !detailRow) return;

    var isExpanded = !detailRow.hidden;
    detailRow.hidden = isExpanded;
    mainRow.setAttribute("aria-expanded", (!isExpanded).toString());

    if (isExpanded) {
      mainRow.classList.remove("is-expanded");
    } else {
      mainRow.classList.add("is-expanded");
    }
  }

  function getDecisionClass(entry) {
    var cat = String(entry.category || "INFO").toLowerCase();
    return "badge-" + cat;
  }

  function getDecisionLabel(entry) {
    var cat = String(entry.category || "INFO").toUpperCase();
    if (cat === "ALLOWED") return "Allowed";
    if (cat === "BLOCKED") return "Blocked";
    if (cat === "WAITING") return "Waiting";
    if (cat === "ERROR") return "Error";
    return "Info";
  }

  function getSourceClass(entry) {
    if (entry.scenario_id || entry.event === "attack_lab_run") return "src-lab";
    var src = String(entry.source || "").toLowerCase();
    if (src === "tool_output" || src === "virtual") return "src-virtual";
    return "src-real";
  }

  function getSourceLabel(entry) {
    if (entry.scenario_id || entry.event === "attack_lab_run") return "Attack Lab";
    var src = String(entry.source || "").toLowerCase();
    if (src === "tool_output" || src === "virtual") return "Virtual";
    return "Real";
  }

  // =========================================================================
  // CHAIN VERIFICATION ("VERIFY CHAIN" BUTTON)
  // =========================================================================

  function runChainVerification() {
    if (!dom.btnVerifyChain) return;

    dom.btnVerifyChain.disabled = true;
    if (dom.btnVerifyLabel) dom.btnVerifyLabel.textContent = "Verifying sequence...";

    fetch("/api/audit/verify")
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        dom.btnVerifyChain.disabled = false;
        if (dom.btnVerifyLabel) dom.btnVerifyLabel.textContent = "Verify chain";

        if (dom.verifyCard) dom.verifyCard.hidden = false;

        var isIntact = Boolean(data.intact);
        var totalEntries = data.total_entries || data.count || state.totalLines || 0;

        if (dom.verifyCard) {
          dom.verifyCard.className = "audit-verify-result-card " + (isIntact ? "status-intact" : "status-tampered");
        }

        if (isIntact) {
          if (dom.verifyHeadline) dom.verifyHeadline.textContent = "Log intact: " + totalEntries + " entries";
          if (dom.verifySubline) {
            dom.verifySubline.textContent = "Every sequential block from root to head verified successfully. Tamper-evident hash chain confirmed.";
          }
          if (dom.verifyMeta) {
            dom.verifyMeta.textContent = "Status: Tamper-Evident SHA-256 Integrity Verified at " + formatIstTimestamp(new Date().toISOString());
          }
        } else {
          var firstBroken = data.first_broken_line || 1;
          if (dom.verifyHeadline) dom.verifyHeadline.textContent = "Tamper Detected at Line " + firstBroken;
          if (dom.verifySubline) {
            dom.verifySubline.textContent = data.error || data.detail || "Hash link mismatch found. Expected predecessor hash differs from stored chain.";
          }
          if (dom.verifyMeta) {
            dom.verifyMeta.textContent = "Ledger validation failed. Chain broken at record #" + firstBroken;
          }
        }
      })
      .catch(function (err) {
        dom.btnVerifyChain.disabled = false;
        if (dom.btnVerifyLabel) dom.btnVerifyLabel.textContent = "Verify chain";
        showToast("Verification Error", "Could not verify log: " + err.message, "danger");
      });
  }

  // =========================================================================
  // TAMPER DEMO WORKBENCH (COPY-ONLY SANDBOX)
  // =========================================================================

  function triggerTamperAction(action) {
    setTamperButtonsDisabled(true);

    fetch("/api/audit/tamper_demo", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": getCsrfToken()
      },
      body: JSON.stringify({ action: action })
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, status: res.status, data: data };
        });
      })
      .then(function (resp) {
        setTamperButtonsDisabled(false);
        if (!resp.ok) {
          showToast("Tamper Lab Notice", resp.data.message || "Failed to execute simulation", "warn");
          return;
        }

        var res = resp.data;
        updateTamperVisualizer(res);
      })
      .catch(function (err) {
        setTamperButtonsDisabled(false);
        showToast("Error", "Sandbox error: " + err.message, "danger");
      });
  }

  function setTamperButtonsDisabled(disabled) {
    if (dom.btnTamperEdit) dom.btnTamperEdit.disabled = disabled;
    if (dom.btnTamperDelete) dom.btnTamperDelete.disabled = disabled;
    if (dom.btnTamperTruncate) dom.btnTamperTruncate.disabled = disabled;
    if (dom.btnTamperRewrite) dom.btnTamperRewrite.disabled = disabled;
    if (dom.btnTamperReset) dom.btnTamperReset.disabled = disabled;
  }

  function updateTamperVisualizer(data) {
    if (dom.tamperEduTitle) {
      if (data.action === "edit_line") {
        dom.tamperEduTitle.textContent = "Attack Simulated: Field Payload Modification";
      } else if (data.action === "delete_line") {
        dom.tamperEduTitle.textContent = "Attack Simulated: Middle Entry Deletion";
      } else if (data.action === "truncate") {
        dom.tamperEduTitle.textContent = "Attack Simulated: Log Truncation (End Deletion)";
      } else if (data.action === "rewrite") {
        dom.tamperEduTitle.textContent = "Attack Simulated: Complete Hash Chain Rewrite";
      } else {
        dom.tamperEduTitle.textContent = "Sandbox Restored to Intact Log Copy";
      }
    }

    if (dom.tamperEduText) {
      dom.tamperEduText.textContent = data.explanation || "Chain integrity evaluated.";
    }

    if (dom.chainNodesContainer) {
      while (dom.chainNodesContainer.firstChild) {
        dom.chainNodesContainer.removeChild(dom.chainNodesContainer.firstChild);
      }

      var blocks = data.chain_blocks || [];
      blocks.forEach(function (block, idx) {
        if (idx > 0) {
          var arrow = document.createElement("div");
          arrow.className = "chain-arrow";
          arrow.textContent = "→";
          dom.chainNodesContainer.appendChild(arrow);
        }

        var node = document.createElement("div");
        var isAfterBreak = (block.status === "after_break" || block.status === "orphaned");
        node.className = "chain-node " + (isAfterBreak ? "node-after_break" : "node-" + block.status);

        var header = document.createElement("div");
        header.className = "node-header";

        var num = document.createElement("span");
        num.className = "node-number";
        num.textContent = "Block #" + block.block_number;
        header.appendChild(num);

        var statusTag = document.createElement("span");
        statusTag.className = "node-status-tag";
        if (isAfterBreak) {
          statusTag.textContent = "NOT TRUSTED";
        } else {
          statusTag.textContent = String(block.status).toUpperCase();
        }
        header.appendChild(statusTag);
        node.appendChild(header);

        var hashes = document.createElement("div");
        hashes.className = "node-hashes";

        var hLine = document.createElement("div");
        hLine.className = "node-hash-line";
        var hLbl = document.createElement("span");
        hLbl.className = "node-hash-label";
        hLbl.textContent = "Hash: ";
        hLine.appendChild(hLbl);
        hLine.appendChild(document.createTextNode(block.hash_short || "—"));
        hashes.appendChild(hLine);

        var pLine = document.createElement("div");
        pLine.className = "node-hash-line";
        var pLbl = document.createElement("span");
        pLbl.className = "node-hash-label";
        pLbl.textContent = "Prev: ";
        pLine.appendChild(pLbl);
        pLine.appendChild(document.createTextNode(block.prev_short || "000000..."));
        hashes.appendChild(pLine);
        node.appendChild(hashes);

        var ev = document.createElement("div");
        ev.className = "node-event";
        ev.textContent = block.event + " (" + block.decision + ")";
        node.appendChild(ev);

        dom.chainNodesContainer.appendChild(node);
      });
    }

    // Dual status check pills
    var chainOk = !!(data.chain_ok !== undefined ? data.chain_ok : data.chain_intact);
    var anchorOk = !!data.anchor_ok;

    if (dom.tamperChainPill) {
      if (chainOk) {
        dom.tamperChainPill.textContent = "OK";
        dom.tamperChainPill.className = "check-pill pill-ok";
      } else {
        dom.tamperChainPill.textContent = "FAILED";
        dom.tamperChainPill.className = "check-pill pill-failed";
      }
    }

    if (dom.tamperAnchorPill) {
      if (anchorOk) {
        dom.tamperAnchorPill.textContent = "MATCH";
        dom.tamperAnchorPill.className = "check-pill pill-ok";
      } else {
        dom.tamperAnchorPill.textContent = "MISMATCH";
        dom.tamperAnchorPill.className = "check-pill pill-failed";
      }
    }
  }

  // =========================================================================
  // ANCHOR VERIFICATION MODAL / DRAWER
  // =========================================================================

  function submitAnchorCheck() {
    var rawText = dom.anchorPasteBox ? dom.anchorPasteBox.value.trim() : "";

    if (!rawText && !state.selectedAnchorFile) {
      showToast("Anchor Required", "Please paste anchor JSON text or upload an anchor file.", "warn");
      return;
    }

    if (dom.btnSubmitAnchorCheck) dom.btnSubmitAnchorCheck.disabled = true;

    var promise;
    if (state.selectedAnchorFile) {
      var formData = new FormData();
      formData.append("file", state.selectedAnchorFile);
      promise = fetch("/api/audit/anchor/check", {
        method: "POST",
        headers: { "X-CSRF-Token": getCsrfToken() },
        body: formData
      });
    } else {
      promise = fetch("/api/audit/anchor/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken()
        },
        body: JSON.stringify({ anchor_text: rawText })
      });
    }

    promise
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        if (dom.btnSubmitAnchorCheck) dom.btnSubmitAnchorCheck.disabled = false;
        if (!dom.anchorCheckFeedback) return;

        dom.anchorCheckFeedback.hidden = false;
        if (data.status === "success" && data.verified) {
          dom.anchorCheckFeedback.className = "anchor-check-feedback feedback-ok";
          dom.anchorCheckFeedback.textContent = "Anchor Verified: " + data.message;
        } else {
          dom.anchorCheckFeedback.className = "anchor-check-feedback feedback-fail";
          dom.anchorCheckFeedback.textContent = "Tamper Detected: " + (data.message || "Anchor head_hash does not match active audit log.");
        }
      })
      .catch(function (err) {
        if (dom.btnSubmitAnchorCheck) dom.btnSubmitAnchorCheck.disabled = false;
        showToast("Anchor Check Failed", err.message, "danger");
      });
  }

  // =========================================================================
  // EVENT LISTENERS BINDING
  // =========================================================================

  function bindEvents() {
    // Pagination
    if (dom.btnPagePrev) {
      dom.btnPagePrev.addEventListener("click", function () {
        if (state.page > 1) {
          state.page--;
          fetchAuditEntries();
        }
      });
    }

    if (dom.btnPageNext) {
      dom.btnPageNext.addEventListener("click", function () {
        if (state.page < state.totalPages) {
          state.page++;
          fetchAuditEntries();
        }
      });
    }

    if (dom.selectPageSize) {
      dom.selectPageSize.addEventListener("change", function () {
        state.limit = parseInt(dom.selectPageSize.value, 10) || 50;
        state.page = 1;
        fetchAuditEntries();
      });
    }

    // Filters
    if (dom.filterDecision) {
      dom.filterDecision.addEventListener("change", function () {
        state.decisionFilter = dom.filterDecision.value;
        state.page = 1;
        fetchAuditEntries();
      });
    }

    if (dom.filterRole) {
      dom.filterRole.addEventListener("change", function () {
        state.roleFilter = dom.filterRole.value;
        state.page = 1;
        fetchAuditEntries();
      });
    }

    if (dom.filterSource) {
      dom.filterSource.addEventListener("change", function () {
        state.sourceFilter = dom.filterSource.value;
        state.page = 1;
        fetchAuditEntries();
      });
    }

    if (dom.filterDatePreset) {
      dom.filterDatePreset.addEventListener("change", function () {
        state.datePreset = dom.filterDatePreset.value;
        state.page = 1;
        fetchAuditEntries();
      });
    }

    // Search with 300ms debounce
    if (dom.searchInput) {
      dom.searchInput.addEventListener("input", function () {
        var query = dom.searchInput.value.trim();
        if (dom.btnClearSearch) {
          dom.btnClearSearch.hidden = !query;
        }

        clearTimeout(state.searchDebounceTimer);
        state.searchDebounceTimer = setTimeout(function () {
          state.searchQuery = query;
          state.page = 1;
          fetchAuditEntries();
        }, 300);
      });
    }

    if (dom.btnClearSearch) {
      dom.btnClearSearch.addEventListener("click", function () {
        if (dom.searchInput) dom.searchInput.value = "";
        dom.btnClearSearch.hidden = true;
        state.searchQuery = "";
        state.page = 1;
        fetchAuditEntries();
      });
    }

    // Reset Filters
    function handleResetAll() {
      if (dom.searchInput) dom.searchInput.value = "";
      if (dom.btnClearSearch) dom.btnClearSearch.hidden = true;
      if (dom.filterDecision) dom.filterDecision.value = "";
      if (dom.filterRole) dom.filterRole.value = "";
      if (dom.filterSource) dom.filterSource.value = "";
      if (dom.filterDatePreset) dom.filterDatePreset.value = "all";

      state.searchQuery = "";
      state.decisionFilter = "";
      state.roleFilter = "";
      state.sourceFilter = "";
      state.datePreset = "all";
      state.page = 1;

      fetchAuditEntries();
    }

    if (dom.btnResetFilters) dom.btnResetFilters.addEventListener("click", handleResetAll);
    if (dom.btnEmptyReset) dom.btnEmptyReset.addEventListener("click", handleResetAll);

    // Verify Chain Button
    if (dom.btnVerifyChain) {
      dom.btnVerifyChain.addEventListener("click", runChainVerification);
    }

    if (dom.btnCloseVerify) {
      dom.btnCloseVerify.addEventListener("click", function () {
        if (dom.verifyCard) dom.verifyCard.hidden = true;
      });
    }

    // Export CSV (Direct GET download with active filter parameters)
    if (dom.btnExportCsv) {
      dom.btnExportCsv.addEventListener("click", function () {
        var params = new URLSearchParams();
        if (state.searchQuery) params.append("search", state.searchQuery);
        if (state.decisionFilter) params.append("decision", state.decisionFilter);
        if (state.roleFilter) params.append("role", state.roleFilter);
        if (state.sourceFilter) params.append("source", state.sourceFilter);

        showToast("Generating CSV", "Formula-protected audit CSV export starting...", "info");
        window.location.href = "/api/audit/export/csv?" + params.toString();
      });
    }

    // Export Anchor
    if (dom.btnExportAnchor) {
      dom.btnExportAnchor.addEventListener("click", function () {
        showToast("Exporting Anchor", "Downloading external anchor. Remember to store off-site!", "info");
        window.location.href = "/api/audit/anchor/export";
      });
    }

    // Toggle Anchor Drawer
    if (dom.btnToggleAnchorModal) {
      dom.btnToggleAnchorModal.addEventListener("click", function () {
        state.anchorDrawerOpen = !state.anchorDrawerOpen;
        if (dom.anchorDrawer) dom.anchorDrawer.hidden = !state.anchorDrawerOpen;
      });
    }

    if (dom.btnCloseAnchorDrawer) {
      dom.btnCloseAnchorDrawer.addEventListener("click", function () {
        state.anchorDrawerOpen = false;
        if (dom.anchorDrawer) dom.anchorDrawer.hidden = true;
      });
    }

    // Anchor Drag & Drop
    if (dom.anchorDropZone && dom.anchorFileInput) {
      dom.anchorDropZone.addEventListener("click", function () {
        dom.anchorFileInput.click();
      });

      dom.anchorFileInput.addEventListener("change", function (e) {
        if (e.target.files && e.target.files.length > 0) {
          state.selectedAnchorFile = e.target.files[0];
          if (dom.anchorFileName) dom.anchorFileName.textContent = state.selectedAnchorFile.name;
        }
      });

      dom.anchorDropZone.addEventListener("dragover", function (e) {
        e.preventDefault();
        dom.anchorDropZone.classList.add("drag-over");
      });

      dom.anchorDropZone.addEventListener("dragleave", function () {
        dom.anchorDropZone.classList.remove("drag-over");
      });

      dom.anchorDropZone.addEventListener("drop", function (e) {
        e.preventDefault();
        dom.anchorDropZone.classList.remove("drag-over");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          state.selectedAnchorFile = e.dataTransfer.files[0];
          if (dom.anchorFileName) dom.anchorFileName.textContent = state.selectedAnchorFile.name;
        }
      });
    }

    if (dom.btnSubmitAnchorCheck) {
      dom.btnSubmitAnchorCheck.addEventListener("click", submitAnchorCheck);
    }

    // Tamper Demo Panel Toggle & Buttons
    if (dom.btnToggleTamperLab) {
      dom.btnToggleTamperLab.addEventListener("click", function () {
        state.tamperLabOpen = !state.tamperLabOpen;
        if (dom.tamperPanel) dom.tamperPanel.hidden = !state.tamperLabOpen;
        if (dom.tamperLabToggleText) {
          dom.tamperLabToggleText.textContent = state.tamperLabOpen ? "Hide demo" : "Tamper demo";
        }
        if (state.tamperLabOpen) {
          // Initialize sandbox with intact copy
          triggerTamperAction("reset");
        }
      });
    }

    if (dom.btnTamperEdit) {
      dom.btnTamperEdit.addEventListener("click", function () { triggerTamperAction("edit_line"); });
    }
    if (dom.btnTamperDelete) {
      dom.btnTamperDelete.addEventListener("click", function () { triggerTamperAction("delete_line"); });
    }
    if (dom.btnTamperTruncate) {
      dom.btnTamperTruncate.addEventListener("click", function () { triggerTamperAction("truncate"); });
    }
    if (dom.btnTamperRewrite) {
      dom.btnTamperRewrite.addEventListener("click", function () { triggerTamperAction("rewrite"); });
    }
    if (dom.btnTamperReset) {
      dom.btnTamperReset.addEventListener("click", function () { triggerTamperAction("reset"); });
    }
  }

  // Self Initialization
  document.addEventListener("DOMContentLoaded", function () {
    initElements();
    bindEvents();
    fetchAuditEntries();
    triggerTamperAction("reset");
  });

})();
