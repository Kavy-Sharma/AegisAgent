/**
 * AegisAgent — Audit Log & Cryptographic Verification
 * Pure DOM construction, safe DOM APIs only, 0 inline styles.
 * Visual model aligned with design_v2/proto.js.
 * Operates with real audit endpoints and client-side SHA-256 tamper sandbox.
 */
(function () {
  "use strict";

  var ZERO = new Array(65).join("0");
  var DEFAULT_EVENTS = [
    "admin signed in",
    "turn_light_on allowed",
    "unlock_door requested",
    "unlock_door approved by admin",
    "injection stopped at Detection",
    "turn_light_off allowed"
  ];

  var chain = [];
  var anchor = "";
  var status = [];
  var note = "The log is intact. Pick an attack, then press Verify chain to see what the check finds.";
  var chainVerdict = null;
  var anchorVerdict = null;

  var state = {
    page: 1,
    limit: 25,
    totalPages: 1,
    totalMatching: 0,
    totalLines: 0,
    search: "",
    filter: "",
    entries: []
  };

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function clear(el) {
    if (el) el.replaceChildren();
    return el;
  }

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : v);
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      var kids = [].concat(arguments[i]);
      kids.forEach(function (child) {
        if (child == null || child === false) return;
        el.append(child.nodeType ? child : document.createTextNode(child));
      });
    }
    return el;
  }

  function svgIcon(d) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    var paths = Array.isArray(d) ? d : [d];
    paths.forEach(function (pathData) {
      var p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", pathData);
      svg.appendChild(p);
    });
    return svg;
  }

  async function sha(s) {
    try {
      var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
      return Array.prototype.map.call(new Uint8Array(buf), function (x) {
        return x.toString(16).padStart(2, "0");
      }).join("");
    } catch (e) {
      var a = 0x811c9dc5, out = "";
      for (var k = 0; k < 8; k++) {
        for (var i = 0; i < s.length; i++) {
          a ^= s.charCodeAt(i) + k;
          a = Math.imul(a, 16777619) >>> 0;
        }
        out += a.toString(16).padStart(8, "0");
      }
      return out;
    }
  }

  function shortHash(x) {
    if (!x || x.length < 12) return x || "--";
    return x.slice(0, 6) + "…" + x.slice(-4);
  }

  async function buildChain(events) {
    var evList = (events && events.length >= 3) ? events : DEFAULT_EVENTS;
    chain = [];
    var prev = ZERO;
    for (var i = 0; i < evList.length; i++) {
      var hh = await sha(prev + "|" + evList[i]);
      chain.push({ text: evList[i], prev: prev, hash: hh });
      prev = hh;
    }
    anchor = chain[chain.length - 1].hash;
    status = [];
    chainVerdict = null;
    anchorVerdict = null;
    note = "The log is intact. Pick an attack, then press Verify chain to see what the check finds.";
  }

  async function rehashFrom(k) {
    for (var i = k; i < chain.length; i++) {
      chain[i].prev = i ? chain[i - 1].hash : ZERO;
      chain[i].hash = await sha(chain[i].prev + "|" + chain[i].text);
    }
  }

  function renderBlocks() {
    var blocksEl = document.getElementById("audit-chain");
    if (!blocksEl) return;
    clear(blocksEl);

    chain.forEach(function (b, i) {
      var st = status[i];
      var cls = "block " + (st ? st.cls : "");
      var blockNode = h("div", { class: cls, "data-i": i },
        h("h3", null,
          "Block " + (i + 1),
          h("span", { class: "st", text: st ? st.label : "not checked" })
        ),
        h("p", { class: "ev", text: b.text }),
        h("div", { class: "hs mono" },
          h("span", null, "hash ", h("b", { text: shortHash(b.hash) })),
          h("span", null, "prev ", h("b", { text: shortHash(b.prev) }))
        ),
        (i < chain.length - 1 ? h("div", { class: "chain-arrow-badge", "aria-hidden": "true" },
          svgIcon(["M5 12h14", "M12 5l7 7-7 7"])
        ) : null)
      );
      blocksEl.append(blockNode);
    });
  }

  function renderVerdicts() {
    var vChain = document.getElementById("verdict-chain-box");
    var vChainText = document.getElementById("verdict-chain-text");
    var vAnchor = document.getElementById("verdict-anchor-box");
    var vAnchorText = document.getElementById("verdict-anchor-text");
    var explainEl = document.getElementById("explain");

    if (vChain && vChainText) {
      vChain.className = "verdict " + (chainVerdict ? chainVerdict.cls : "");
      vChainText.textContent = chainVerdict ? chainVerdict.text : "Not run";
    }

    if (vAnchor && vAnchorText) {
      vAnchor.className = "verdict " + (anchorVerdict ? anchorVerdict.cls : "");
      vAnchorText.textContent = anchorVerdict ? anchorVerdict.text : "Not run";
    }

    if (explainEl) {
      explainEl.textContent = note;
    }
  }

  async function verifyChain() {
    var res = [];
    var firstBad = -1;

    for (var i = 0; i < chain.length; i++) {
      var b = chain[i];
      var okContent = (await sha(b.prev + "|" + b.text)) === b.hash;
      var okLink = i === 0 ? b.prev === ZERO : b.prev === chain[i - 1].hash;
      var s = !okContent ? { cls: "bad", label: "content changed" }
            : !okLink ? { cls: "bad", label: "link broken" }
            : { cls: "ok", label: "valid" };

      if (s.cls === "bad" && firstBad < 0) firstBad = i;
      res[i] = s;
    }

    status = [];
    chainVerdict = null;
    renderBlocks();
    renderVerdicts();

    var blocksEl = document.getElementById("audit-chain");
    for (var j = 0; j < chain.length; j++) {
      if (blocksEl && blocksEl.children[j]) {
        blocksEl.children[j].className = "block checking";
      }
      await sleep(120);
      status[j] = res[j];
      renderBlocks();
    }

    chainVerdict = firstBad < 0
      ? { cls: "ok", text: "Intact" }
      : { cls: "bad", text: "Broken at block " + (firstBad + 1) };

    if (firstBad >= 0) {
      note = "The check found the change at block " + (firstBad + 1) + ". Everything before it is still valid.";
    } else {
      note = "All blocks in the chain have matching SHA-256 hashes.";
    }

    // Simultaneously query server verify endpoint
    try {
      var resp = await fetch("/api/audit/verify");
      if (resp.ok) {
        var data = await resp.json();
        if (data && data.intact) {
          note += " Server log verified intact (" + (data.count || 0) + " entries).";
        }
      }
    } catch (e) {
      // server check silent fallback
    }

    renderVerdicts();
  }

  function checkAnchor() {
    var ok = chain.length >= DEFAULT_EVENTS.length && chain[DEFAULT_EVENTS.length - 1].hash === anchor;
    anchorVerdict = ok ? { cls: "ok", text: "Matches" } : { cls: "bad", text: "Does not match" };

    if (!ok && chainVerdict && chainVerdict.cls === "ok") {
      note = "The chain check passed, but the anchor does not match. Someone rewrote or shortened the log. Only the off-computer anchor catches this.";
    } else if (ok) {
      note = "Anchor hash matches the head of the log.";
    }

    renderVerdicts();
  }

  async function act(kind) {
    status = [];
    chainVerdict = null;
    anchorVerdict = null;

    if (kind === "edit") {
      if (chain.length > 2) {
        chain[2].text = "unlock_door DENIED by admin";
        note = "Block 3 was edited, but its stored hash was left alone. Press Verify chain.";
      }
    } else if (kind === "rehash") {
      if (chain.length > 2) {
        chain[2].text = "unlock_door DENIED by admin";
        chain[2].hash = await sha(chain[2].prev + "|" + chain[2].text);
        note = "Block 3 was edited and re-hashed, so it looks valid. Block 4 still points to the old hash. Press Verify chain.";
      }
    } else if (kind === "rewrite") {
      if (chain.length > 2) {
        chain[2].text = "unlock_door DENIED by admin";
        await rehashFrom(2);
        note = "Every block from 3 onward was re-hashed. The chain is self-consistent again. Press Verify chain, then Check anchor.";
      }
    } else if (kind === "delete") {
      if (chain.length > 0) {
        chain.pop();
        note = "The newest block was deleted. The remaining chain is still consistent. Press Verify chain, then Check anchor.";
      }
    } else if (kind === "reset") {
      await buildChain();
    }

    renderBlocks();
    renderVerdicts();
  }

  /* ---------- Real Audit Feed ---------- */

  function formatTime(isoStr) {
    if (!isoStr) return "--";
    try {
      var d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch (e) {
      return isoStr;
    }
  }

  function outcomeNode(entry) {
    var dec = (entry.decision || entry.status || "").toUpperCase();
    var cls = "ok";
    var label = "Allowed";
    if (dec === "BLOCK" || dec === "BLOCKED") {
      cls = "stop";
      label = "Blocked";
    } else if (dec === "WAITING" || dec === "REVIEW") {
      cls = "wait";
      label = "Waiting";
    } else if (dec === "ERROR") {
      cls = "stop";
      label = "Error";
    }
    return h("span", { class: "out " + cls },
      h("i"),
      h("span", { text: label })
    );
  }

  function renderFeed() {
    var feedEl = document.getElementById("audit-feed");
    if (!feedEl) return;
    clear(feedEl);

    if (!state.entries.length) {
      feedEl.append(h("li", null, h("p", { class: "empty", text: "No audit records found matching the filters." })));
      return;
    }

    state.entries.forEach(function (e, idx) {
      var li = h("li", null);
      var summaryText = e.reason || e.event || e.tool || "Audit event";
      var toolName = e.tool || e.event || "none";
      var timeStr = formatTime(e.timestamp);

      var rowBtn = h("button", {
        class: "row",
        type: "button",
        "aria-expanded": "false",
        onclick: function () {
          toggleDetail(idx, li, e);
        }
      },
        h("span", { class: "t mono", text: timeStr }),
        outcomeNode(e),
        h("span", { class: "txt", text: summaryText }),
        h("span", { class: "tool mono", text: toolName })
      );

      li.append(rowBtn);
      feedEl.append(li);
    });

    var infoEl = document.getElementById("audit-page-info");
    if (infoEl) {
      infoEl.textContent = "Page " + state.page + " of " + state.totalPages + " (" + state.totalMatching + " records)";
    }

    var prevBtn = document.getElementById("btn-prev-page");
    var nextBtn = document.getElementById("btn-next-page");
    if (prevBtn) prevBtn.disabled = state.page <= 1;
    if (nextBtn) nextBtn.disabled = state.page >= state.totalPages;
  }

  function toggleDetail(idx, li, entry) {
    var row = li.querySelector(".row");
    if (!row) return;

    var isOpen = row.getAttribute("aria-expanded") === "true";
    var feedEl = document.getElementById("audit-feed");
    if (feedEl) {
      feedEl.querySelectorAll(".detail").forEach(function (el) { el.remove(); });
      feedEl.querySelectorAll(".row").forEach(function (r) { r.setAttribute("aria-expanded", "false"); });
    }

    if (!isOpen) {
      row.setAttribute("aria-expanded", "true");
      var detailEl = h("div", { class: "detail" },
        h("dl", null,
          h("div", null, h("dt", { text: "Timestamp" }), h("dd", { class: "mono", text: entry.timestamp || "--" })),
          h("div", null, h("dt", { text: "Actor" }), h("dd", { text: entry.role || entry.user || "system" })),
          h("div", null, h("dt", { text: "Tool" }), h("dd", { class: "mono", text: entry.tool || "none" })),
          h("div", null, h("dt", { text: "Decision" }), h("dd", { text: entry.decision || "none" })),
          h("div", null, h("dt", { text: "Reason" }), h("dd", { text: entry.reason || "None specified" })),
          h("div", null, h("dt", { text: "Entry Hash" }), h("dd", { class: "mono", text: entry.entry_hash || entry.hash || "--" })),
          h("div", null, h("dt", { text: "Prev Hash" }), h("dd", { class: "mono", text: entry.prev_hash || "--" }))
        )
      );
      li.append(detailEl);
    }
  }

  async function fetchEntries() {
    try {
      var url = "/api/audit/entries?limit=" + encodeURIComponent(state.limit) +
                "&page=" + encodeURIComponent(state.page);
      if (state.filter) url += "&decision=" + encodeURIComponent(state.filter);
      if (state.search) url += "&search=" + encodeURIComponent(state.search);

      var resp = await fetch(url);
      if (resp.ok) {
        var data = await resp.json();
        state.entries = data.entries || [];
        state.totalMatching = data.total_matching || 0;
        state.totalLines = data.total_lines || 0;
        state.totalPages = data.total_pages || 1;
        renderFeed();

        // If initial chain not customized yet, initialize chain with recent event names
        if (state.entries.length >= 3 && chain.length === DEFAULT_EVENTS.length) {
          var realTexts = state.entries.slice(0, 6).reverse().map(function (e) {
            var action = e.tool || e.event || "action";
            var dec = (e.decision || "").toLowerCase();
            return (e.role ? e.role + ": " : "") + action + (dec ? " " + dec : "");
          });
          if (realTexts.length >= 3) {
            await buildChain(realTexts);
            renderBlocks();
            renderVerdicts();
          }
        }
      }
    } catch (e) {
      var feedEl = document.getElementById("audit-feed");
      if (feedEl) {
        clear(feedEl);
        feedEl.append(h("li", null, h("p", { class: "empty", text: "Error fetching audit records." })));
      }
    }
  }

  async function handleAnchorCheck() {
    var pasteBox = document.getElementById("anchor-paste-box");
    var feedbackEl = document.getElementById("anchor-check-feedback");
    var csrfTokenEl = document.getElementById("csrf-token-val");

    if (!pasteBox || !feedbackEl) return;
    var rawText = pasteBox.value.trim();
    if (!rawText) {
      feedbackEl.textContent = "Please paste an anchor string or JSON first.";
      feedbackEl.classList.remove("is-hidden");
      return;
    }

    feedbackEl.textContent = "Checking anchor against log...";
    feedbackEl.classList.remove("is-hidden");

    try {
      var headers = { "Content-Type": "application/json" };
      if (csrfTokenEl && csrfTokenEl.value) {
        headers["X-CSRF-Token"] = csrfTokenEl.value;
      }

      var resp = await fetch("/api/audit/anchor/check", {
        method: "POST",
        headers: headers,
        body: JSON.stringify({ anchor_text: rawText })
      });

      var data = await resp.json();
      if (resp.ok && data.verified) {
        feedbackEl.textContent = "Anchor verification PASSED: " + (data.message || "Active log matches external anchor.");
      } else {
        feedbackEl.textContent = "Anchor verification FAILED: " + (data.message || "Log does not match external anchor.");
      }
    } catch (e) {
      feedbackEl.textContent = "Error executing anchor check: " + e.message;
    }
  }

  function bindEvents() {
    var btnVerify = document.getElementById("btn-verify-chain");
    if (btnVerify) btnVerify.addEventListener("click", verifyChain);

    var btnAnchor = document.getElementById("btn-check-anchor");
    if (btnAnchor) btnAnchor.addEventListener("click", checkAnchor);

    var btnEdit = document.getElementById("btn-tamper-edit");
    if (btnEdit) btnEdit.addEventListener("click", function () { act("edit"); });

    var btnRehash = document.getElementById("btn-tamper-rehash");
    if (btnRehash) btnRehash.addEventListener("click", function () { act("rehash"); });

    var btnRewrite = document.getElementById("btn-tamper-rewrite");
    if (btnRewrite) btnRewrite.addEventListener("click", function () { act("rewrite"); });

    var btnDelete = document.getElementById("btn-tamper-delete");
    if (btnDelete) btnDelete.addEventListener("click", function () { act("delete"); });

    var btnReset = document.getElementById("btn-tamper-reset");
    if (btnReset) btnReset.addEventListener("click", function () { act("reset"); });

    var btnSubmitAnchor = document.getElementById("btn-submit-anchor-check");
    if (btnSubmitAnchor) btnSubmitAnchor.addEventListener("click", handleAnchorCheck);

    // Filter chips
    var chips = document.querySelectorAll("#audit-filter-chips .chip");
    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        chips.forEach(function (c) { c.setAttribute("aria-pressed", "false"); });
        chip.setAttribute("aria-pressed", "true");
        state.filter = chip.getAttribute("data-filter") || "";
        state.page = 1;
        fetchEntries();
      });
    });

    // Search input
    var searchInput = document.getElementById("audit-search-input");
    var searchTimer = null;
    if (searchInput) {
      searchInput.addEventListener("input", function () {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(function () {
          state.search = searchInput.value.trim();
          state.page = 1;
          fetchEntries();
        }, 300);
      });
    }

    // Pagination
    var prevBtn = document.getElementById("btn-prev-page");
    if (prevBtn) {
      prevBtn.addEventListener("click", function () {
        if (state.page > 1) {
          state.page--;
          fetchEntries();
        }
      });
    }

    var nextBtn = document.getElementById("btn-next-page");
    if (nextBtn) {
      nextBtn.addEventListener("click", function () {
        if (state.page < state.totalPages) {
          state.page++;
          fetchEntries();
        }
      });
    }
  }

  async function init() {
    bindEvents();
    await buildChain();
    renderBlocks();
    renderVerdicts();
    fetchEntries();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
