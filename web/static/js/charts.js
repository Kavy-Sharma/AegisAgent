/**
 * AegisAgent Pure SVG Charts
 * Renders 30-min rolling stacked bars, top triggered rules, and sparklines.
 * Zero external libraries; reads CSS variables for instant theme restyling.
 */
var charts = (function () {
  function getThemeColor(varName) {
    return getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
  }

  // 1. Decisions Over Time: Stacked Bar Chart (30-min window)
  function renderDecisionTimeline(containerId, minuteBuckets) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";

    if (!minuteBuckets || minuteBuckets.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.innerHTML = '<svg class="empty-state-icon"><use href="/static/icons.svg#icon-dashboard"></use></svg>' +
        '<div class="empty-state-title">No Recent Decisions</div>' +
        '<div class="empty-state-desc">No gateway requests recorded in the last 30 minutes.</div>';
      container.appendChild(empty);
      return;
    }

    var totalDecisions = minuteBuckets.reduce(function (sum, b) {
      return sum + (b.allow || 0) + (b.block || 0) + (b.review || 0);
    }, 0);

    if (totalDecisions === 0) {
      var emptyNoData = document.createElement("div");
      emptyNoData.className = "empty-state";
      var t1 = document.createElement("div");
      t1.className = "empty-state-title";
      t1.textContent = "No Decisions in Past 30 Minutes";
      var t2 = document.createElement("div");
      t2.className = "empty-state-desc";
      t2.textContent = "Pipeline activity is currently quiet. Decisions will appear here in real time.";
      emptyNoData.appendChild(t1);
      emptyNoData.appendChild(t2);
      container.appendChild(emptyNoData);
      return;
    }

    var okColor = getThemeColor("--ok-text");
    var dangerColor = getThemeColor("--danger-text");
    var warnColor = getThemeColor("--warn-text");
    var gridColor = getThemeColor("--chart-grid");
    var textColor = getThemeColor("--muted");

    var width = container.clientWidth || 600;
    var height = 220;
    var padding = { top: 20, right: 16, bottom: 32, left: 32 };
    var plotWidth = width - padding.left - padding.right;
    var plotHeight = height - padding.top - padding.bottom;

    // Find max value per bucket
    var maxVal = 1;
    minuteBuckets.forEach(function (b) {
      var sum = (b.allow || 0) + (b.block || 0) + (b.review || 0);
      if (sum > maxVal) maxVal = sum;
    });

    var numBars = minuteBuckets.length;
    var barWidth = Math.max(4, Math.floor((plotWidth / numBars) * 0.75));
    var slotWidth = plotWidth / numBars;

    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("class", "svg-chart");

    // Grid line (horizontal)
    var gridLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
    gridLine.setAttribute("x1", padding.left);
    gridLine.setAttribute("y1", padding.top + plotHeight);
    gridLine.setAttribute("x2", width - padding.right);
    gridLine.setAttribute("y2", padding.top + plotHeight);
    gridLine.setAttribute("stroke", gridColor);
    gridLine.setAttribute("stroke-width", "1");
    svg.appendChild(gridLine);

    minuteBuckets.forEach(function (b, i) {
      var x = padding.left + i * slotWidth + (slotWidth - barWidth) / 2;
      var curY = padding.top + plotHeight;

      var allowH = Math.round(((b.allow || 0) / maxVal) * plotHeight);
      var warnH = Math.round(((b.review || 0) / maxVal) * plotHeight);
      var blockH = Math.round(((b.block || 0) / maxVal) * plotHeight);

      // Stacked segments: ALLOW (bottom), REVIEW (middle), BLOCK (top)
      if (allowH > 0) {
        curY -= allowH;
        var rAllow = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rAllow.setAttribute("x", x);
        rAllow.setAttribute("y", curY);
        rAllow.setAttribute("width", barWidth);
        rAllow.setAttribute("height", allowH);
        rAllow.setAttribute("fill", okColor);
        rAllow.setAttribute("class", "chart-bar-hover");
        rAllow.setAttribute("rx", (warnH === 0 && blockH === 0) ? "2" : "0");
        svg.appendChild(rAllow);
      }

      if (warnH > 0) {
        curY -= warnH;
        var rWarn = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rWarn.setAttribute("x", x);
        rWarn.setAttribute("y", curY);
        rWarn.setAttribute("width", barWidth);
        rWarn.setAttribute("height", warnH);
        rWarn.setAttribute("fill", warnColor);
        rWarn.setAttribute("class", "chart-bar-hover");
        rWarn.setAttribute("rx", (blockH === 0) ? "2" : "0");
        svg.appendChild(rWarn);
      }

      if (blockH > 0) {
        curY -= blockH;
        var rBlock = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rBlock.setAttribute("x", x);
        rBlock.setAttribute("y", curY);
        rBlock.setAttribute("width", barWidth);
        rBlock.setAttribute("height", blockH);
        rBlock.setAttribute("fill", dangerColor);
        rBlock.setAttribute("class", "chart-bar-hover");
        rBlock.setAttribute("rx", "2");
        svg.appendChild(rBlock);
      }

      // X-axis label every 5th minute or 10th
      if (i % 6 === 0 || i === numBars - 1) {
        var lbl = document.createElementNS("http://www.w3.org/2000/svg", "text");
        lbl.setAttribute("x", x + barWidth / 2);
        lbl.setAttribute("y", padding.top + plotHeight + 18);
        lbl.setAttribute("text-anchor", "middle");
        lbl.setAttribute("fill", textColor);
        lbl.setAttribute("font-size", "11px");
        lbl.setAttribute("font-family", "inherit");
        lbl.textContent = b.minute || "";
        svg.appendChild(lbl);
      }
    });

    container.appendChild(svg);
  }

  // 2. Top Triggered Rules: Horizontal Bar Chart
  function renderTopRules(containerId, rulesList) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";

    if (!rulesList || rulesList.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      var t1 = document.createElement("div");
      t1.className = "empty-state-title";
      t1.textContent = "Clean Inspection State";
      var t2 = document.createElement("div");
      t2.className = "empty-state-desc";
      t2.textContent = "No prompt injection or attack rules have been triggered.";
      empty.appendChild(t1);
      empty.appendChild(t2);
      container.appendChild(empty);
      return;
    }

    var accentColor = getThemeColor("--accent");
    var maxCount = Math.max.apply(null, rulesList.map(function (r) { return r.count || 0; })) || 1;

    var listWrapper = document.createElement("div");
    listWrapper.style.setProperty("display", "flex");
    listWrapper.style.setProperty("flex-direction", "column");
    listWrapper.style.setProperty("gap", "12px");
    listWrapper.style.setProperty("padding", "8px 0");

    rulesList.forEach(function (rule) {
      var row = document.createElement("div");
      row.style.setProperty("display", "flex");
      row.style.setProperty("flex-direction", "column");
      row.style.setProperty("gap", "4px");

      var head = document.createElement("div");
      head.style.setProperty("display", "flex");
      head.style.setProperty("justify-content", "space-between");
      head.style.setProperty("font-size", "12px");

      var nameSpan = document.createElement("span");
      nameSpan.className = "mono";
      nameSpan.style.setProperty("font-weight", "600");
      nameSpan.textContent = rule.id + " - " + (rule.description || rule.name || "");

      var countSpan = document.createElement("span");
      countSpan.className = "tabular-nums";
      countSpan.style.setProperty("font-weight", "700");
      countSpan.textContent = rule.count;

      head.appendChild(nameSpan);
      head.appendChild(countSpan);

      var track = document.createElement("div");
      track.style.setProperty("height", "8px");
      track.style.setProperty("background-color", "var(--surface-2)");
      track.style.setProperty("border-radius", "4px");
      track.style.setProperty("overflow", "hidden");

      var fill = document.createElement("div");
      fill.style.setProperty("height", "100%");
      fill.style.setProperty("border-radius", "4px");
      fill.style.setProperty("background-color", accentColor);
      var pct = Math.min(100, Math.round(((rule.count || 0) / maxCount) * 100));
      fill.style.setProperty("width", pct + "%");
      fill.style.setProperty("transition", "width 250ms ease");

      track.appendChild(fill);
      row.appendChild(head);
      row.appendChild(track);
      listWrapper.appendChild(row);
    });

    container.appendChild(listWrapper);
  }

  // 3. KPI Sparkline (Mini SVG polyline)
  function renderSparkline(svgElement, dataPoints, color) {
    if (!svgElement || !dataPoints || dataPoints.length < 2) return;
    svgElement.innerHTML = "";

    var width = 72;
    var height = 28;
    var max = Math.max.apply(null, dataPoints);
    var min = Math.min.apply(null, dataPoints);
    var range = max - min || 1;

    var points = dataPoints.map(function (val, idx) {
      var x = Math.round((idx / (dataPoints.length - 1)) * (width - 4) + 2);
      var y = Math.round(height - 4 - ((val - min) / range) * (height - 8) + 2);
      return x + "," + y;
    }).join(" ");

    var poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    poly.setAttribute("points", points);
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke", color || "var(--accent)");
    poly.setAttribute("stroke-width", "2");
    poly.setAttribute("stroke-linecap", "round");
    poly.setAttribute("stroke-linejoin", "round");

    svgElement.appendChild(poly);
  }

  return {
    renderDecisionTimeline: renderDecisionTimeline,
    renderTopRules: renderTopRules,
    renderSparkline: renderSparkline,
  };
})();
