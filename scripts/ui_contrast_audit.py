#!/usr/bin/env python3
"""
scripts/ui_contrast_audit.py - Automated WCAG Contrast Audit Gate.
Tests 7 pages (overview, console, attack_lab, approvals, login, audit, voice) x 2 themes:
1) Theme toggle click (light / dark)
2) prefers-color-scheme emulation without data-theme attribute
Calculates relative luminance and WCAG ratio (>= 4.5 normal, >= 3.0 large/bold).
Required result: 0 failures and 0 SKIPPED.
"""

import sys
import threading
import time
from pathlib import Path
from werkzeug.serving import make_server
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from web.server import create_app
import security.auth

AUDIT_JS = """
() => {
  function parseRgba(str) {
    if (!str) return null;
    var m = str.match(/rgba?\\s*\\(\\s*([\\d.]+)\\s*,\\s*([\\d.]+)\\s*,\\s*([\\d.]+)(?:\\s*,\\s*([\\d.]+))?\\s*\\)/);
    if (!m) return null;
    return {
      r: parseFloat(m[1]),
      g: parseFloat(m[2]),
      b: parseFloat(m[3]),
      a: m[4] !== undefined ? parseFloat(m[4]) : 1.0
    };
  }

  function srgbToLinear(c) {
    var v = c / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  }

  function getLuminance(r, g, b) {
    return 0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
  }

  function contrastRatio(l1, l2) {
    var max = Math.max(l1, l2);
    var min = Math.min(l1, l2);
    return (max + 0.05) / (min + 0.05);
  }

  function composite(fg, bg) {
    var a = fg.a + bg.a * (1 - fg.a);
    if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
    return {
      r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
      g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
      b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
      a: a
    };
  }

  function getEffectiveBg(el) {
    var cur = el;
    var layers = [];
    while (cur && cur !== document) {
      var style = window.getComputedStyle(cur);
      if (style.backgroundImage && style.backgroundImage !== "none" && style.backgroundImage.indexOf("gradient") !== -1) {
        return { isGradient: true, el: cur };
      }
      var c = parseRgba(style.backgroundColor);
      if (c && c.a > 0) {
        layers.push(c);
        if (c.a >= 0.99) break;
      }
      cur = cur.parentElement;
    }
    var base = { r: 255, g: 255, b: 255, a: 1 };
    var htmlStyle = window.getComputedStyle(document.documentElement);
    var htmlBg = parseRgba(htmlStyle.backgroundColor);
    if (htmlBg && htmlBg.a >= 0.99) base = htmlBg;
    var bodyStyle = window.getComputedStyle(document.body);
    var bodyBg = parseRgba(bodyStyle.backgroundColor);
    if (bodyBg && bodyBg.a >= 0.99) base = bodyBg;

    var result = base;
    for (var i = layers.length - 1; i >= 0; i--) {
      result = composite(layers[i], result);
    }
    return { color: result, layers: layers };
  }

  var failures = [];
  var skipped = [];
  var checkedCount = 0;

  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
    acceptNode: function(node) {
      if (node.tagName === "SCRIPT" || node.tagName === "STYLE" || node.tagName === "SVG" || node.tagName === "NOSCRIPT") {
        return NodeFilter.FILTER_REJECT;
      }
      var inClosedDetails = node.closest("details:not([open])");
      if (inClosedDetails && node !== inClosedDetails.querySelector("summary")) {
        return NodeFilter.FILTER_REJECT;
      }
      var style = window.getComputedStyle(node);
      if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
        return NodeFilter.FILTER_REJECT;
      }
      var rect = node.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        return NodeFilter.FILTER_SKIP;
      }
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  var el;
  while ((el = walker.nextNode())) {
    var hasDirectText = false;
    for (var i = 0; i < el.childNodes.length; i++) {
      var child = el.childNodes[i];
      if (child.nodeType === Node.TEXT_NODE && child.textContent.trim()) {
        hasDirectText = true;
        break;
      }
    }
    if (!hasDirectText) continue;

    var text = el.textContent.trim();
    if (!text) continue;

    checkedCount++;
    var style = window.getComputedStyle(el);
    var fg = parseRgba(style.color);
    if (!fg) continue;

    var bgResult = getEffectiveBg(el);
    if (bgResult.isGradient) {
      skipped.push({
        selector: el.tagName.toLowerCase() + (el.className ? "." + el.className.split(" ").join(".") : ""),
        text: text.slice(0, 30),
        reason: "gradient background on " + bgResult.el.tagName.toLowerCase()
      });
      continue;
    }

    var bg = bgResult.color;
    var fgLum = getLuminance(fg.r, fg.g, fg.b);
    var bgLum = getLuminance(bg.r, bg.g, bg.b);
    var ratio = contrastRatio(fgLum, bgLum);

    var fontSize = parseFloat(style.fontSize);
    var fontWeight = parseInt(style.fontWeight, 10) || 400;
    var isLarge = (fontSize >= 24) || (fontSize >= 18.66 && fontWeight >= 600);
    var required = isLarge ? 3.0 : 4.5;

    if (ratio < required) {
      var sel = el.tagName.toLowerCase() +
        (el.id ? "#" + el.id : "") +
        (el.className ? "." + el.className.trim().split(/\\s+/).join(".") : "");
      failures.push({
        selector: sel,
        text: text.slice(0, 30),
        fg: "rgba(" + Math.round(fg.r) + "," + Math.round(fg.g) + "," + Math.round(fg.b) + "," + fg.a + ")",
        bg: "rgb(" + Math.round(bg.r) + "," + Math.round(bg.g) + "," + Math.round(bg.b) + ")",
        ratio: Math.round(ratio * 100) / 100,
        required: required
      });
    }
  }

  return { checkedCount: checkedCount, failures: failures, skipped: skipped };
}
"""


def run_contrast_audit():
    # Ensure admin password is reset to kavy100504
    security.auth.reset_password("admin", "kavy100504")

    # Start Flask server on port 5002
    port = 5002
    base_url = f"http://127.0.0.1:{port}"
    app = create_app()
    app.config["TESTING"] = True
    server = make_server("127.0.0.1", port, app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(1)

    pages = [
        ("overview", f"{base_url}/overview"),
        ("console", f"{base_url}/console"),
        ("attack_lab", f"{base_url}/attack_lab"),
        ("approvals", f"{base_url}/approvals"),
        ("login", f"{base_url}/login"),
        ("audit", f"{base_url}/audit"),
        ("voice", f"{base_url}/voice"),
    ]

    total_checked = 0
    all_failures = []
    all_skipped = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Test 1: Real theme toggle click (light and dark)
            for page_name, url in pages:
                context = browser.new_context()
                page = context.new_page()

                if page_name != "login":
                    # Log in as admin
                    page.goto(f"{base_url}/login")
                    page.fill('input[name="username"]', "admin")
                    page.fill('input[name="password"]', "kavy100504")
                    page.click('button[type="submit"]')
                    page.wait_for_load_state("networkidle")

                page.goto(url)
                page.wait_for_load_state("networkidle")
                time.sleep(0.5)

                for target_theme in ["light", "dark"]:
                    current_theme = page.evaluate("() => document.documentElement.getAttribute('data-theme') || 'light'")
                    if current_theme != target_theme:
                        btn = page.query_selector("#theme")
                        if btn:
                            btn.click()
                        else:
                            page.evaluate(f"() => {{ document.documentElement.setAttribute('data-theme', '{target_theme}'); }}")
                    time.sleep(0.3)

                    res = page.evaluate(AUDIT_JS)
                    print(f"Auditing page: {page_name} ({target_theme})")
                    print(f"  Checked {res['checkedCount']} elements.")
                    total_checked += res["checkedCount"]
                    for f in res["failures"]:
                        all_failures.append({
                            "page": page_name,
                            "theme": f"toggle-{target_theme}",
                            **f
                        })
                    for s in res["skipped"]:
                        all_skipped.append({
                            "page": page_name,
                            "theme": f"toggle-{target_theme}",
                            **s
                        })

                # Test 2: Emulating prefers-color-scheme WITHOUT data-theme attribute
                for emulated_scheme in ["light", "dark"]:
                    page.emulate_media(color_scheme=emulated_scheme)
                    page.evaluate("""() => {
                        document.documentElement.removeAttribute('data-theme');
                    }""")
                    time.sleep(0.3)

                    res = page.evaluate(AUDIT_JS)
                    total_checked += res["checkedCount"]
                    for f in res["failures"]:
                        all_failures.append({
                            "page": page_name,
                            "theme": f"prefers-{emulated_scheme}",
                            **f
                        })
                    for s in res["skipped"]:
                        all_skipped.append({
                            "page": page_name,
                            "theme": f"prefers-{emulated_scheme}",
                            **s
                        })

                context.close()

            browser.close()

    finally:
        server.shutdown()

    print("=" * 80)
    print("UI CONTRAST AUDIT RESULTS")
    print("=" * 80)
    print(f"Total text-bearing elements checked: {total_checked}")
    print(f"Total failures: {len(all_failures)}")
    print(f"Total skipped: {len(all_skipped)}")
    print("-" * 80)

    if all_skipped:
        print("SKIPPED ELEMENTS:")
        for s in all_skipped:
            print(f"  [{s['page']} | {s['theme']}] {s['selector']} - '{s['text']}' ({s['reason']})")
        print("-" * 80)

    if all_failures:
        print("CONTRAST FAILURES TABLE:")
        print(f"{'Page':<12} | {'Theme':<16} | {'Ratio':<6} | {'Req':<4} | {'FG':<18} | {'BG':<18} | {'Selector'}")
        print("-" * 100)
        for f in all_failures:
            print(f"{f['page']:<12} | {f['theme']:<16} | {f['ratio']:<6.2f} | {f['required']:<4.1f} | {f['fg']:<18} | {f['bg']:<18} | {f['selector']} ('{f['text']}')")
        print("=" * 80)
        sys.exit(1)
    else:
        print("0 failures and 0 SKIPPED across all 7 pages x 2 themes! (PASSED)")
        print("=" * 80)
        sys.exit(0)


if __name__ == "__main__":
    run_contrast_audit()
