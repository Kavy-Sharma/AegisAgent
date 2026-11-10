/**
 * AURA Voice Input - AegisAgent (v2)
 * AudioContext AnalyserNode reactive particle orb, live interim/final transcript,
 * push-to-talk + typed fallback, real AegisGateLine pipeline polling,
 * optional plain speechSynthesis replies (default OFF), and last-5 command history.
 * Pure DOM: strictly zero innerHTML and zero inline HTML style attributes.
 */
(function () {
  "use strict";

  var canvas = document.getElementById("voice-sphere-canvas");
  if (!canvas) return;

  var ctx = canvas.getContext("2d");
  var GL = window.AegisGateLine || {};
  var DM = window.AegisDecisionMap || {};
  var h = GL.h || function (tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") e.className = v;
        else if (k === "text") e.textContent = v;
        else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? "" : v);
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      [].concat(arguments[i]).forEach(function (c) {
        if (c == null || c === false) return;
        e.append(c.nodeType ? c : document.createTextNode(c));
      });
    }
    return e;
  };
  var clear = GL.clear || function (el) { el.replaceChildren(); return el; };

  // DOM Elements
  var orbCard = document.getElementById("voice-orb-card");
  var canvasWrap = document.getElementById("voice-canvas-wrap");
  var reducedRing = document.getElementById("voice-reduced-ring");
  var micTrigger = document.getElementById("voice-mic-trigger");
  var statusBadge = document.getElementById("orb-status-text");
  var statusDot = document.getElementById("orb-pulse-dot");
  var langBtnEn = document.getElementById("lang-btn-en");
  var langBtnHi = document.getElementById("lang-btn-hi");
  var speakerToggle = document.getElementById("voice-speaker-toggle");
  var speakerLabel = document.getElementById("speaker-label");
  var replayBtn = document.getElementById("voice-replay-audio-btn");
  var finalSpan = document.getElementById("voice-transcript-final");
  var interimSpan = document.getElementById("voice-transcript-interim");
  var agentTextEl = document.getElementById("voice-agent-text");
  var userLangLabel = document.getElementById("user-lang-label");
  var hintEl = document.getElementById("voice-instruction-hint");
  var errorBanner = document.getElementById("voice-error-banner");
  var errorTextEl = document.getElementById("voice-error-text");
  var retryBtn = document.getElementById("voice-retry-btn");
  var srBanner = document.getElementById("voice-sr-banner");
  var typedForm = document.getElementById("voice-typed-form");
  var typedInput = document.getElementById("voice-typed-input");
  var typedSubmit = document.getElementById("voice-typed-submit");
  var resultCard = document.getElementById("voice-result-card");
  var outcomeBadge = document.getElementById("voice-outcome-badge");
  var turnMetaEl = document.getElementById("voice-turn-meta");
  var railHost = document.getElementById("voice-rail-host");
  var approvalAlert = document.getElementById("voice-approval-alert");
  var approvalToolEl = document.getElementById("voice-approval-tool");
  var approvalCountdownEl = document.getElementById("voice-approval-countdown");
  var stayBtn = document.getElementById("voice-stay-btn");
  var historyList = document.getElementById("voice-history");

  // Environment / Stage Mapping
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
  var rail = null;
  if (railHost && GL.createRail) {
    rail = GL.createRail(railHost, {
      compact: true,
      labels: stageLabels,
      idle: "Ready for voice command."
    });
  }

  // Runtime State
  var currentState = "idle"; // 'idle' | 'listening' | 'thinking' | 'speaking'
  var currentLang = "en";    // 'en' | 'hi'
  var speakerEnabled = false; // Default OFF per requirement C.4
  var isRecognizing = false;
  var isTurnRunning = false;
  var activeRecognition = null;
  var lastPlainReply = "";
  var lastCommandText = "";
  var audioPrimed = false;
  var approvalCountdownTimer = null;
  var thinkingTicker = null;
  var thinkingStartMs = null;
  var activeStage = null;
  var hasSettledResult = false;
  var commandHistory = [];

  // Push-to-talk hold detection
  var pointerDownAt = 0;
  var justStartedOnPointerDown = false;
  var holdCommitPending = false;
  var latestInterimTranscript = "";

  // Web Audio AnalyserNode state
  var audioCtx = null;
  var analyserNode = null;
  var micStream = null;
  var freqData = null;
  var smoothedMicLevel = 0;

  function isReducedMotion() {
    return Boolean(
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function getSpeechRecognitionCtor() {
    return window.SpeechRecognition || window.webkitSpeechRecognition || null;
  }

  // =========================================================================
  // 1. Reactive 3D Particle Sphere (with AnalyserNode + reduced-motion ring)
  // =========================================================================

  var numParticles = 240;
  var particles = [];
  var baseRadius = 74;
  var rotX = 0.25;
  var rotY = 0;
  var fov = 260;
  var animTime = 0;
  var rafId = null;

  var phiRatio = (1 + Math.sqrt(5)) / 2;
  for (var idx = 0; idx < numParticles; idx++) {
    var theta = (2 * Math.PI * idx) / phiRatio;
    var phi = Math.acos(1 - (2 * (idx + 0.5)) / numParticles);
    particles.push({
      theta: theta,
      phi: phi,
      baseX: Math.sin(phi) * Math.cos(theta),
      baseY: Math.cos(phi),
      baseZ: Math.sin(phi) * Math.sin(theta),
      phase: (idx * 0.37) % (Math.PI * 2),
      variant: idx % 4
    });
  }

  function sampleMicLevel() {
    if (currentState !== "listening") {
      smoothedMicLevel *= 0.82;
      return smoothedMicLevel;
    }
    var rawLevel = 0;
    if (analyserNode && freqData) {
      analyserNode.getByteTimeDomainData(freqData);
      var sumSq = 0;
      for (var i = 0; i < freqData.length; i++) {
        var norm = (freqData[i] - 128) / 128;
        sumSq += norm * norm;
      }
      var rms = Math.sqrt(sumSq / freqData.length);
      rawLevel = Math.min(1, rms * 4.5);
    } else {
      // Gentle fallback pulse when speech stub is used without live hardware audio stream
      rawLevel = 0.22 + 0.14 * Math.sin(animTime * 3.5);
    }
    smoothedMicLevel = smoothedMicLevel * 0.7 + rawLevel * 0.3;
    return smoothedMicLevel;
  }

  function paletteForState(isLight, vIdx) {
    if (currentState === "listening") {
      return [
        [22, 163, 74],
        [16, 185, 129],
        [14, 165, 233],
        [52, 211, 153]
      ][vIdx];
    }
    if (currentState === "thinking") {
      return [
        [37, 99, 235],
        [6, 182, 212],
        [56, 189, 248],
        [99, 102, 241]
      ][vIdx];
    }
    if (currentState === "speaking") {
      return [
        [124, 58, 237],
        [14, 165, 233],
        [168, 85, 247],
        [20, 184, 166]
      ][vIdx];
    }
    if (isLight) {
      return [
        [29, 78, 216],
        [2, 132, 199],
        [79, 70, 229],
        [13, 148, 136]
      ][vIdx];
    }
    return [
      [56, 189, 248],
      [96, 165, 250],
      [167, 139, 250],
      [45, 212, 191]
    ][vIdx];
  }

  function drawStaticCore() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    var cx = canvas.width / 2;
    var cy = canvas.height / 2;
    var isLight = document.documentElement.getAttribute("data-theme") === "light";
    var rgb = paletteForState(isLight, 0);
    var grad = ctx.createRadialGradient(cx, cy, 8, cx, cy, 100);
    grad.addColorStop(0, "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ", 0.85)");
    grad.addColorStop(0.55, "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ", 0.25)");
    grad.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(cx, cy, 100, 0, Math.PI * 2);
    ctx.fill();
  }

  function renderFrame() {
    if (isReducedMotion()) {
      drawStaticCore();
      rafId = null;
      return;
    }

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    var cx = canvas.width / 2;
    var cy = canvas.height / 2;
    var isLight = document.documentElement.getAttribute("data-theme") === "light";
    var level = sampleMicLevel();

    var rotSpeed = 0.007;
    var waveAmp = 8;
    var waveFreq = 3.0;
    var dynamicRadius = baseRadius;

    if (currentState === "listening") {
      rotSpeed = 0.015 + level * 0.02;
      waveAmp = 12 + level * 26;
      waveFreq = 4.4;
      dynamicRadius = baseRadius + level * 32;
    } else if (currentState === "thinking") {
      rotSpeed = 0.036;
      waveAmp = 18;
      waveFreq = 6.5;
      dynamicRadius = baseRadius + 4 * Math.sin(animTime * 2.5);
    } else if (currentState === "speaking") {
      rotSpeed = 0.02;
      waveAmp = 22;
      waveFreq = 4.2;
      dynamicRadius = baseRadius + 10 * Math.abs(Math.sin(animTime * 3.0));
    }

    if (canvasWrap) {
      canvasWrap.style.setProperty("--mic-level", level.toFixed(3));
    }

    var bloomRgb = paletteForState(isLight, 0);
    var bloom = ctx.createRadialGradient(cx, cy, 18, cx, cy, 165 + level * 30);
    bloom.addColorStop(0, "rgba(" + bloomRgb[0] + "," + bloomRgb[1] + "," + bloomRgb[2] + ", " + (isLight ? 0.16 : 0.14) + ")");
    bloom.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = bloom;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    rotY += rotSpeed;
    rotX += rotSpeed * 0.32;
    animTime += 0.04;

    var projected = [];
    for (var i = 0; i < numParticles; i++) {
      var p = particles[i];
      var disp = Math.sin(p.theta * waveFreq + animTime + p.phase) *
                 Math.cos(p.phi * waveFreq - animTime * 0.8) * waveAmp;
      var r = dynamicRadius + disp;
      var x = p.baseX * r;
      var y = p.baseY * r;
      var z = p.baseZ * r;

      var x1 = x * Math.cos(rotY) + z * Math.sin(rotY);
      var z1 = -x * Math.sin(rotY) + z * Math.cos(rotY);
      var y1 = y * Math.cos(rotX) - z1 * Math.sin(rotX);
      var z2 = y * Math.sin(rotX) + z1 * Math.cos(rotX);

      var scale = fov / (fov + z2 + 210);
      var px = cx + x1 * scale;
      var py = cy + y1 * scale;
      var depth = Math.max(0.18, Math.min(1.0, (z2 + dynamicRadius) / (2 * dynamicRadius || 1)));
      projected.push({ x: px, y: py, z: z2, scale: Math.max(0.25, scale), depth: depth, variant: p.variant });
    }

    projected.sort(function (a, b) { return b.z - a.z; });
    for (var k = 0; k < projected.length; k++) {
      var pt = projected[k];
      var rgb = paletteForState(isLight, pt.variant);
      var alpha = (isLight ? 0.35 : 0.3) + pt.depth * 0.65;
      var rad = (1.6 + pt.depth * 2.2) * pt.scale;
      ctx.fillStyle = "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + "," + alpha.toFixed(2) + ")";
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, rad, 0, Math.PI * 2);
      ctx.fill();
    }

    rafId = window.requestAnimationFrame(renderFrame);
  }

  function ensureRenderLoop() {
    if (isReducedMotion()) {
      drawStaticCore();
      return;
    }
    if (!rafId) {
      rafId = window.requestAnimationFrame(renderFrame);
    }
  }

  // =========================================================================
  // 2. Orb & Mic Stream Management
  // =========================================================================

  function setOrbState(state, badgeText) {
    currentState = state;
    if (orbCard) orbCard.setAttribute("data-state", state);
    if (statusBadge) {
      statusBadge.textContent = badgeText || (
        state === "listening" ? "LISTENING" :
        state === "thinking" ? "THINKING" :
        state === "speaking" ? "SPEAKING" : "STANDBY"
      );
    }
    if (statusDot) {
      var labelUpper = String(badgeText || "").toUpperCase();
      var dotCls = state === "thinking" ? "warn"
        : state === "speaking" ? "accent"
        : (labelUpper === "BLOCKED" || labelUpper === "ERROR") ? "stop"
        : (labelUpper === "WAITING" || labelUpper === "APPROVAL NEEDED") ? "warn"
        : "live";
      statusDot.className = "pulse-dot " + dotCls;
    }

    var listeningActive = (state === "listening");
    if (micTrigger) {
      micTrigger.classList.toggle("listening", listeningActive);
      micTrigger.setAttribute("aria-pressed", String(listeningActive));
    }
    document.querySelectorAll(".mic-wave-ring").forEach(function (ring) {
      ring.classList.toggle("active", listeningActive);
    });
    if (reducedRing) {
      reducedRing.classList.toggle("is-active", state !== "idle");
      reducedRing.setAttribute("data-state", state);
    }
    ensureRenderLoop();
  }

  function stopMicStream() {
    if (micStream) {
      try {
        micStream.getTracks().forEach(function (t) { t.stop(); });
      } catch (e) {}
      micStream = null;
    }
    if (audioCtx) {
      try { audioCtx.close(); } catch (e) {}
      audioCtx = null;
    }
    analyserNode = null;
    freqData = null;
  }

  function startMicAnalyser() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      return Promise.resolve({ denied: false });
    }
    return navigator.mediaDevices.getUserMedia({ audio: true })
      .then(function (stream) {
        if (currentState !== "listening" && !isRecognizing) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          return { denied: false };
        }
        micStream = stream;
        var AC = window.AudioContext || window.webkitAudioContext;
        if (AC) {
          audioCtx = new AC();
          analyserNode = audioCtx.createAnalyser();
          analyserNode.fftSize = 256;
          analyserNode.smoothingTimeConstant = 0.72;
          var src = audioCtx.createMediaStreamSource(stream);
          src.connect(analyserNode);
          freqData = new Uint8Array(analyserNode.frequencyBinCount);
        }
        return { denied: false };
      })
      .catch(function (err) {
        var name = (err && err.name) || "";
        var isDenied = (name === "NotAllowedError" || name === "PermissionDeniedError");
        return { denied: isDenied, errorName: name };
      });
  }

  // =========================================================================
  // 3. Error & Transcript Helpers
  // =========================================================================

  function hideError() {
    if (errorBanner) errorBanner.setAttribute("hidden", "");
    if (errorTextEl) errorTextEl.textContent = "";
  }

  function showError(msg) {
    stopMicStream();
    isRecognizing = false;
    setOrbState("idle", "ERROR");
    if (errorTextEl) errorTextEl.textContent = msg;
    if (errorBanner) errorBanner.removeAttribute("hidden");
    if (hintEl) hintEl.textContent = "Check error message above or type a command below.";
  }

  function setTranscriptDisplay(finalText, interimText) {
    if (finalSpan) finalSpan.textContent = finalText || "";
    if (interimSpan) interimSpan.textContent = interimText || "";
  }

  function setResultVisual(outcomeKind, badgeText, sentenceText, metaText) {
    if (resultCard) {
      resultCard.classList.remove("is-allow", "is-stop", "is-wait");
      if (outcomeKind === "allow") resultCard.classList.add("is-allow");
      else if (outcomeKind === "stop" || outcomeKind === "not_done") resultCard.classList.add("is-stop");
      else if (outcomeKind === "wait") resultCard.classList.add("is-wait");
      resultCard.setAttribute("data-outcome", outcomeKind || "idle");
    }
    if (outcomeBadge) outcomeBadge.textContent = badgeText || "Ready";
    if (agentTextEl) agentTextEl.textContent = sentenceText || "";
    if (turnMetaEl) turnMetaEl.textContent = metaText || "";
  }

  function addHistoryEntry(cmd, outcomeKind, outcomeLabel) {
    var nowStr = new Date().toTimeString().slice(0, 8);
    commandHistory.unshift({
      time: nowStr,
      command: cmd,
      kind: outcomeKind,
      label: outcomeLabel
    });
    if (!historyList) return;
    clear(historyList);
    commandHistory.slice(0, 5).forEach(function (item) {
      var cls = item.kind === "allow" ? "ok" : (item.kind === "wait" ? "wait" : "stop");
      historyList.append(
        h("li", { class: "voice-history-item" },
          h("span", { class: "mono text-muted", text: item.time }),
          h("span", { class: "voice-history-cmd", text: item.command }),
          h("span", { class: "badge " + cls, text: item.label })
        )
      );
    });
  }

  // =========================================================================
  // 4. Optional Spoken Replies (speechSynthesis, default OFF, plain only)
  // =========================================================================

  function sanitizePlainSpeech(text) {
    if (!text) return "";
    return String(text)
      .replace(/\{[\s\S]*\}/g, "")
      .replace(/\b[a-f0-9]{12,64}\b/gi, "")
      .replace(/\(?Error ID:\s*[a-zA-Z0-9_-]+\)?/gi, "")
      .replace(/\breq_[a-zA-Z0-9_-]+\b/gi, "")
      .replace(/\bINJ-\d+\b/gi, "")
      .replace(/\[Rules?:[^\]]*\]/gi, "")
      .replace(/\(via\s+[^)]+\)/gi, "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function pickVoice(lang) {
    if (!window.speechSynthesis) return null;
    var voices = window.speechSynthesis.getVoices() || [];
    var prefix = lang === "hi" ? "hi" : "en";
    for (var i = 0; i < voices.length; i++) {
      if (voices[i].lang && voices[i].lang.toLowerCase().indexOf(prefix) === 0) {
        return voices[i];
      }
    }
    return null;
  }

  function speakPlain(sentence, forceSpeak) {
    var clean = sanitizePlainSpeech(sentence);
    if (!clean) return;
    if ((!speakerEnabled && !forceSpeak) || !window.speechSynthesis) return;

    try {
      window.speechSynthesis.cancel();
    } catch (e) {}

    var utt = new SpeechSynthesisUtterance(clean);
    utt.lang = currentLang === "hi" ? "hi-IN" : "en-IN";
    var v = pickVoice(currentLang);
    if (v) utt.voice = v;

    utt.onstart = function () { setOrbState("speaking", "SPEAKING"); };
    utt.onend = function () { if (currentState === "speaking") setOrbState("idle", "STANDBY"); };
    utt.onerror = function () { if (currentState === "speaking") setOrbState("idle", "STANDBY"); };

    window.speechSynthesis.speak(utt);
  }

  // =========================================================================
  // 5. SpeechRecognition Push-to-Talk & Error Handling
  // =========================================================================

  function startListening() {
    var SR = getSpeechRecognitionCtor();
    if (!SR || isTurnRunning) {
      if (!SR) {
        if (srBanner) srBanner.removeAttribute("hidden");
        showError("Speech recognition is not supported in this browser. Type your command below.");
      }
      return;
    }

    hideError();
    latestInterimTranscript = "";
    setTranscriptDisplay("", "");

    if (activeRecognition) {
      try { activeRecognition.abort(); } catch (e) {}
      activeRecognition = null;
    }

    var rec = new SR();
    rec.continuous = false;
    rec.interimResults = true;
    rec.maxAlternatives = 1;
    rec.lang = currentLang === "hi" ? "hi-IN" : "en-IN";

    var hadFinal = false;

    rec.onstart = function () {
      isRecognizing = true;
      setOrbState("listening", "LISTENING...");
      if (hintEl) {
        hintEl.textContent = currentLang === "hi"
          ? "सुन रहा हूँ... बोलें और रुकने के लिए क्लिक करें"
          : "Listening… speak clearly, click or release when done.";
      }
    };

    rec.onresult = function (event) {
      var finals = [];
      var interims = [];
      for (var i = 0; i < event.results.length; i++) {
        var r = event.results[i];
        var txt = (r[0] && r[0].transcript) ? r[0].transcript : "";
        if (r.isFinal) finals.push(txt);
        else interims.push(txt);
      }
      var finalStr = finals.join(" ").trim();
      var interimStr = interims.join(" ").trim();
      latestInterimTranscript = (finalStr || interimStr).trim();
      setTranscriptDisplay(finalStr ? (finalStr + (interimStr ? " " : "")) : "", interimStr);

      if (finalStr) {
        hadFinal = true;
        isRecognizing = false;
        activeRecognition = null;
        stopMicStream();
        try { rec.stop(); } catch (e) {}
        setTranscriptDisplay(finalStr, "");
        submitVoiceCommand(finalStr);
      }
    };

    rec.onerror = function (ev) {
      var errCode = (ev && ev.error) || "unknown";
      activeRecognition = null;
      isRecognizing = false;
      holdCommitPending = false;
      if (errCode === "not-allowed" || errCode === "service-not-allowed") {
        showError("Microphone permission denied. Allow microphone access or type your command below.");
      } else if (errCode === "no-speech") {
        showError("No speech detected. Speak clearly and try again.");
      } else if (errCode === "aborted") {
        stopMicStream();
        setOrbState("idle", "STANDBY");
      } else {
        showError("Speech recognition service error (" + errCode + "). Try again or type below.");
      }
    };

    rec.onend = function () {
      activeRecognition = null;
      isRecognizing = false;
      stopMicStream();
      if (holdCommitPending && !hadFinal && latestInterimTranscript) {
        holdCommitPending = false;
        setTranscriptDisplay(latestInterimTranscript, "");
        submitVoiceCommand(latestInterimTranscript);
        return;
      }
      holdCommitPending = false;
      if (currentState === "listening" && !hadFinal && !isTurnRunning) {
        setOrbState("idle", "STANDBY");
        if (hintEl) hintEl.textContent = "Click or hold microphone (or press Space) to speak.";
      }
    };

    try {
      activeRecognition = rec;
      isRecognizing = true;
      setOrbState("listening", "LISTENING...");
      rec.start();

      startMicAnalyser().then(function (micRes) {
        if (micRes && micRes.denied && isRecognizing && !hadFinal) {
          // Real mic denied before recognition succeeded (real browser or denied permission test)
          try { rec.abort(); } catch (e) {}
          activeRecognition = null;
          showError("Microphone permission denied. Allow microphone access or type your command below.");
        }
      });
    } catch (err) {
      activeRecognition = null;
      isRecognizing = false;
      showError("Could not start microphone listening. Try again or type your command below.");
    }
  }

  function stopListening(commitInterim) {
    if (!isRecognizing && !activeRecognition) return;
    holdCommitPending = Boolean(commitInterim);
    isRecognizing = false;
    if (activeRecognition) {
      try { activeRecognition.stop(); } catch (e) {}
    }
    stopMicStream();
    if (!commitInterim && currentState === "listening") {
      setOrbState("idle", "STANDBY");
    }
  }

  function toggleListening() {
    if (isTurnRunning) return;
    if (isRecognizing) {
      stopListening(Boolean(latestInterimTranscript));
    } else {
      startListening();
    }
  }

  // =========================================================================
  // 6. Security Pipeline Submission (Matches Console API + Real Gate Rail)
  // =========================================================================

  function setBusy(busy) {
    isTurnRunning = busy;
    var hasSR = Boolean(getSpeechRecognitionCtor());
    if (micTrigger) micTrigger.disabled = busy || !hasSR;
    if (typedInput) typedInput.disabled = busy;
    if (typedSubmit) typedSubmit.disabled = busy;
  }

  function stopThinkingTicker() {
    if (thinkingTicker) {
      clearInterval(thinkingTicker);
      thinkingTicker = null;
    }
  }

  function stopApprovalTimer() {
    if (approvalCountdownTimer) {
      clearInterval(approvalCountdownTimer);
      approvalCountdownTimer = null;
    }
  }

  function plainOutcomeForSpeech(dec, gateName, reply) {
    if (dec === "ALLOW" || dec === "DIRECT_ALLOW") {
      return sanitizePlainSpeech(reply || (currentLang === "hi" ? "अनुरोध पूरा हो गया।" : "Request allowed and completed."));
    }
    if (dec === "DENY") {
      return currentLang === "hi"
        ? "सुपरवाइज़र ने इस कार्रवाई को अस्वीकार कर दिया।"
        : "Action denied by supervisor. Nothing was executed.";
    }
    if (dec === "REVIEW" || dec === "WAITING") {
      return currentLang === "hi"
        ? "यह कार्रवाई मानवीय अनुमति के लिए प्रतीक्षा में है।"
        : "Action held for human supervisor approval.";
    }
    if (currentLang === "hi") {
      return "सुरक्षा नियम द्वारा अनुरोध " + gateName + " पर रोक दिया गया।";
    }
    var sanitized = sanitizePlainSpeech(reply || "");
    return sanitized || ("Stopped at " + gateName + ". Request blocked by security policy.");
  }

  function handleApprovalPrompt(detail, reqIdFallback) {
    var toolName = (detail && detail.tool) || "action";
    var reqId = (detail && detail.request_id) || reqIdFallback;
    var reqHash = (detail && detail.request_hash) || "";

    if (approvalToolEl) approvalToolEl.textContent = toolName;
    var hashEl = document.getElementById("voice-approval-hash-display");
    if (hashEl) hashEl.textContent = "Hash: " + (reqHash ? reqHash.slice(0, 14) + "..." : "pending");
    var argsEl = document.getElementById("voice-approval-args");
    if (argsEl) {
      var argsObj = (detail && detail.args) || {};
      argsEl.textContent = Object.keys(argsObj).length ? JSON.stringify(argsObj, null, 2) : "Privileged action requires administrator decision.";
    }
    if (approvalAlert) approvalAlert.classList.remove("is-hidden");

    var secs = 60;
    var fill = document.getElementById("voice-approval-progress");
    if (approvalCountdownEl) approvalCountdownEl.textContent = String(secs);
    if (fill) fill.style.width = "100%";

    stopApprovalTimer();
    approvalCountdownTimer = setInterval(function () {
      secs -= 1;
      if (approvalCountdownEl) approvalCountdownEl.textContent = String(Math.max(0, secs));
      if (fill) fill.style.width = Math.max(0, (secs / 60) * 100) + "%";
      if (secs <= 0) stopApprovalTimer();
    }, 1000);

    var approveBtn = document.getElementById("voice-inline-approve-btn");
    var denyBtn = document.getElementById("voice-inline-deny-btn");
    if (approveBtn) {
      approveBtn.onclick = function () {
        if (!reqId) return;
        approveBtn.disabled = true;
        api.post("/api/approvals/decide", { request_id: reqId, request_hash: reqHash, approved: true })
          .then(function () {
            stopApprovalTimer();
            if (approvalAlert) approvalAlert.classList.add("is-hidden");
            approveBtn.disabled = false;
          })
          .catch(function () { approveBtn.disabled = false; });
      };
    }
    if (denyBtn) {
      denyBtn.onclick = function () {
        if (!reqId) return;
        denyBtn.disabled = true;
        api.post("/api/approvals/decide", { request_id: reqId, request_hash: reqHash, approved: false })
          .then(function () {
            stopApprovalTimer();
            if (approvalAlert) approvalAlert.classList.add("is-hidden");
            denyBtn.disabled = false;
          })
          .catch(function () { denyBtn.disabled = false; });
      };
    }
  }

  function submitVoiceCommand(rawText) {
    var text = (rawText || "").trim();
    if (!text || isTurnRunning) return;

    hideError();
    lastCommandText = text;
    stageLabels = resolveStageLabels();
    if (rail && rail.setLabels) rail.setLabels(stageLabels);

    setTranscriptDisplay(text, "");
    if (userLangLabel) userLangLabel.textContent = currentLang === "hi" ? "हिंदी" : "English";

    setBusy(true);
    setOrbState("thinking", "CHECKING GATES...");
    if (approvalAlert) approvalAlert.classList.add("is-hidden");
    setResultVisual("idle", "Checking", "Sending command through Aegis security pipeline...", "");
    if (rail) rail.syncLive({ completedGates: [], activeGate: 0, captionParts: [{ text: "Checking " + stageLabels[0] + "…" }] });

    var startTime = Date.now();
    var lastTickMs = startTime;
    var waitBudgetMs = 0;
    var waitingForApproval = false;
    var approvalShown = false;
    var settled = false;
    activeStage = null;
    thinkingStartMs = null;

    function settleTurn(kind, stopIdx, badge, plainSentence, rawSayForRail, histLabel) {
      if (settled) return;
      settled = true;
      hasSettledResult = true;
      stopThinkingTicker();
      stopApprovalTimer();
      setBusy(false);

      if (approvalAlert && !waitingForApproval) approvalAlert.classList.add("is-hidden");

      if (rail) {
        rail.settle({
          kind: kind,
          stop: stopIdx,
          say: rawSayForRail,
          why: rawSayForRail
        });
      }

      var metaText = (kind === "allow") ? "All 9 gates passed" : badge;
      setResultVisual(kind, badge, plainSentence, metaText);
      addHistoryEntry(text, kind, histLabel || badge);
      lastPlainReply = plainSentence;
      if (replayBtn) replayBtn.disabled = !plainSentence;

      if (resultCard && resultCard.scrollIntoView) {
        resultCard.scrollIntoView({ behavior: isReducedMotion() ? "auto" : "smooth", block: "nearest" });
      }
      if (hintEl) hintEl.textContent = "Click or hold microphone (or press Space) to speak.";
      setOrbState("idle", kind === "allow" ? "ALLOWED" : (kind === "wait" ? "WAITING" : "BLOCKED"));
      speakPlain(plainSentence, false);
    }

    api.post("/api/console/send", { text: text })
      .then(function (sendRes) {
        var reqId = sendRes && (sendRes.request_id || sendRes.id || sendRes.req_id);
        if (!reqId) {
          var errMsg = (sendRes && sendRes.error) || "Gateway rejected request.";
          settleTurn("stop", 0, "Stopped", errMsg, errMsg, "Error");
          return;
        }

        function poll() {
          if (settled) return;
          var now = Date.now();
          if (!waitingForApproval) {
            waitBudgetMs += (now - lastTickMs);
          }
          lastTickMs = now;

          // Keep Date.now() - startTime > 90000 for policy timeout test invariant
          if (!waitingForApproval && (Date.now() - startTime > 90000 || waitBudgetMs > 90000)) {
            settleTurn("stop", 2, "Timed out", "No answer from the model. Please try again.", "Timed out waiting for response.", "Timeout");
            return;
          }

          api.get("/api/console/poll/" + encodeURIComponent(reqId))
            .then(function (pollRes) {
              if (settled || !pollRes) return;

              var steps = pollRes.steps || [];
              var completedGates = Array.isArray(pollRes.completed_gates) ? pollRes.completed_gates : [];
              var pollActiveStage = pollRes.active_stage || null;
              var pollActiveGate = (typeof pollRes.active_gate === "number") ? pollRes.active_gate : -1;

              var appStep = steps.find(function (s) {
                return s.stage === "approval" && (s.status === "running" || s.status === "review" || s.status === "hold");
              });

              if (!pollRes.final && (appStep || pollActiveStage === "approval") && !approvalShown) {
                approvalShown = true;
                waitingForApproval = true;
                stopThinkingTicker();
                setOrbState("idle", "APPROVAL NEEDED");
                setResultVisual("wait", "Waiting for approval", "Privileged action requires supervisor approval below.", "Gate 7: Approval");
                if (rail) {
                  rail.syncLive({
                    completedGates: completedGates,
                    activeGate: 6,
                    waiting: true,
                    captionParts: [
                      { text: "Waiting at " + (stageLabels[6] || "Approval") + ". ", tone: "wait" },
                      { text: "Waiting for human supervisor approval." }
                    ]
                  });
                }
                handleApprovalPrompt(appStep && appStep.detail, reqId);
              }

              if (!pollRes.final && !waitingForApproval && rail) {
                if (pollActiveStage === "llm" || pollActiveGate === 2) {
                  if (activeStage !== "llm") {
                    activeStage = "llm";
                    thinkingStartMs = Date.now();
                    if (!thinkingTicker) {
                      thinkingTicker = setInterval(function () {
                        if (settled || activeStage !== "llm" || !thinkingStartMs) {
                          stopThinkingTicker();
                          return;
                        }
                        var s = Math.max(0, Math.floor((Date.now() - thinkingStartMs) / 1000));
                        rail.setCaption([{ text: "Model is thinking... (" + s + "s)" }]);
                      }, 500);
                    }
                  }
                  var secs = thinkingStartMs ? Math.max(0, Math.floor((Date.now() - thinkingStartMs) / 1000)) : 0;
                  rail.syncLive({
                    completedGates: completedGates,
                    activeGate: 2,
                    waiting: false,
                    captionParts: [{ text: "Model is thinking... (" + secs + "s)" }]
                  });
                } else if (pollActiveGate >= 0) {
                  activeStage = pollActiveStage;
                  stopThinkingTicker();
                  rail.syncLive({
                    completedGates: completedGates,
                    activeGate: pollActiveGate,
                    waiting: false,
                    captionParts: [{ text: "Checking " + (stageLabels[pollActiveGate] || "Gate") + "…" }]
                  });
                }
              }

              if (pollRes.final) {
                waitingForApproval = false;
                if (approvalAlert) approvalAlert.classList.add("is-hidden");
                var final = pollRes.final;
                var dec = String(final.decision || "BLOCK").toUpperCase();
                var isAllow = (dec === "ALLOW" || dec === "DIRECT_ALLOW");
                var isWait = (dec === "REVIEW" || dec === "WAITING");
                var trStatus = (final.tool_result && typeof final.tool_result === "object")
                  ? String(final.tool_result.status || "").toLowerCase()
                  : "";
                var isNotDone = isAllow && (trStatus === "error" || trStatus === "refused" || trStatus === "failed");

                var stopStage = pollRes.stopped_stage || final.stopped_at || final.stage;
                if (!stopStage && steps.length) {
                  for (var idx = 0; idx < steps.length; idx++) {
                    if (steps[idx].status === "block" || steps[idx].status === "deny" || steps[idx].status === "error") {
                      stopStage = steps[idx].stage;
                      break;
                    }
                  }
                }
                var stopIdx = (isAllow && !isNotDone)
                  ? -1
                  : (typeof pollRes.stopped_gate === "number" && pollRes.stopped_gate >= 0
                    ? pollRes.stopped_gate
                    : (DM.layerToGateIndex ? DM.layerToGateIndex(stopStage) : 0));
                if (!isAllow && stopIdx < 0) stopIdx = 0;
                if (isNotDone && stopIdx < 0) stopIdx = 7;

                var gateName = (stopIdx >= 0 && stageLabels[stopIdx]) ? stageLabels[stopIdx] : "Detection";
                var trText = (final.tool_result && typeof final.tool_result === "object" && final.tool_result.text)
                  ? final.tool_result.text
                  : "";
                var rawReply = final.reply || trText || final.error || "";
                var plainSentence = plainOutcomeForSpeech(dec, gateName, rawReply);

                var kind = isNotDone ? "not_done" : (isAllow ? "allow" : (isWait ? "wait" : "stop"));
                var badge = isAllow && !isNotDone
                  ? "Allowed"
                  : (isNotDone ? ("Not completed at " + gateName) : ("Stopped at " + gateName));

                settleTurn(kind, stopIdx, badge, plainSentence, rawReply || plainSentence, badge);

                if (final.error && final.error.indexOf("SESSION QUARANTINED") !== -1 && window.AegisApp && window.AegisApp.openQuarantineModal) {
                  window.AegisApp.openQuarantineModal();
                }
                return;
              }

              setTimeout(poll, 400);
            })
            .catch(function (err) {
              settleTurn("stop", 0, "Error", (err && err.message) || "Failed to poll gateway.", "Polling error", "Error");
            });
        }

        poll();
      })
      .catch(function (err) {
        var msg = (err && err.message) || "Request failed.";
        settleTurn("stop", 0, "Blocked", sanitizePlainSpeech(msg) || msg, msg, "Blocked");
      });
  }

  // =========================================================================
  // 7. Wire Push-to-Talk, Typed Fallback, Controls & Suggestion Chips
  // =========================================================================

  if (micTrigger) {
    micTrigger.addEventListener("pointerdown", function (e) {
      if (e.button !== undefined && e.button !== 0) return;
      if (!isRecognizing && !isTurnRunning) {
        pointerDownAt = Date.now();
        justStartedOnPointerDown = true;
        startListening();
      } else {
        pointerDownAt = 0;
        justStartedOnPointerDown = false;
      }
    });

    micTrigger.addEventListener("pointerup", function () {
      var heldMs = pointerDownAt ? (Date.now() - pointerDownAt) : 0;
      pointerDownAt = 0;
      if (heldMs >= 320 && isRecognizing) {
        justStartedOnPointerDown = false;
        stopListening(true);
      }
    });

    micTrigger.addEventListener("pointercancel", function () {
      pointerDownAt = 0;
      justStartedOnPointerDown = false;
    });

    micTrigger.addEventListener("click", function () {
      if (justStartedOnPointerDown) {
        justStartedOnPointerDown = false;
        return;
      }
      toggleListening();
    });
  }

  if (retryBtn) {
    retryBtn.addEventListener("click", function () {
      hideError();
      if (getSpeechRecognitionCtor()) {
        startListening();
      } else if (typedInput) {
        typedInput.focus();
      }
    });
  }

  if (typedForm && typedInput) {
    typedForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var txt = typedInput.value.trim();
      if (!txt || isTurnRunning) return;
      typedInput.value = "";
      submitVoiceCommand(txt);
    });
  }

  if (speakerToggle) {
    speakerToggle.addEventListener("click", function () {
      speakerEnabled = !speakerEnabled;
      speakerToggle.setAttribute("aria-pressed", String(speakerEnabled));
      if (speakerLabel) speakerLabel.textContent = speakerEnabled ? "Speak replies: ON" : "Speak replies: OFF";
      if (!speakerEnabled && window.speechSynthesis) {
        try { window.speechSynthesis.cancel(); } catch (e) {}
      }
    });
  }

  if (replayBtn) {
    replayBtn.addEventListener("click", function () {
      if (lastPlainReply) speakPlain(lastPlainReply, true);
    });
  }

  function setLanguage(lang) {
    currentLang = lang;
    if (langBtnEn) {
      langBtnEn.classList.toggle("active", lang === "en");
      langBtnEn.setAttribute("aria-pressed", String(lang === "en"));
    }
    if (langBtnHi) {
      langBtnHi.classList.toggle("active", lang === "hi");
      langBtnHi.setAttribute("aria-pressed", String(lang === "hi"));
    }
    if (userLangLabel) userLangLabel.textContent = lang === "hi" ? "हिंदी" : "English";
  }

  if (langBtnEn) langBtnEn.addEventListener("click", function () { setLanguage("en"); });
  if (langBtnHi) langBtnHi.addEventListener("click", function () { setLanguage("hi"); });

  if (stayBtn && approvalAlert) {
    stayBtn.addEventListener("click", function () {
      stopApprovalTimer();
      approvalAlert.classList.add("is-hidden");
    });
  }

  document.querySelectorAll(".voice-cmd-chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      var phrase = chip.getAttribute("data-speak");
      if (!phrase || isTurnRunning) return;
      setLanguage(/[\u0900-\u097F]/.test(phrase) ? "hi" : "en");
      submitVoiceCommand(phrase);
    });
  });

  window.addEventListener("keydown", function (e) {
    var tag = e.target && e.target.tagName;
    if (e.code === "Space" && tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "BUTTON" && tag !== "A") {
      e.preventDefault();
      toggleListening();
    }
  });

  window.addEventListener("aegis:health", function (ev) {
    var d = ev && ev.detail;
    if (d) {
      var nextLabels = resolveStageLabels(d.environment, d.hardware_status);
      var changed = nextLabels.join("|") !== stageLabels.join("|");
      stageLabels = nextLabels;
      if (rail && rail.setLabels && changed && currentState === "idle" && !isTurnRunning && !hasSettledResult) {
        rail.setLabels(stageLabels);
      }
    }
  });

  // Initialize browser speech recognition availability banner
  if (!getSpeechRecognitionCtor()) {
    if (srBanner) srBanner.removeAttribute("hidden");
    if (micTrigger) {
      micTrigger.disabled = true;
      micTrigger.title = "Speech recognition unavailable in this browser; use typed input below.";
    }
    if (hintEl) hintEl.textContent = "Speech recognition unavailable here — use the typed command input below.";
  }

  setOrbState("idle", "STANDBY");
  ensureRenderLoop();
})();
