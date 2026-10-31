/**
 * AURA Neural Voice Assistant - AegisAgent
 * Interactive 3D Kinetic Particle Sphere with Web Speech API integration.
 * Dual-language (English + Hindi) speech-to-text & text-to-speech with Zero-Trust Security Gating.
 */
(function () {
  var canvas = document.getElementById("voice-sphere-canvas");
  if (!canvas) return;

  var ctx = canvas.getContext("2d");
  var micTrigger = document.getElementById("voice-mic-trigger");
  var statusBadge = document.getElementById("orb-status-text");
  var statusDot = document.getElementById("orb-pulse-dot");
  var langBtnEn = document.getElementById("lang-btn-en");
  var langBtnHi = document.getElementById("lang-btn-hi");
  var speakerToggle = document.getElementById("voice-speaker-toggle");
  var speakerLabel = document.getElementById("speaker-label");
  var replayBtn = document.getElementById("voice-replay-audio-btn");
  var userLine = document.getElementById("voice-user-line");
  var userTextEl = document.getElementById("voice-user-text");
  var agentTextEl = document.getElementById("voice-agent-text");
  var userLangLabel = document.getElementById("user-lang-label");
  var hintEl = document.getElementById("voice-instruction-hint");
  var stepperContainer = document.getElementById("voice-stepper-container");
  var approvalAlert = document.getElementById("voice-approval-alert");
  var approvalToolEl = document.getElementById("voice-approval-tool");
  var approvalCountdownEl = document.getElementById("voice-approval-countdown");
  var stayBtn = document.getElementById("voice-stay-btn");

  // State Management
  var currentState = "idle"; // 'idle' | 'listening' | 'thinking' | 'speaking'
  var currentLang = "en";    // 'en' | 'hi'
  var speakerEnabled = true;
  var isRecognizing = false;
  var activeRecognition = null;
  var lastSpokenText = "Hello! I'm Aura, your security and smart home assistant. How can I help you today?";
  var audioPrimed = false;
  var approvalCountdownTimer = null;
  var wittyTimer = null;

  // Selected Witty / Informative loading lines spoken aloud during processing
  var SPOKEN_LOADING_LINES_EN = [
    "Consulting the security council, hold tight...",
    "Checking security clearances for your request...",
    "Navigating gateway traffic, verifying policies...",
    "Inspecting byte packets for injection patterns..."
  ];

  var SPOKEN_LOADING_LINES_HI = [
    "सुरक्षा परिषद से अनुमति ली जा रही है, थोड़ा इंतज़ार करें...",
    "सुरक्षा नीति और अनुमतियों की जांच हो रही है...",
    "हार्डवेयर और नेटवर्क की स्थिति जांची जा रही है..."
  ];

  // =========================================================================
  // 1. 3D Kinetic Particle Sphere Engine (Vibrant Multi-Spectral Glow)
  // =========================================================================

  var numParticles = 640;
  var particles = [];
  var baseRadius = 140;
  var rotX = 0.25;
  var rotY = 0;
  var fov = 380;
  var time = 0;

  // Golden spiral distribution across sphere surface
  var phiRatio = (1 + Math.sqrt(5)) / 2;
  for (var i = 0; i < numParticles; i++) {
    var theta = 2 * Math.PI * i / phiRatio;
    var phi = Math.acos(1 - 2 * (i + 0.5) / numParticles);
    particles.push({
      theta: theta,
      phi: phi,
      baseX: Math.sin(phi) * Math.cos(theta),
      baseY: Math.cos(phi),
      baseZ: Math.sin(phi) * Math.sin(theta),
      phase: Math.random() * Math.PI * 2,
      variant: i % 4, // 0: Luminous Cyan, 1: Electric Blue, 2: Violet, 3: Neon Magenta
    });
  }

  function renderSphere() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    var cx = canvas.width / 2;
    var cy = canvas.height / 2;

    // Soft atmospheric radial bloom background inside canvas
    var bloom = ctx.createRadialGradient(cx, cy, 20, cx, cy, 210);
    bloom.addColorStop(0, "rgba(52, 224, 210, 0.09)");
    bloom.addColorStop(0.45, "rgba(168, 85, 247, 0.05)");
    bloom.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = bloom;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Dynamics adjusted by assistant state
    var rotSpeed = 0.009;
    var waveAmp = 14;
    var waveFreq = 3.2;

    if (currentState === "listening") {
      rotSpeed = 0.016;
      waveAmp = 20;
      waveFreq = 4.8;
    } else if (currentState === "thinking") {
      rotSpeed = 0.038;
      waveAmp = 25;
      waveFreq = 7.0;
    } else if (currentState === "speaking") {
      rotSpeed = 0.018;
      waveAmp = 28;
      waveFreq = 4.5;
    }

    rotY += rotSpeed;
    rotX += rotSpeed * 0.35;
    time += 0.04;

    var projected = [];

    for (var i = 0; i < numParticles; i++) {
      var p = particles[i];

      // Undulating surface displacement waves
      var displacement = Math.sin(p.theta * waveFreq + time + p.phase) *
                         Math.cos(p.phi * waveFreq - time * 0.8) * waveAmp;

      if (currentState === "speaking") {
        displacement += Math.sin(time * 4 + p.phi * 8) * 12;
      }

      var r = baseRadius + displacement;
      var x = p.baseX * r;
      var y = p.baseY * r;
      var z = p.baseZ * r;

      // 3D Matrix Rotation (Y axis then X axis)
      var x1 = x * Math.cos(rotY) + z * Math.sin(rotY);
      var z1 = -x * Math.sin(rotY) + z * Math.cos(rotY);

      var y1 = y * Math.cos(rotX) - z1 * Math.sin(rotX);
      var z2 = y * Math.sin(rotX) + z1 * Math.cos(rotX);

      // Perspective Projection
      var scale = fov / (fov + z2 + 240);
      var px = cx + x1 * scale;
      var py = cy + y1 * scale;
      var depthNorm = (z2 + baseRadius) / (2 * baseRadius);
      depthNorm = Math.max(0.15, Math.min(1.0, depthNorm));

      projected.push({
        x: px,
        y: py,
        z: z2,
        scale: Math.max(0.2, scale),
        depth: depthNorm,
        variant: p.variant,
      });
    }

    // Depth sorting (back-to-front rendering)
    projected.sort(function (a, b) {
      return a.z - b.z;
    });

    // Connecting kinetic mesh web between nearby particles
    ctx.lineWidth = 0.7;
    for (var i = 0; i < projected.length; i += 3) {
      var p1 = projected[i];
      for (var j = i + 1; j < Math.min(i + 12, projected.length); j++) {
        var p2 = projected[j];
        var dx = p1.x - p2.x;
        var dy = p1.y - p2.y;
        var dist = dx * dx + dy * dy;
        if (dist < 900) {
          var meshAlpha = (1 - dist / 900) * 0.28 * p1.depth;
          ctx.strokeStyle = "rgba(52, 224, 210, " + meshAlpha + ")";
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }
    }

    // Luminous kinetic particle dots with glowing multi-color spectrum
    for (var i = 0; i < projected.length; i++) {
      var pt = projected[i];
      var size = Math.max(1.4, 3.8 * pt.scale * pt.depth);

      var rCol, gCol, bCol;
      if (currentState === "thinking") {
        // High-energy amber & electric violet during policy scan
        rCol = Math.floor(180 + 70 * pt.depth);
        gCol = Math.floor(90 + 40 * pt.depth);
        bCol = 245;
      } else if (currentState === "speaking") {
        // Radiant voice resonance: cyan and neon magenta
        if (pt.variant % 2 === 0) {
          rCol = 52;  gCol = 224; bCol = 210; // Cyan
        } else {
          rCol = 236; gCol = 72;  bCol = 153; // Magenta
        }
      } else {
        // Standby & Listening: Cyan, Blue, Emerald, Violet
        if (pt.variant === 0) {
          rCol = 52;  gCol = 224; bCol = 210; // Cyan
        } else if (pt.variant === 1) {
          rCol = 59;  gCol = 130; bCol = 246; // Electric Blue
        } else if (pt.variant === 2) {
          rCol = 14;  gCol = 124; bCol = 114; // Aegis Emerald
        } else {
          rCol = 168; gCol = 85;  bCol = 247; // Violet
        }
      }

      var dotAlpha = Math.min(1.0, 0.4 + 0.6 * pt.depth);
      ctx.fillStyle = "rgba(" + rCol + ", " + gCol + ", " + bCol + ", " + dotAlpha + ")";
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, Math.max(1.0, size), 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(renderSphere);
  }

  requestAnimationFrame(renderSphere);

  // =========================================================================
  // 2. State & UI Helpers
  // =========================================================================

  function setOrbState(state, text) {
    currentState = state;
    if (statusBadge) statusBadge.textContent = text || state.toUpperCase();

    if (statusDot) {
      statusDot.className = "pulse-dot " + (
        state === "speaking" ? "live" :
        state === "listening" ? "live" :
        state === "thinking" ? "warn" : "live"
      );
    }

    var micRings = document.querySelectorAll(".mic-wave-ring");
    if (micTrigger) {
      if (state === "listening") {
        micTrigger.classList.add("listening");
        micRings.forEach(function (ring) { ring.classList.add("active"); });
      } else {
        micTrigger.classList.remove("listening");
        micRings.forEach(function (ring) { ring.classList.remove("active"); });
      }
    }
  }

  // =========================================================================
  // 3. Audio & Web Speech API (Voices, Autoplay Priming, Speaking)
  // =========================================================================

  var availableVoices = [];

  function loadVoices() {
    if (!window.speechSynthesis) return;
    availableVoices = window.speechSynthesis.getVoices() || [];
  }

  if (window.speechSynthesis) {
    loadVoices();
    if (window.speechSynthesis.onvoiceschanged !== undefined) {
      window.speechSynthesis.onvoiceschanged = loadVoices;
    }
  }

  function getBestVoice(lang) {
    if (!availableVoices.length) loadVoices();
    var targetPrefix = lang === "hi" ? "hi" : "en";

    // 1. Look for preferred natural voices
    for (var i = 0; i < availableVoices.length; i++) {
      var v = availableVoices[i];
      if (v.lang && v.lang.toLowerCase().indexOf(targetPrefix) === 0) {
        if (v.name.indexOf("Natural") !== -1 || v.name.indexOf("Google") !== -1 || v.name.indexOf("Heera") !== -1 || v.name.indexOf("Kalpana") !== -1) {
          return v;
        }
      }
    }

    // 2. Any voice matching language code
    for (var j = 0; j < availableVoices.length; j++) {
      if (availableVoices[j].lang && availableVoices[j].lang.toLowerCase().indexOf(targetPrefix) === 0) {
        return availableVoices[j];
      }
    }

    return null;
  }

  function primeAudio() {
    if (audioPrimed || !window.speechSynthesis) return;
    audioPrimed = true;
    try {
      var silent = new SpeechSynthesisUtterance(" ");
      silent.volume = 0.01;
      window.speechSynthesis.speak(silent);
    } catch (e) {}
  }

  // Prime audio on very first user interaction anywhere
  window.addEventListener("click", function onFirstClick() {
    primeAudio();
    window.removeEventListener("click", onFirstClick);
  }, { once: true });

  function sanitizeForSpeech(text) {
    if (!text) return "";
    var clean = text
      .replace(/\b[a-f0-9]{16,64}\b/gi, "")
      .replace(/\(?Error ID:\s*[a-zA-Z0-9_-]+\)?/gi, "")
      .replace(/\breq_[a-zA-Z0-9_-]+\b/gi, "")
      .replace(/\bINJ-\d+\b/gi, "")
      .replace(/\s+/g, " ")
      .trim();
    return clean || text;
  }

  function speakText(rawText, onEndCallback) {
    var text = sanitizeForSpeech(rawText);
    if (!speakerEnabled || !window.speechSynthesis || !text) {
      if (onEndCallback) onEndCallback();
      return;
    }

    primeAudio();
    try {
      window.speechSynthesis.cancel();
      if (window.speechSynthesis.paused) {
        window.speechSynthesis.resume();
      }
    } catch (e) {}

    var utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = currentLang === "hi" ? "hi-IN" : "en-IN";
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    utterance.volume = 1.0;

    var bestVoice = getBestVoice(currentLang);
    if (bestVoice) {
      utterance.voice = bestVoice;
    }

    utterance.onstart = function () {
      setOrbState("speaking", "AURA SPEAKING...");
    };

    utterance.onend = function () {
      setOrbState("idle", "STANDBY");
      if (hintEl) hintEl.textContent = "Click microphone or press Spacebar to talk to Aura";
      if (onEndCallback) onEndCallback();
    };

    utterance.onerror = function () {
      setOrbState("idle", "STANDBY");
      if (hintEl) hintEl.textContent = "Click microphone or press Spacebar to talk to Aura";
      if (onEndCallback) onEndCallback();
    };

    window.speechSynthesis.speak(utterance);
  }

  // Direct entrance greeting
  function triggerAuraGreeting() {
    var greeting = currentLang === "hi"
      ? "नमस्ते! मैं ऑरा हूँ, आपकी स्मार्ट होम वॉइस असिस्टेंट। मैं आपकी क्या मदद कर सकती हूँ?"
      : "Hello! I am Aura, your security and smart home assistant. How can I help you today?";

    if (agentTextEl) agentTextEl.textContent = greeting;
    lastSpokenText = greeting;

    // Speak aloud directly
    try {
      speakText(greeting);
    } catch (e) {}
  }

  // =========================================================================
  // 4. Robust Speech Recognition (Fixes "3 out of 5 times doesn't listen")
  // =========================================================================

  function startListening() {
    primeAudio();

    // Clean up any stale or lingering recognition instance
    if (activeRecognition) {
      try { activeRecognition.abort(); } catch (e) {}
      activeRecognition = null;
    }

    var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      if (window.showToast) {
        window.showToast("Speech Recognition Unavailable", "Speech Recognition is not supported in this browser. Please use Google Chrome or Microsoft Edge.", "danger");
      }
      return;
    }

    // Always create a fresh instance per listen turn to eliminate stuck state
    var rec = new SR();
    rec.continuous = false;
    rec.interimResults = true;
    rec.maxAlternatives = 1;
    rec.lang = currentLang === "hi" ? "hi-IN" : "en-IN";

    rec.onstart = function () {
      isRecognizing = true;
      setOrbState("listening", "LISTENING...");
      if (hintEl) hintEl.textContent = "🔴 Listening... speak your command now";
    };

    rec.onresult = function (event) {
      var transcript = "";
      for (var i = event.resultIndex; i < event.results.length; i++) {
        transcript += event.results[i][0].transcript;
      }

      if (userTextEl) userTextEl.textContent = transcript;
      if (userLine) userLine.style.display = "flex";

      if (event.results[0] && event.results[0].isFinal) {
        try { rec.stop(); } catch (e) {}
        activeRecognition = null;
        isRecognizing = false;
        processVoiceInput(transcript);
      }
    };

    rec.onerror = function (e) {
      console.warn("[AURA] Speech Recognition Error:", e.error);
      activeRecognition = null;
      isRecognizing = false;
      setOrbState("idle", "STANDBY");
      if (hintEl) hintEl.textContent = "Click microphone or press Spacebar to talk to Aura";

      if (e.error === "not-allowed") {
        if (window.showToast) {
          window.showToast("Microphone Blocked", "Please grant microphone permissions in your browser address bar.", "warn", 6000);
        }
      }
    };

    rec.onend = function () {
      activeRecognition = null;
      isRecognizing = false;
      if (currentState === "listening") {
        setOrbState("idle", "STANDBY");
        if (hintEl) hintEl.textContent = "Click microphone or press Spacebar to talk to Aura";
      }
    };

    try {
      rec.start();
      activeRecognition = rec;
    } catch (err) {
      console.error("[AURA] Failed to start speech recognition:", err);
      activeRecognition = null;
      isRecognizing = false;
      setOrbState("idle", "STANDBY");
    }
  }

  function toggleListening() {
    if (isRecognizing && activeRecognition) {
      try { activeRecognition.stop(); } catch (e) {}
      activeRecognition = null;
      isRecognizing = false;
      setOrbState("idle", "STANDBY");
    } else {
      startListening();
    }
  }

  // =========================================================================
  // 5. Dispatch Voice Input to Aegis Security Gateway
  // =========================================================================

  function processVoiceInput(text) {
    if (!text || !text.trim()) {
      setOrbState("idle", "STANDBY");
      return;
    }

    primeAudio();
    setOrbState("thinking", "SCANNING POLICY & INTENT...");

    // 1. Pick a selected witty loading line and SPEAK IT ALOUD to the user!
    var loadingLines = currentLang === "hi" ? SPOKEN_LOADING_LINES_HI : SPOKEN_LOADING_LINES_EN;
    var chosenLine = loadingLines[Math.floor(Math.random() * loadingLines.length)];
    speakText(chosenLine);

    if (hintEl) hintEl.textContent = "🧠 " + chosenLine;

    // Reset UI transcript states immediately
    if (stepperContainer) stepperContainer.style.display = "block";
    resetVoiceStepper();

    if (approvalAlert) approvalAlert.style.display = "none";
    if (userLine) userLine.style.display = "flex";
    if (userTextEl) userTextEl.textContent = text;
    if (userLangLabel) userLangLabel.textContent = currentLang === "hi" ? "हिंदी" : "English";

    if (agentTextEl) {
      agentTextEl.textContent = "Analyzing command and checking security policies...";
    }

    api.sendChat(text)
      .then(function (res) {
        var reqId = res.request_id;
        pollVoiceTurn(reqId);
      })
      .catch(function (err) {
        setOrbState("idle", "STANDBY");
        if (agentTextEl) agentTextEl.textContent = "Error: " + err.message;
        if (window.showToast) window.showToast("Gateway Error", err.message, "danger");
      });
  }

  function resetVoiceStepper() {
    var pills = document.querySelectorAll("#voice-stepper [data-stage]");
    pills.forEach(function (pill) {
      pill.className = "pill pill-default text-xs";
    });
  }

  function updateVoiceStepperStage(stage, status) {
    var pill = document.querySelector('#voice-stepper [data-stage="' + stage + '"]');
    if (!pill) return;
    if (status === "pass") {
      pill.className = "pill pill-ok text-xs";
    } else if (status === "block") {
      pill.className = "pill pill-danger text-xs";
    } else if (status === "running" || status === "pending" || status === "hold") {
      pill.className = "pill pill-info text-xs";
    }
  }

  function pollVoiceTurn(reqId) {
    var startTime = Date.now();
    var lastStepCount = 0;
    var approvalTriggered = false;

    function poll() {
      api.get("/api/console/poll/" + encodeURIComponent(reqId))
        .then(function (data) {
          var steps = data.steps || [];
          for (var i = lastStepCount; i < steps.length; i++) {
            var s = steps[i];
            updateVoiceStepperStage(s.stage, s.status);

            // Detect if human approval is pending (matches 'running', 'pending', or 'hold')
            if (s.stage === "approval" && (s.status === "running" || s.status === "pending" || s.status === "hold") && !approvalTriggered) {
              approvalTriggered = true;
              handleApprovalRequired(s.detail);
            }
          }
          lastStepCount = steps.length;

          if (data.final) {
            var reply = data.final.reply || (data.final.error ? ("Blocked: " + data.final.error) : "Done.");
            lastSpokenText = reply;
            if (agentTextEl) agentTextEl.textContent = reply;

            if (data.final.error && data.final.error.indexOf("SESSION QUARANTINED") !== -1) {
              setOrbState("idle", "SESSION QUARANTINED");
              if (micTrigger) micTrigger.disabled = true;
              if (hintEl) {
                hintEl.textContent = "🚨 Session Quarantined: Hardware containment active. Admin release required.";
              }
              if (window.AegisApp && window.AegisApp.openQuarantineModal) {
                window.AegisApp.openQuarantineModal();
              }
              var qSpeech = currentLang === "hi"
                ? "अलर्ट: बार-बार हमलों के कारण सिस्टम क्वारंटाइन कर दिया गया है।"
                : "Alert: Hardware containment engaged. Session quarantined after repeated attacks.";
              lastSpokenText = qSpeech;
              speakText(qSpeech);
              return;
            }

            if (data.final.decision === "BLOCK") {
              setOrbState("idle", "BLOCKED BY POLICY");
              var blockSpeech = currentLang === "hi"
                ? "अनुरोध सुरक्षा नीति द्वारा ब्लॉक कर दिया गया है।"
                : "Request blocked by Aegis security policy: " + (data.final.error || "violation detected.");
              lastSpokenText = blockSpeech;
              speakText(blockSpeech);
            } else if (data.final.decision === "DENY") {
              setOrbState("idle", "ACTION DENIED");
              lastSpokenText = "Action was denied by human administrator.";
              speakText(lastSpokenText);
            } else {
              // SAY THE RESULT ALOUD TO THE USER!
              speakText(reply);
            }
            return;
          }

          if (Date.now() - startTime > 75000) {
            setOrbState("idle", "STANDBY");
            if (agentTextEl) agentTextEl.textContent = "Gateway response timed out.";
            return;
          }

          setTimeout(poll, 350);
        })
        .catch(function () {
          setOrbState("idle", "STANDBY");
        });
    }

    poll();
  }

  // =========================================================================
  // 6. Inline Operator Authorization Handler (No Page Reload / Context Preserved!)
  // =========================================================================

  var currentApprovalReqId = null;
  var currentApprovalHash = null;

  function handleApprovalRequired(detail) {
    var toolName = (detail && detail.tool) ? detail.tool : "high_risk_action";
    currentApprovalReqId = (detail && detail.request_id) ? detail.request_id : null;
    currentApprovalHash = (detail && detail.request_hash) ? detail.request_hash : "";
    var toolArgs = (detail && detail.args) ? detail.args : {};

    if (approvalAlert) approvalAlert.style.display = "block";
    if (approvalToolEl) approvalToolEl.textContent = toolName;

    var hashEl = document.getElementById("voice-approval-hash-display");
    if (hashEl) {
      hashEl.textContent = "Hash: " + (currentApprovalHash ? currentApprovalHash.slice(0, 14) + "..." : "pending");
    }

    var argsEl = document.getElementById("voice-approval-args");
    if (argsEl) {
      argsEl.textContent = JSON.stringify(toolArgs, null, 2);
    }

    if (agentTextEl) {
      agentTextEl.textContent = "Privileged action '" + toolName + "' requires human administrator authorization. Review below to authorize.";
    }

    // Speak notice to user
    speakText("This action requires human authorization. You can approve it directly on this screen.");

    // Eye-catching warning toast
    if (window.showToast) {
      window.showToast("Operator Approval Required", "Privileged action '" + toolName + "' held by security gateway.", "warn", 7000);
    }

    // 60-second interactive countdown timer
    var secondsLeft = 60;
    var progressFill = document.getElementById("voice-approval-progress");
    if (approvalCountdownEl) approvalCountdownEl.textContent = String(secondsLeft);
    if (progressFill) progressFill.style.width = "100%";

    if (approvalCountdownTimer) clearInterval(approvalCountdownTimer);
    approvalCountdownTimer = setInterval(function () {
      secondsLeft -= 1;
      if (approvalCountdownEl) approvalCountdownEl.textContent = String(Math.max(0, secondsLeft));
      if (progressFill) progressFill.style.width = Math.max(0, (secondsLeft / 60) * 100) + "%";
      if (secondsLeft <= 0) {
        clearInterval(approvalCountdownTimer);
        approvalCountdownTimer = null;
      }
    }, 1000);

    // If request_hash was not in detail, fetch from pending
    if (!currentApprovalHash || Object.keys(toolArgs).length === 0) {
      api.get("/api/approvals/pending").then(function (res) {
        var items = (res && res.pending) || [];
        for (var k = 0; k < items.length; k++) {
          if (items[k].tool === toolName || items[k].request_id === currentApprovalReqId) {
            currentApprovalReqId = items[k].request_id;
            currentApprovalHash = items[k].request_hash || currentApprovalHash;
            if (hashEl) hashEl.textContent = "Hash: " + (currentApprovalHash ? currentApprovalHash.slice(0, 14) + "..." : "pending");
            if (argsEl) argsEl.textContent = JSON.stringify(items[k].args || toolArgs, null, 2);
            break;
          }
        }
      }).catch(function () {});
    }
  }

  // Inline Approve Button (1-Click Authorization directly on Voice screen!)
  var inlineApproveBtn = document.getElementById("voice-inline-approve-btn");
  if (inlineApproveBtn) {
    inlineApproveBtn.addEventListener("click", function () {
      if (!currentApprovalReqId) return;
      inlineApproveBtn.disabled = true;
      inlineApproveBtn.textContent = "Authorizing...";

      api.post("/api/approvals/decide", {
        request_id: currentApprovalReqId,
        request_hash: currentApprovalHash,
        approved: true
      })
      .then(function () {
        if (approvalCountdownTimer) {
          clearInterval(approvalCountdownTimer);
          approvalCountdownTimer = null;
        }
        if (approvalAlert) approvalAlert.style.display = "none";
        if (window.showToast) window.showToast("Action Authorized", "Cryptographic HMAC generated. Executing command...", "ok", 4000);
        speakText("Action approved by operator. Executing command now...");
        if (agentTextEl) agentTextEl.textContent = "Authorized by administrator. Executing command...";
        inlineApproveBtn.disabled = false;
        inlineApproveBtn.textContent = "Approve Action Now";
      })
      .catch(function (err) {
        if (window.showToast) window.showToast("Authorization Error", err.message, "danger");
        inlineApproveBtn.disabled = false;
        inlineApproveBtn.textContent = "Approve Action Now";
      });
    });
  }

  // Inline Deny Button
  var inlineDenyBtn = document.getElementById("voice-inline-deny-btn");
  if (inlineDenyBtn) {
    inlineDenyBtn.addEventListener("click", function () {
      if (!currentApprovalReqId) return;
      inlineDenyBtn.disabled = true;

      api.post("/api/approvals/decide", {
        request_id: currentApprovalReqId,
        request_hash: currentApprovalHash,
        approved: false
      })
      .then(function () {
        if (approvalCountdownTimer) {
          clearInterval(approvalCountdownTimer);
          approvalCountdownTimer = null;
        }
        if (approvalAlert) approvalAlert.style.display = "none";
        if (window.showToast) window.showToast("Action Denied", "Operation denied and audited.", "warn", 4000);
        speakText("Action denied by operator.");
        if (agentTextEl) agentTextEl.textContent = "Operator denied action.";
        inlineDenyBtn.disabled = false;
      })
      .catch(function (err) {
        if (window.showToast) window.showToast("Denial Error", err.message, "danger");
        inlineDenyBtn.disabled = false;
      });
    });
  }

  if (stayBtn) {
    stayBtn.addEventListener("click", function () {
      if (approvalCountdownTimer) {
        clearInterval(approvalCountdownTimer);
        approvalCountdownTimer = null;
      }
      if (approvalAlert) approvalAlert.style.display = "none";
      if (window.showToast) window.showToast("Banner Dismissed", "Action remains held in security queue.", "info");
    });
  }

  // =========================================================================
  // 7. Event Listeners & Shortcuts
  // =========================================================================

  if (micTrigger) {
    micTrigger.addEventListener("click", toggleListening);
  }

  // Replay Audio button
  if (replayBtn) {
    replayBtn.addEventListener("click", function () {
      primeAudio();
      if (lastSpokenText) {
        speakText(lastSpokenText);
        if (window.showToast) window.showToast("Replaying Audio", lastSpokenText, "ok", 3000);
      }
    });
  }

  // Spacebar hotkey
  window.addEventListener("keydown", function (e) {
    if (e.code === "Space" && e.target.tagName !== "INPUT" && e.target.tagName !== "TEXTAREA") {
      e.preventDefault();
      toggleListening();
    }
  });

  // Language switch
  if (langBtnEn) {
    langBtnEn.addEventListener("click", function () {
      currentLang = "en";
      langBtnEn.classList.add("active");
      if (langBtnHi) langBtnHi.classList.remove("active");
      triggerAuraGreeting();
      if (window.showToast) window.showToast("Aura Language", "Set to English", "ok");
    });
  }

  if (langBtnHi) {
    langBtnHi.addEventListener("click", function () {
      currentLang = "hi";
      langBtnHi.classList.add("active");
      if (langBtnEn) langBtnEn.classList.remove("active");
      triggerAuraGreeting();
      if (window.showToast) window.showToast("ऑरा भाषा", "हिंदी चुनी गई", "ok");
    });
  }

  // Speaker toggle
  if (speakerToggle) {
    speakerToggle.addEventListener("click", function () {
      speakerEnabled = !speakerEnabled;
      if (speakerLabel) {
        speakerLabel.textContent = speakerEnabled ? "Speaker: ON" : "Speaker: OFF";
      }
      if (!speakerEnabled && window.speechSynthesis) {
        window.speechSynthesis.cancel();
      }
      if (window.showToast) {
        window.showToast("Speaker Audio", speakerEnabled ? "Audio speech enabled" : "Audio speech muted", "info");
      }
    });
  }

  // Showcase Command Chips
  var commandChips = document.querySelectorAll(".voice-cmd-chip, .voice-suggestion-chip");
  commandChips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      var phrase = chip.getAttribute("data-speak");
      if (phrase) {
        var isHindi = /[\u0900-\u097F]/.test(phrase);
        if (isHindi && langBtnHi) {
          langBtnHi.click();
        } else if (!isHindi && langBtnEn) {
          langBtnEn.click();
        }
        processVoiceInput(phrase);
      }
    });
  });

  // Listen for global quarantine release from modal
  window.addEventListener("aegis:quarantine_released", function () {
    if (micTrigger) micTrigger.disabled = false;
    setOrbState("idle", "STANDBY");
    if (hintEl) {
      hintEl.textContent = "Click microphone or press Spacebar to talk to Aura";
    }
  });

  // Greet on load (with fallback on first click if blocked by browser autoplay)
  setTimeout(function () {
    triggerAuraGreeting();
  }, 350);

})();
