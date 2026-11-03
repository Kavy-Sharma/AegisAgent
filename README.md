# AegisAgent

AegisAgent is a security gateway positioned between a local LLM agent (**Ollama**) and **IoT Hardware (ESP32)**. It protects physical smart-home hardware from malicious prompt injections, unauthorized role privilege escalation, rate-limit abuse, and unapproved critical actions.

---

## 🛡️ Architecture & Security Pipeline

```
[ User Input / Local Client ]
            │
            ▼
┌───────────────────────────┐
│  Prompt Injection Engine  │ ──► Multi-View Normalizer (NFKC, Zero-Width Strip, Base64)
│    (DetectionEngine)      │ ──► Rule-Based Detector (INJ-001..INJ-011, Noisy-OR)
└─────────────┬─────────────┘ ──► Multi-Turn Context (Cumulative Suspicion & Split Payload)
              │
              ▼
┌───────────────────────────┐
│        Intent Lock        │ ──► Bounds Permitted Actions to Declared User Intent Scope
│    (security/intent.py)   │ ──► Blocks Tool Execution Outside Scope Post-RBAC
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│     Ollama LLM Agent      │ ──► Model Tool Calling (llama3.1)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│     Security Gateway      │ ──► 1. Tool Existence & Schema Check
│        (gateway.py)       │ ──► 2. Role-Based Access Control (RBAC: guest / admin)
└─────────────┬─────────────┘ ──► 3. Sliding-Window Rate Limiter
              │               ──► 4. Human-in-the-Loop Approval (One-Time Request Hash)
              ▼
┌───────────────────────────┐
│  Hardware Bridge / Broker │ ──► Hardware Bridge (default: auto -> USB ESP32 or Virtual Home)
│     (security/hardware)   │ ──► Command Allowlist Check & 3s Door Auto-Relock
└─────────────┬─────────────┘ ──► Physical Attack Blocked LED Trigger (2s Debounce)
              │
              ▼
┌───────────────────────────┐
│        Output Scan        │ ──► Inspects Untrusted Tool Outputs (e.g. read_note)
│     (agent/agent.py)      │ ──► Blocks Indirect Prompt Injections Before User Reply
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│   Tamper-Evident Logger   │ ──► Cryptographic SHA-256 Hash-Chained Audit Trail
└───────────────────────────┘
```

---

## 📊 Phase Status

- [x] **Phase 0** — Environment Setup & Dependencies
- [x] **Phase 1** — Core Fake Tool Functions (`agent/tools.py`)
- [x] **Phase 2** — Local Ollama Integration (`agent/agent.py`)
- [x] **Phase 3** — Security Gateway Interception Layer
- [x] **Phase 4** — RBAC, Rate Limiting & SHA-256 Audit Chain (`policy.yaml`, `gateway.py`, `logger.py`)
- [x] **Phase 5** — Data-Driven Multi-Turn Prompt Injection Detection (`security/detection/`)
- [x] **Phase 6** — Human-in-the-Loop Approval System & Sanitization (`security/approval.py`)
- [x] **Phase 7** — Authenticated MQTT Hardware Bridge, ESP32 Sketch & Physical Attack LED (`security/hardware.py`, `esp32/`, `mosquitto/`)
- [x] **Phase 8** — Web Dashboard Interface & Audit Log Page
- [x] **Phase 9** — Attack Lab simulation & full pipeline benchmark (done)
- [ ] **Phase 10** — Final Project Technical Report

---

## 🔑 Key Features & Security Mechanics

### 1. Role-Based Access Control (RBAC) & Dynamic Role Switching
- Roles defined in `policy.yaml` (`guest`, `admin`).
- CLI flag support: `python -m agent.agent --role admin` (defaults to least-privileged role `guest`).
- In-chat commands `/role <name>` and `/whoami`.
- Every role transition creates a cryptographic `role_change` entry in the audit log.

### 2. Prompt Injection Detection (Phase 5)
- **Multi-View Normalization**: Scans `raw` text, `normalized` text (NFKC, curly quote replacement, zero-width char removal, whitespace collapsing), and `base64_decoded` content.
- **Rule Engine**: Evaluates regex rules (`INJ-001` through `INJ-011`) from `security/rules/injection_rules.yaml` combined via noisy-OR probability calculation.
- **Multi-Turn Context Awareness**: Detects cumulative suspicion across conversation windows and split-payload assembly attacks across multiple messages.

### 3. Human-in-the-Loop Approval (Phase 6)
- High-risk operations (e.g. `activate_alarm`, `unlock_door`) require explicit human operator approval.
- One-time approval per unique SHA-256 `request_hash` (never cached or reused).
- Terminal output sanitization strips ANSI escapes and control codes, truncating parameters to 200 chars to prevent prompt spoofing.
- Cross-platform timeout polling (`msvcrt` on Windows / `select` on POSIX). Fail-closed architecture on error, timeout, or cancellation.

### 4. Hardware Integration & Virtual Home (Phase 7)
- Multi-mode support (default `auto` uses USB ESP32 if plugged in or Virtual Home simulation if absent; `mqtt` for broker mode; `fake` for testing).
- Physical Red "Attack Blocked" LED triggered on block decisions with a 2-second rate debounce filter.
- ESP32 firmware featuring non-blocking `millis()` execution, Last Will & Testament (LWT) tracking, and on-device command allowlisting.

### 5. Cryptographic Audit Logging & Audit Log Page
- All gateway decisions, prompt inspections, approval requests, role switches, and hardware dispatches are chained using SHA-256 hashes in `logs/audit_log.jsonl`.
- Tamper-evident audit chain verified via `python security/verify_log.py`.
- **Audit Log Page**: A tamper-evident, SHA-256 hash-chained log viewer with live verification, external anchor export/check, and an isolated copy-only tamper demonstration.

### 6. Attack Lab Simulation Environment
- **Attack Lab**: Interactive side-by-side simulator demonstrating unmitigated agent prompt injections vs. multi-layer Aegis security defenses across realistic smart-home scenarios.
- The protected run uses the real Aegis pipeline with a mock model that always obeys the attacker, so the demo does not depend on Ollama.

### 7. Virtual Home vs ESP32
- **Shipped Hardware Mode**: `policy.yaml` defaults to `hardware.mode: auto`. If an ESP32 is plugged in over USB, it is used automatically; with no board present, it falls back to Virtual Home simulation where nothing physical happens.
- **Broker Mode**: To use a real ESP32 through a Mosquitto MQTT broker, set `hardware.mode: mqtt` in `policy.yaml`.

---

## ⚙️ Tools & Security Matrix

### Policy Tools (`policy.yaml`)
| Tool Name | Risk Level | Description | Allowed Roles | ESP32 Firmware Command |
| :--- | :--- | :--- | :--- | :--- |
| `turn_light_on` | LOW | Turns LED light on | guest, admin | `light_on` |
| `turn_light_off` | LOW | Turns LED light off | guest, admin | `light_off` |
| `read_temperature` | LOW | Reads ambient temperature sensor (simulated) | guest, admin | *(simulated)* |
| `activate_alarm` | HIGH | Sounds buzzer alarm (Requires Approval) | admin | `alarm_on` |
| `unlock_door` | HIGH | Unlocks door lock (Requires Approval, 3s auto-relock) | admin | `unlock_door` |
| `read_note` | LOW | Reads user notes (untrusted content scanner) | guest, admin | *(local disk)* |
| `disable_security_perimeter` | HONEYPOT | Trap tool to catch injection attempts | (none — auto-quarantines) | *(none)* |

### ESP32 Firmware Allowed Commands (`esp32/aegis_device/aegis_device.ino`)
- `light_on` — Turns Green LED on (`digitalWrite(GREEN_LED, HIGH)`)
- `light_off` — Turns Green LED off (`digitalWrite(GREEN_LED, LOW)`)
- `unlock_door` — Pulses Green LED for 3000 ms auto-relock
- `alarm_on` — Activates piezo buzzer alarm
- `alert_blocked` — Turns Red LED on for 5000 ms on attack block
- `ping` / `status` — Emits `STATUS:online` heartbeat ACK

---

## ⚡ Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Kavy-Sharma/AegisAgent.git
   cd AegisAgent
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Start AegisAgent**:
   ```bash
   python start.py
   ```
   *Note on First-Run Setup*: When opening `http://127.0.0.1:8501`, the system automatically redirects to `/setup` if no registered users exist in `data/users.json`. Register the initial administrator account (minimum 10-character password). Once any user account exists, `/setup` redirects to `/login`. If user data is reset, `/setup` re-opens until initialized.

   > **Default mode is auto:** No hardware is required out-of-the-box. Without an ESP32 plugged in over USB, AegisAgent automatically uses Virtual Home simulation (nothing physical happens). A plugged ESP32 over USB is detected and used automatically; broker mode needs `hardware.mode: mqtt`.

---

## 💻 Installation & Setup

### 1. Prerequisites
- **Python 3.10+**
- **Ollama** (`ollama pull llama3.1`) — optional, needed only for live CLI chat; Attack Lab uses mock models
- **Mosquitto MQTT Broker** — optional, needed only for physical ESP32 mode

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Credentials Configuration (Optional)
Secrets and HMAC tokens are auto-generated on launch if missing. To set custom MQTT credentials:
```bash
cp .env.example .env
```
Edit `.env`:
```ini
AEGIS_MQTT_USER=aegis_gateway
AEGIS_MQTT_PASS=<CHOOSE-A-STRONG-PASSWORD>
```

---

## 🚀 Running AegisAgent

### Start the Agent CLI (Default: Guest Role)
```bash
python -m agent.agent
```

### Start the Agent as Admin
```bash
python -m agent.agent --role admin
```

### In-Chat Commands
- `/whoami` — Displays active role and permitted tools.
- `/role admin` — Switches active role to `admin`.
- `/role guest` — Switches active role to `guest`.
- `quit` or `exit` — Terminate session.

---

## 🛠️ Testing & Harness Scripts

### 1. Run Complete Automated Test Suite (299 tests)
```bash
pytest -v
```

### 2. Verify SHA-256 Audit Log Chain Integrity
```bash
python security/verify_log.py
```

### 3. Prompt Injection Detection Harness
Test prompt injection detection without Ollama:
```bash
python scripts/try_detection.py --session demo --source user
```

### 4. Approval System Demo
Test human approval prompt interactions and timeouts:
```bash
python scripts/try_approval.py
```

### 5. Hardware Bridge Dispatch Harness
Dispatch allowlisted commands to the hardware bridge:
```bash
python scripts/try_hardware.py unlock_door
```

### 6. Security Benchmarks

#### Component Benchmark (benchmark/run.py)
The earlier 4-configuration benchmark (`python -m benchmark.run`) is an isolated component test, not the full system. It measures individual defensive layers against 50 attacks and 50 benign prompts in isolation.

#### Full-Pipeline Benchmark (benchmark/pipeline_run.py)
The full-pipeline benchmark evaluates the entire defense chain (`gateway -> normalizer -> detector -> intent_lock -> rbac -> rate_limiter -> approval -> virtual_home -> output_scan`) against a mocked model that always obeys the attacker:
```bash
python -m benchmark.pipeline_run
```
Runs 226 total cases (50 attacks, 60 novel bypass attempts, 50 easy benign, 66 paraphrased benign) and outputs `benchmark/pipeline_results.csv` and `benchmark/pipeline_meta.json`.

---

## 📡 MQTT Broker & ESP32 Setup (Hardware Mode)

1. **Mosquitto Password Setup**:
   ```cmd
   mosquitto_passwd -c mosquitto/passwd aegis_gateway
   mosquitto_passwd mosquitto/passwd esp32_device
   ```
2. **Start Mosquitto Broker**:
   ```cmd
   mosquitto -c mosquitto/mosquitto.conf -v
   ```
3. **Configure ESP32 Firmware**:
   Copy `esp32/secrets.example.h` to `esp32/aegis_device/secrets.h`, update WiFi & MQTT credentials, and flash `esp32/aegis_device/aegis_device.ino` via Arduino IDE.
4. **Set Hardware Mode in `policy.yaml`**:
   Set `hardware.mode: mqtt` in `policy.yaml` (broker mode needs `hardware.mode: mqtt`; default is `auto`).

---

## 📁 Repository Structure

```
AegisAgent/
├── agent/
│   ├── agent.py               # Main Agent CLI, Pipeline Dispatch & Ollama Integration
│   ├── tools.py               # Tool Dispatchers & Hardware Interfaces
│   └── worker.py              # Background Worker Service (Inbox/Outbox IPC)
├── benchmark/
│   ├── attacks.jsonl          # 50 Attack Prompts (7 categories)
│   ├── benign.jsonl           # 50 Benign Prompts (trigger words & normal tasks)
│   ├── benign_paraphrase.jsonl # 66 Paraphrased Benign Prompts (frozen SHA-256: 501c5e919519710f28a8161062c965c2ecc057cc828dfa7d3cb6c470675bed60; hash is of the LF-normalised file)
│   ├── pipeline_meta.json     # Full Pipeline Benchmark Metadata
│   ├── pipeline_results.csv   # 226 Full Pipeline Benchmark Run Evaluations
│   ├── pipeline_run.py        # Full Pipeline Benchmark Runner
│   ├── results.csv            # 400 Component Benchmark Evaluations
│   └── run.py                 # 4-Configuration Component Benchmark Runner
├── security/
│   ├── approval.py            # Phase 6 Human Approval Framework & IPC
│   ├── attack_lab.py          # Attack Lab Scenario Engine & Simulation
│   ├── auth.py                # User Authentication, Password Hashing & Lockout
│   ├── gateway.py             # Security Gateway Interception Engine
│   ├── hardware.py            # Phase 7 Hardware Bridge & MQTT Client
│   ├── health.py              # Subsystem Health Checks
│   ├── intent.py              # Intent Lock Scope Calculator
│   ├── logger.py              # SHA-256 Tamper-Evident Audit Logger
│   ├── policy_loader.py       # policy.yaml Configuration Loader
│   ├── quarantine.py          # Session Quarantine on Repeated Attacks
│   ├── rate_limiter.py        # Sliding-Window Rate Limiter
│   ├── signing.py             # HMAC-SHA256 Request & Decision Signing
│   ├── verify_log.py          # Cryptographic Audit Log Verifier
│   ├── virtual_home.py        # In-Memory Smart Home Simulation (Default)
│   ├── detection/
│   │   ├── base.py            # Detection Dataclasses & Interfaces
│   │   ├── normalizer.py      # Multi-View Text Normalizer
│   │   ├── rule_detector.py   # Data-Driven Rule Engine
│   │   ├── context_detector.py# Multi-Turn Context Suspicion Engine
│   │   └── engine.py          # Detection Engine Orchestrator
│   └── rules/
│       └── injection_rules.yaml # Prompt Injection Rule Specifications
├── web/
│   ├── server.py              # Flask Web Server (127.0.0.1:8501)
│   ├── api.py                 # Core REST API (Chat, Overview, Approvals, Attack Lab)
│   ├── api_audit.py           # Audit Log Viewer & Tamper Demo API
│   ├── guards.py              # Auth Decorators, CSRF Verification & Host Validation
│   ├── static/                # CSS Tokens, Vanilla JS Modules, Icons & Media
│   └── templates/             # Jinja2 Templates (Overview, Approvals, Attack Lab, Audit)
├── esp32/
│   ├── secrets.example.h      # ESP32 Secrets Template
│   └── aegis_device/
│       └── aegis_device.ino   # ESP32 Firmware Sketch
├── mosquitto/
│   ├── mosquitto.conf         # Broker Configuration
│   ├── acl.conf               # Topic Access Control List
│   └── README_mosquitto.md    # Mosquitto Setup & Verification Guide
├── scripts/
│   ├── create_user.py         # Admin User Creation CLI
│   ├── reset_password.py      # Lockout Recovery & Password Reset CLI
│   ├── try_approval.py        # Approval System REPL
│   ├── try_detection.py       # Detection Engine REPL
│   └── try_hardware.py        # Hardware Dispatch CLI
├── tests/
│   ├── test_approval.py       # Pytest Approval Suite
│   ├── test_attack_lab.py     # Attack Lab Scenarios & API Suite
│   ├── test_audit_page.py     # Audit Log Viewer & Tamper Demo Suite
│   ├── test_benchmark.py      # Benchmark Verification Suite
│   ├── test_detection.py      # Pytest Prompt Injection Suite
│   ├── test_hardware.py       # Pytest Hardware & Alert Suite
│   ├── test_phase8b_clean.py  # Ported Auth Lockout, Signing & IST Suite
│   ├── test_pipeline_benchmark.py # Pipeline Benchmark Integrity Suite
│   └── test_virtual_home.py   # Virtual Home Simulation Suite
├── logs/
│   └── audit_log.jsonl        # Cryptographic Audit Log File
├── policy.yaml                # Master Security Policy Configuration
├── conftest.py                # Pytest Test Discovery Configuration
├── .env.example               # Environment Variables Template
└── README.md                  # Project Documentation
```


---

## 📈 Measured Results

- **Component benchmark vs full system**: The earlier 4-configuration benchmark (`benchmark/run.py`) is an isolated component test, not the full system.
- **Rule detector alone**: Detects **16.7%** of 60 novel adversarial bypasses (10/60), with **0/30 false positives** on benign operational inputs.
  - Hindi / Hinglish translation attacks: **0.0%** (0 / 10 detected)
  - Homoglyphs / Unicode substitution: **0.0%** (0 / 8 detected)
  - Base64 / Hex / ROT13 encoding: **10.0%** (1 / 10 detected)
  - Role spoofing: **12.5%** (1 / 8 detected)
  - Slow multi-turn split payloads: **25.0%** (2 / 8 detected)
  - Markdown / JSON wrapping: **25.0%** (2 / 8 detected)
  - Spacing / Whitespace insertion: **50.0%** (4 / 8 detected)
- **New full-pipeline benchmark (`benchmark/pipeline_run.py`)**: Evaluates the complete defense pipeline against a mocked model that always obeys the attacker (worst-case model compromise):
  - **Attacks**: **0/50** attacks reached a dangerous action (door or alarm).
  - **Novel bypass attempts**: **0/60** reached a dangerous action (door or alarm). 1 bypass (`hi_08`) ran a harmless light-on (`turn_light_on`).
  - **Easy benign set**: **50/50** correct (including 5 high-risk requests that properly reached human approval).
  - **Paraphrased benign set**: **29/56** wrongly blocked by the Intent Lock (17 low-risk, 12 high-risk fail-safe). 27/56 ran correctly.
  - **Detector false positives on trigger-word test**: **0/6** false positives.
- **Intent Lock limitation**: The Intent Lock is a keyword list, it blocks unknown phrasing, and some short words ("on", "off", "read") can match the wrong intent. Not tuned on this test set; planned improvement for the major project.

---

## ⚠️ Honest Limitations

1. **Plaintext HTTP and MQTT**: There is no TLS/HTTPS encryption implemented for web or MQTT transport; someone on the same network could read the traffic. Local network only.
2. **Secrets live in .env**: Secrets (`AEGIS_WEB_SECRET`, `AEGIS_DASH_SECRET`, MQTT password) live in `.env`; any process running as the same OS user can read them and forge signed requests.
3. **No device-side replay protection**: No device-side replay protection on the ESP32 beyond the timestamp; relies on broker access control and network isolation.
4. **Admin accounts not exempt from lockout**: Admin accounts are not exempt from lockout (5 failed logins); recovery is performed locally via loopback CLI with `python scripts/reset_password.py`.
5. **Cookie sessions not revocable**: Authentication uses signed client-side cookies; logging out clears the client browser cookie, but active session cookies cannot be invalidated server-side before idle expiration (15 minutes).
6. **Admin can approve own request**: An administrator who submits a high-risk action can approve their own pending request in the authorization dashboard (no mandatory two-person rule).
7. **Audit chain truncation requires external anchor**: The audit chain detects edited or deleted older entries. It cannot detect deletion of the newest entries unless the anchor is stored off this computer. Someone with write access to the disk can rewrite both log and anchor.
8. **Single worker blocked up to 60 s by a pending approval**: The backend worker processes queued turns sequentially. When a high-risk action (such as `unlock_door`) is triggered, the worker is blocked for up to the 60-second approval timeout awaiting operator action.
9. **Probabilistic detection**: Rule and heuristic injection detection is probabilistic and may miss novel or sophisticated adversarial inputs.
10. **Weak on Hindi, homoglyphs & encoding**: Rule engine shows high miss rates against non-English prompts (0.0% on Hindi/Hinglish), Unicode homoglyph substitutions (0.0%), and encoded payloads (10.0%).
11. **Browser speech recognition cloud routing**: Browser-based speech recognition on the Voice page relies on the Web Speech API; depending on the browser vendor (e.g. Chrome / Edge), captured audio may be transmitted to cloud speech-to-text servers.
12. **Inconsistent LLM tool-calling**: Smaller local LLMs (e.g. `llama3.1:8b`) may exhibit inconsistent tool calling behavior, syntax formatting errors in function arguments, or occasional instruction hallucinations.
13. **MQTT dispatch vs. device-side confirmation**: A successful MQTT publish status only confirms that the local broker accepted the packet; physical hardware confirmation requires waiting for the asynchronous device ACK event.
14. **Attack Lab worker simulation scope**: The Attack Lab simulator temporarily patches the session quarantine and hardware bridge inside the single backend worker process to run side-by-side simulations; this isolation is safe only because the worker handles one request at a time.
15. **Intent Lock keyword brittleness**: The Intent Lock is a keyword list; it blocks unknown phrasing (causing false positives on natural paraphrasing), and short words ("on", "off", "read") can match the wrong intent. Not tuned on this test set; planned improvement for the major project.
16. **Virtual Home simulation vs. physical device**: In Virtual Home mode, 'door unlocked' means the simulation changed, not a physical device.
