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
│     Ollama LLM Agent      │ ──► Model Tool Calling (llama3.1)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│     Security Gateway      │ ──► 1. Tool Existence Check
│        (gateway.py)       │ ──► 2. Role-Based Access Control (RBAC: guest / admin)
└─────────────┬─────────────┘ ──► 3. Sliding-Window Rate Limiter
              │               ──► 4. Human-in-the-Loop Approval (One-Time Request Hash)
              ▼
┌───────────────────────────┐
│  Hardware Bridge / Broker │ ──► Authenticated Local MQTT Broker (Mosquitto)
│     (security/hardware)   │ ──► Command Allowlist Check (Defense in Depth)
└─────────────┬─────────────┘ ──► Physical Attack Blocked LED Trigger (2s Debounce)
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
- [ ] **Phase 8** — Web Dashboard Interface
- [ ] **Phase 9** — Automated Security Attack Test Suite
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

### 4. Hardware Integration & Attack LED (Phase 7)
- Dual-mode support (`fake` for offline testing/CI, `mqtt` for real ESP32 hardware).
- Secure MQTT communication over QoS 1 using `paho-mqtt` with authentication credentials loaded from environment variables or local `.env`.
- Physical Red "Attack Blocked" LED triggered on block decisions with a 2-second rate debounce filter.
- ESP32 firmware featuring non-blocking `millis()` execution, Last Will & Testament (LWT) tracking, and on-device command allowlisting.

### 5. Cryptographic Audit Logging
- All gateway decisions, prompt inspections, approval requests, role switches, and hardware dispatches are chained using SHA-256 hashes in `logs/audit_log.jsonl`.
- Immutable audit chain verified via `python security/verify_log.py`.

---

## ⚙️ Tools & Security Matrix

| Tool Name | Risk Level | Description | Allowed Roles |
| :--- | :--- | :--- | :--- |
| `turn_light_on` | LOW | Turns LED light on | guest, admin |
| `turn_light_off` | LOW | Turns LED light off | guest, admin |
| `read_temperature` | LOW | Reads ambient temperature sensor | guest, admin |
| `activate_alarm` | HIGH | Sounds buzzer alarm (Requires Approval) | admin |
| `unlock_door` | HIGH | Unlocks door lock (Requires Approval) | admin |

---

## 💻 Installation & Setup

### 1. Prerequisites
- **Python 3.10+**
- **Ollama** (`ollama pull llama3.1`)
- **Mosquitto MQTT Broker** (for hardware mode)

### 2. Install Dependencies
```bash
pip install ollama paho-mqtt pytest pyyaml
```

### 3. Environment Credentials Configuration
Create a local `.env` file at the root directory:
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

### 1. Run Complete Automated Test Suite (30 Pytest Tests)
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
   Set `hardware.mode: mqtt` in `policy.yaml`.

---

## 📁 Repository Structure

```
AegisAgent/
├── agent/
│   ├── agent.py               # Main Agent CLI & Ollama Integration
│   └── tools.py               # Tool Dispatchers & Hardware Interfaces
├── security/
│   ├── approval.py            # Phase 6 Human Approval Framework
│   ├── gateway.py             # Security Gateway Interception Engine
│   ├── hardware.py            # Phase 7 Hardware Bridge & MQTT Client
│   ├── logger.py              # SHA-256 Tamper-Evident Audit Logger
│   ├── policy_loader.py       # policy.yaml Configuration Loader
│   ├── rate_limiter.py        # Sliding-Window Rate Limiter
│   ├── verify_log.py          # Cryptographic Audit Log Verifier
│   ├── detection/
│   │   ├── base.py            # Detection Dataclasses & Interfaces
│   │   ├── normalizer.py      # Multi-View Text Normalizer
│   │   ├── rule_detector.py   # Data-Driven Rule Engine
│   │   ├── context_detector.py# Multi-Turn Context Suspicion Engine
│   │   └── engine.py          # Detection Engine Orchestrator
│   └── rules/
│       └── injection_rules.yaml # Prompt Injection Rule Specifications
├── esp32/
│   ├── secrets.example.h      # ESP32 Secrets Template
│   └── aegis_device/
│       └── aegis_device.ino   # ESP32 Firmware Sketch
├── mosquitto/
│   ├── mosquitto.conf         # Broker Configuration
│   ├── acl.conf               # Topic Access Control List
│   └── README_mosquitto.md    # Mosquitto Setup & Verification Guide
├── scripts/
│   ├── try_approval.py        # Approval System REPL
│   ├── try_detection.py       # Detection Engine REPL
│   └── try_hardware.py        # Hardware Dispatch CLI
├── tests/
│   ├── test_approval.py       # Pytest Approval Suite
│   ├── test_detection.py      # Pytest Prompt Injection Suite
│   └── test_hardware.py       # Pytest Hardware & Alert Suite
├── logs/
│   └── audit_log.jsonl        # Cryptographic Audit Log File
├── policy.yaml                # Master Security Policy Configuration
├── conftest.py                # Pytest Test Discovery Configuration
├── .env.example               # Environment Variables Template
└── README.md                  # Project Documentation
```
