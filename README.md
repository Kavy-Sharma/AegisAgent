\# AegisAgent



Security gateway between an AI agent (Ollama) and IoT hardware (ESP32).



\## Team setup (do this once per laptop)



1\. Install Python 3.10+, Ollama (`ollama pull llama3.1`), and:

&#x20;  ```

&#x20;  pip install ollama paho-mqtt streamlit pytest python-dotenv

&#x20;  ```

2\. Clone this repo:

&#x20;  ```

&#x20;  git clone https://github.com/YOUR-USERNAME/AegisAgent.git

&#x20;  cd AegisAgent

&#x20;  ```

3\. Person 2 only, additionally: install Mosquitto + Arduino IDE (see project notes doc).



\## Daily workflow



```

git pull              # before working

... make changes ...

git add .

git commit -m "describe what you changed"

git push               # after working

```



\## Phase status



\- \[x] Phase 0 — environment setup

\- \[x] Phase 1 — fake tool functions (`agent/tools.py`)

\- \[x] Phase 2 — real Ollama tool-calling (`agent/agent.py`)

\- \[ ] Phase 3 — gateway inserted

\- \[ ] Phase 4 — risk levels + permissions

\- \[ ] Phase 5 — injection detection

\- \[ ] Phase 6 — human approval

\- \[ ] Phase 7 — real ESP32 + MQTT

\- \[ ] Phase 8 — dashboard

\- \[ ] Phase 9 — attack test suite

\- \[ ] Phase 10 — report

