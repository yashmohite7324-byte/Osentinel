# OSentinel 🛡️

OSentinel is a lightweight, AI-driven Endpoint Detection and Response (EDR) agent with a modern, glassmorphic React dashboard. It provides real-time system monitoring, autonomous threat containment, and an interactive AI analyst powered by local Large Language Models.

![Dashboard Preview](web/favicon.ico) <!-- You can add a real screenshot here later! -->

## 🚀 Features

- **Real-Time Telemetry:** Monitors processes, network connections, file integrity, and system resources using `psutil`.
- **Cyber-Glass Dashboard:** A responsive, dark-mode React UI tracking risk scores, live metrics, and incident queues.
- **Autonomous Response:** Capable of suspending or terminating malicious processes before they spread (configurable dry-run mode).
- **Ask the Analyst:** Built-in chat interface to query a local `llama3.1` model about active incidents and system posture.

## 🧠 Detection Engine & ML Models

OSentinel uses a multi-layered detection pipeline to identify threats without overwhelming the system. 

### 1. The Dataset (`corpus.jsonl`)
The machine learning layers are trained on a synthesized dataset stored in `data/models/corpus.jsonl`. 
- **How it's built:** Instead of relying purely on static external datasets, OSentinel uses an LLM "Teacher" (or built-in templates) to dynamically synthesize and label realistic benign and malicious command-line executions.
- **Continuous Learning:** If no model exists on startup, the agent builds one from the synthetic corpus automatically, meaning the dataset evolves based on the host environment.

### 2. The ML Models
The agent passes telemetry through 4 distinct layers of AI/ML evaluation:

- **Layer 1 - Rule Engine:** A deterministic YAML ruleset (`rules/rules.yaml`) running dynamic Python expressions and YARA files to catch known malware signatures instantly.
- **Layer 2 - Semantic Similarity:** Uses a pretrained sentence-transformer (or hashed character n-grams) to score command lines based on how conceptually similar they are to known attack tooling, and how anomalous they are compared to the host's normal baseline.
- **Layer 2b - Distilled Classifier:** A lightning-fast logistic regression model trained offline on the `corpus.jsonl` dataset. It evaluates interpretable command-line features at line rate with zero API calls.
- **Layer 3 - Sequence Markov Model:** Learns the normal transition chains of processes (e.g., `explorer.exe` -> `cmd.exe`) on the specific host. It flags anomalous attack stages that violate the Markov model's expected transitions.
- **Layer 4 - LLM Adjudicator:** For detections falling in an "ambiguous" band, OSentinel queries a local `llama3.1` model (via Ollama) to serve as a tie-breaker, adjusting the final incident score based on contextual reasoning.

## 🛠️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yashmohite7324-byte/Osentinel.git
   cd Osentinel
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the Agent:**
   Edit `config.yaml` to adjust polling intervals, ML model thresholds, and LLM backends (e.g., Anthropic vs local Ollama).

4. **Run the Server:**
   ```bash
   python run.py
   ```

5. **Open the Dashboard:**
   Navigate to `http://127.0.0.1:8787` in your browser. Log in with your configured credentials (e.g., `asus f15` / `admin`).

## ⚠️ Disclaimer
This tool is built for educational and research purposes. Test thoroughly in `dry_run: true` mode before enabling autonomous termination (`--enforce`) in a production environment.
