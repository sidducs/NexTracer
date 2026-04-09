# NexTracer 🛡️

**NexTracer** is an autonomous system intelligence and resource control platform. It uses AI-driven anomaly detection to identify rogue processes (including cryptominers and CPU hijacks) and mitigates them in real-time using non-destructive kernel-level controls.

---

## 🚀 Key Value Proposition

**"We Control, We Don't Kill."**  
Traditionally, system security tools terminate suspicious processes. NexTracer takes a more sophisticated approach by using Linux **cgroups** and **renice** to throttle resource-heavy processes. This preserves the process state for forensic analysis and avoids service disruption while maintaining system stability.

## 🧠 Core Features

-   **Autonomous Baseline Learning**: Uses a 60-sample learning window to establish a "normal" behavioral profile specific to the machine.
-   **Isolation Forest Anomaly Detection**: Leverages the `PyOD` library to detect statistical outliers in CPU and Memory usage patterns.
-   **Intelligent Threat Classification**: Automatically identifies and categorizes threats (Cryptominers, Memory Leaks, CPU Hijacks, etc.) based on multi-signal analysis.
-   **Non-Destructive Mitigation**: 
    -   **cgroups v2**: Implements hard CPU capping at the kernel level.
    -   **renice**: Dynamic priority adjustment for non-destructive deprioritization.
-   **Cyberpunk Dashboard**: A high-performance, real-time telemetry dashboard built with vanilla JavaScript and WebSockets.

## 🏗️ Technical Architecture

### Backend: FastAPI & AI
The backend acts as the central intelligence hub. It collects telemetry via `psutil`, feeds it into the Isolation Forest model, and orchestrates mitigation actions.
- **WebSocket Protocol**: Ensures zero-latency data streaming to the frontend.
- **Classification Engine**: A rule-based system that works alongside the AI to confirm and categorize anomalies.

### Frontend: Reactive Telemetry
The dashboard provides total visibility into the system's "thought process."
- **Live Charts**: Real-time visualization of CPU/Memory trends.
- **Control Panel**: Shows active interventions and their reasoning.
- **Event Log**: A detailed history of system events and healed anomalies.

## 🛠️ Quick Start

### Prerequisites
- Python 3.9+
- Linux (Ubuntu/Debian recommended for cgroup support)
- Root/Sudo permissions (required for process control features)

### Installation
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/NexTracer.git
    cd NexTracer
    ```
2.  **Create a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the application**:
    ```bash
    sudo python main.py
    ```
5.  **Open the dashboard**:
    Simply open `test.html` in your web browser.

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.

---

> [!NOTE]
> *This project was developed for advanced system monitoring scenarios where process survival and forensic evidence are prioritized over simple termination.*
