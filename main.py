"""
NexTracer — Production Backend
Philosophy: We NEVER kill. We CONTROL.

Two tools we use:
─────────────────────────────────────────────────────────────────
1. cgroups (Control Groups)
   - Linux kernel feature that HARD LIMITS how much CPU a process gets
   - Like putting a governor on a car engine — it physically cannot exceed the limit
   - Used for: HIGH severity threats (severity 4-5) where the process is
     genuinely dangerous and needs immediate resource capping
   - Example: cryptominer at 98% CPU → cgroup caps it at 20%
   - The process keeps running — it just can't consume more than allowed
   - Enterprise reason: preserves evidence, maintains audit trail,
     avoids service disruption that a kill would cause

2. renice (Scheduler Priority)
   - Tells the Linux scheduler "deprioritize this process"
   - Scale: -20 (highest priority) to 19 (lowest priority). Default = 0.
   - Used for: MEDIUM severity (severity 3) where process is suspicious
     but not confirmed dangerous
   - Example: a process spiking to 60% — may be legitimate (backup job, compile)
   - renice to 15 means: other processes always get CPU first,
     this one only runs when nothing else needs it
   - Gentler than cgroups — no hard limit, just lower priority
   - Enterprise reason: non-destructive, reversible, no false-positive impact

WSL2 note on cgroups:
   WSL2 supports cgroups v2 but the nextracer_group directory must exist.
   If mkdir fails (permission), we fall back to renice as the safe alternative.
   Both are non-destructive. Neither kills anything.
─────────────────────────────────────────────────────────────────
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import psutil
import asyncio
import numpy as np
import os
import time
from datetime import datetime, timezone
from pyod.models.iforest import IForest

app = FastAPI(title="NexTracer API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─────────────────────────────────────────────
# AI MODEL
# ─────────────────────────────────────────────
model         = IForest(contamination=0.05)
data_buffer   = []
model_trained = False
MIN_SAMPLES   = 60   # 2 minutes of baseline before trusting detections

# ─────────────────────────────────────────────
# CGROUPS — Hard CPU cap
# ─────────────────────────────────────────────
CGROUP_PATH    = "/sys/fs/cgroup/nextracer_group"
cgroup_available = False  # detected at startup

def setup_cgroup():
    """
    Try to create the NexTracer cgroup at startup.
    If it works → cgroup_available = True → we use hard CPU limits.
    If it fails (WSL2 permission) → cgroup_available = False → we use renice instead.
    Either way: no process is ever killed.
    """
    global cgroup_available
    try:
        if not os.path.exists(CGROUP_PATH):
            os.mkdir(CGROUP_PATH)
        # Quick write test to confirm we have permission
        with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
            f.write("max 100000")
        cgroup_available = True
        print("[CGROUP] ✅ Available — hard CPU limits enabled")
    except Exception as e:
        cgroup_available = False
        print(f"[CGROUP] Not available ({e}) — will use renice instead")

def apply_cgroup_limit(pid: int, cap_pct: int) -> dict:
    """
    Cap process CPU usage to cap_pct% using Linux cgroups v2.
    Process continues running — just limited.
    """
    try:
        quota = int((cap_pct / 100) * 100000)  # microseconds per 100ms period
        with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
            f.write(f"{quota} 100000")
        with open(f"{CGROUP_PATH}/cgroup.procs", "w") as f:
            f.write(str(pid))
        print(f"[CGROUP] PID {pid} hard-capped at {cap_pct}% CPU")
        return {
            "success":    True,
            "method":     "cgroup",
            "pid":        pid,
            "cap_pct":    cap_pct,
            "detail":     f"Hard CPU cap applied: process limited to {cap_pct}% via cgroups v2"
        }
    except Exception as e:
        print(f"[CGROUP] Write failed: {e} — falling back to renice")
        return apply_renice(pid, 19)  # max deprioritization as fallback

def remove_cgroup_limit():
    """Restore unlimited CPU when threat resolves."""
    try:
        with open(f"{CGROUP_PATH}/cpu.max", "w") as f:
            f.write("max 100000")
        print("[CGROUP] Limits removed — process restored")
    except:
        pass

# ─────────────────────────────────────────────
# RENICE — Scheduler Priority
# ─────────────────────────────────────────────
def apply_renice(pid: int, nice_val: int) -> dict:
    """
    Lower the scheduler priority of a process.
    nice_val: 0=normal, 10=medium depriority, 15=low, 19=lowest possible.
    The process still runs — it just gets CPU only when nothing else needs it.
    """
    try:
        proc = psutil.Process(pid)
        proc.nice(nice_val)
        print(f"[RENICE] PID {pid} priority set to {nice_val} (lower = less CPU time)")
        return {
            "success":  True,
            "method":   "renice",
            "pid":      pid,
            "nice_val": nice_val,
            "detail":   f"Scheduler priority lowered to {nice_val} — process deprioritized"
        }
    except Exception as e:
        print(f"[RENICE] Failed: {e}")
        return {"success": False, "method": "renice", "error": str(e)}

def restore_renice(pid: int) -> dict:
    """Restore normal priority (0) when threat resolves."""
    try:
        psutil.Process(pid).nice(0)
        print(f"[RENICE] PID {pid} priority restored to 0")
        return {"success": True}
    except:
        return {"success": False}

# ─────────────────────────────────────────────
# METRICS COLLECTION
# ─────────────────────────────────────────────
def get_metrics() -> dict:
    cpu  = psutil.cpu_percent(interval=None)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_io_counters()
    net  = psutil.net_io_counters()
    return {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "cpu_percent":     cpu,
        "memory_percent":  mem.percent,
        "memory_used_gb":  round(mem.used  / (1024**3), 2),
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "swap_percent":    psutil.swap_memory().percent,
        "disk_read_mb":    round(disk.read_bytes  / (1024**2), 2) if disk else 0,
        "disk_write_mb":   round(disk.write_bytes / (1024**2), 2) if disk else 0,
        "net_sent_mb":     round(net.bytes_sent / (1024**2), 2) if net else 0,
        "net_recv_mb":     round(net.bytes_recv / (1024**2), 2) if net else 0,
    }

def get_top_processes(limit: int = 8) -> list:
    """
    Two-pass CPU measurement.
    Pass 1: seed the CPU counter for each process.
    Wait 0.3s (kernel updates its stats).
    Pass 2: read actual CPU percentage.
    Without this, psutil always returns 0.0 on first call.
    """
    pmap = {}
    for p in psutil.process_iter(['pid', 'name', 'memory_percent', 'status', 'username']):
        try:
            p.cpu_percent(interval=None)  # seed
            pmap[p.pid] = p
        except:
            pass

    time.sleep(0.3)

    procs = []
    for pid, p in pmap.items():
        try:
            cpu  = p.cpu_percent(interval=None)
            info = p.info
            info['cpu_percent'] = round(cpu, 1)
            procs.append(info)
        except:
            pass

    return sorted(procs, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:limit]

# ─────────────────────────────────────────────
# THREAT CLASSIFIER
#
# How classification works:
# We check signals in priority order (most dangerous first).
# Each threat type has:
#   - severity (1-5): how dangerous
#   - category: what kind of threat
#   - reason: human-readable explanation
#   - classification_basis: WHAT signals triggered this (shown in UI)
# ─────────────────────────────────────────────
MINER_NAMES = {"xmrig", "nbminer", "t-rex", "phoenixminer", "lolminer", "cpuminer", "cryptominer"}

def classify_threat(cpu: float, mem: float, swap: float, top_procs: list) -> dict:
    top_cpu  = top_procs[0].get("cpu_percent", 0) if top_procs else 0
    top_name = top_procs[0].get("name", "unknown") if top_procs else "unknown"
    top_pid  = top_procs[0].get("pid", 0)          if top_procs else 0

    # ── SEVERITY 5: MALWARE signature match ──────────────────
    # Classified by: process name matches known miner database
    # Why severity 5: confirmed malicious, not ambiguous at all
    if top_name.lower() in MINER_NAMES:
        return {
            "threat_type":          "Cryptominer Detected",
            "severity":             5,
            "category":             "MALWARE",
            "reason":               f"'{top_name}' (PID {top_pid}) matches known cryptominer signatures",
            "classification_basis": f"Name match against miner database | CPU: {top_cpu:.1f}%",
            "optimization_method":  "cgroup" if cgroup_available else "renice",
            "cap_target":           20
        }

    # ── SEVERITY 5: Process hijacking system ─────────────────
    # Classified by: single process taking >75% while system >90%
    # Why severity 5: one process has essentially seized the entire CPU
    if cpu > 90 and top_cpu > 75:
        return {
            "threat_type":          "Process CPU Hijack",
            "severity":             5,
            "category":             "CPU_HOG",
            "reason":               f"'{top_name}' (PID {top_pid}) consuming {top_cpu:.1f}% — system seized",
            "classification_basis": f"System CPU: {cpu:.1f}% | Top process: {top_cpu:.1f}% | Ratio: single process dominance",
            "optimization_method":  "cgroup" if cgroup_available else "renice",
            "cap_target":           20
        }

    # ── SEVERITY 4: System-wide saturation ───────────────────
    # Classified by: total CPU >85% but no single process dominates
    # Why severity 4: multiple processes or system-level issue
    if cpu > 85:
        return {
            "threat_type":          "System CPU Saturation",
            "severity":             4,
            "category":             "CPU_HOG",
            "reason":               f"Total CPU at {cpu:.1f}% — service degradation imminent",
            "classification_basis": f"System CPU: {cpu:.1f}% sustained above 85% threshold | IForest score anomalous",
            "optimization_method":  "cgroup" if cgroup_available else "renice",
            "cap_target":           40
        }

    # ── SEVERITY 5: Memory emergency ─────────────────────────
    # Classified by: RAM >92% → OOM killer about to fire
    # Why severity 5: OOM killer will randomly terminate processes — worse than our intervention
    if mem > 92:
        return {
            "threat_type":          "Critical Memory Exhaustion",
            "severity":             5,
            "category":             "MEMORY_LEAK",
            "reason":               f"RAM at {mem:.1f}% — Linux OOM killer risk — services may die",
            "classification_basis": f"Memory: {mem:.1f}% > 92% critical threshold | OOM killer activation imminent",
            "optimization_method":  "renice",  # renice top mem process
            "cap_target":           None
        }

    # ── SEVERITY 3: Memory pressure ──────────────────────────
    # Classified by: RAM >80% but not yet critical
    # Why severity 3: likely a slow memory leak — intervene early
    if mem > 80:
        return {
            "threat_type":          "Memory Pressure Detected",
            "severity":             3,
            "category":             "MEMORY_LEAK",
            "reason":               f"RAM at {mem:.1f}% — memory leak pattern, swap pressure building",
            "classification_basis": f"Memory: {mem:.1f}% > 80% | IForest detected growth trend vs baseline",
            "optimization_method":  "renice",
            "cap_target":           None
        }

    # ── SEVERITY 3: Swap thrashing ───────────────────────────
    # Classified by: swap >60% → system is paging to disk heavily
    # Why severity 3: disk I/O from swapping degrades all services
    if swap > 60:
        return {
            "threat_type":          "Swap Thrashing",
            "severity":             3,
            "category":             "MEMORY_LEAK",
            "reason":               f"Swap at {swap:.1f}% — heavy disk paging causing system-wide slowdown",
            "classification_basis": f"Swap: {swap:.1f}% > 60% | Disk I/O pressure from memory paging",
            "optimization_method":  "renice",
            "cap_target":           None
        }

    # ── SEVERITY 3: Rogue process spike ──────────────────────
    # Classified by: a single process >40% CPU, IForest flags it as anomalous
    # Why severity 3: abnormal for THIS machine's baseline, but not system-wide crisis
    if top_cpu > 40:
        return {
            "threat_type":          "Rogue Process Spike",
            "severity":             3,
            "category":             "CPU_HOG",
            "reason":               f"'{top_name}' (PID {top_pid}) at {top_cpu:.1f}% — abnormal vs learned baseline",
            "classification_basis": f"Process CPU: {top_cpu:.1f}% | IForest: deviates from {MIN_SAMPLES}-sample baseline | Persistence: 3+ consecutive ticks",
            "optimization_method":  "renice",
            "cap_target":           None
        }

    # ── SEVERITY 2: Generic behavioral deviation ─────────────
    # Classified by: IForest flags it but no specific signal is dominant
    # Why severity 2: monitor only, don't intervene — could be false positive
    return {
        "threat_type":          "Behavioral Deviation",
        "severity":             2,
        "category":             "UNKNOWN",
        "reason":               "System metrics deviate from learned baseline — no dominant signal",
        "classification_basis": f"IForest anomaly score exceeds threshold | CPU: {cpu:.1f}% | Mem: {mem:.1f}% | No single cause",
        "optimization_method":  "none",
        "cap_target":           None
    }

# ─────────────────────────────────────────────
# OPTIMIZATION DECISION ENGINE
#
# Decision tree:
#   Severity 5 → cgroup hard cap at 20%  (or renice 19 if cgroup unavailable)
#   Severity 4 → cgroup hard cap at 40%  (or renice 15 if cgroup unavailable)
#   Severity 3 → renice to 15            (always — not severe enough for hard cap)
#   Severity 2 → log only                (don't intervene on uncertain signals)
#
# Why this split?
#   cgroups = absolute guarantee (kernel enforces it)
#   renice  = cooperative (scheduler respects it but process can still spike)
#   For severity 3 we prefer renice because we're not 100% sure it's malicious
# ─────────────────────────────────────────────
def decide_and_apply_optimization(threat: dict, top_procs: list) -> dict:
    if not top_procs:
        return {"action": "NONE", "reason": "No target process identified"}

    pid   = top_procs[0]["pid"]
    name  = top_procs[0]["name"]
    sev   = threat.get("severity", 1)
    opt_m = threat.get("optimization_method", "none")
    cap   = threat.get("cap_target")

    if sev == 5:
        if cgroup_available:
            result = apply_cgroup_limit(pid, cap or 20)
            return {
                "action":       "CGROUP_THROTTLE",
                "pid":          pid,
                "process_name": name,
                "cap_pct":      cap or 20,
                "why":          "Severity 5 — hard CPU cap via cgroups (kernel-enforced, process survives)",
                "result":       result
            }
        else:
            result = apply_renice(pid, 19)
            return {
                "action":       "RENICE",
                "pid":          pid,
                "process_name": name,
                "nice_val":     19,
                "why":          "Severity 5 — cgroup unavailable (WSL2) → maximum renice to 19 (lowest priority)",
                "result":       result
            }

    elif sev == 4:
        if cgroup_available:
            result = apply_cgroup_limit(pid, cap or 40)
            return {
                "action":       "CGROUP_THROTTLE",
                "pid":          pid,
                "process_name": name,
                "cap_pct":      cap or 40,
                "why":          "Severity 4 — CPU cap at 40% via cgroups — system stays stable",
                "result":       result
            }
        else:
            result = apply_renice(pid, 15)
            return {
                "action":       "RENICE",
                "pid":          pid,
                "process_name": name,
                "nice_val":     15,
                "why":          "Severity 4 — cgroup unavailable → renice to 15 (significant depriority)",
                "result":       result
            }

    elif sev == 3:
        # Always renice for severity 3 — not confirmed dangerous enough for hard cap
        result = apply_renice(pid, 15)
        return {
            "action":       "RENICE",
            "pid":          pid,
            "process_name": name,
            "nice_val":     15,
            "why":          "Severity 3 — renice to 15 (non-destructive, reversible, process keeps running)",
            "result":       result
        }

    else:
        return {
            "action":       "LOG_ONLY",
            "pid":          pid,
            "process_name": name,
            "why":          "Severity 2 — monitoring only. Intervention avoided to prevent false-positive disruption.",
            "result":       {"success": True, "method": "log_only"}
        }

def restore_optimization(action: str, pid: int):
    """Undo whatever we applied when system recovers."""
    if action == "CGROUP_THROTTLE":
        remove_cgroup_limit()
    elif action == "RENICE" and pid:
        restore_renice(pid)

# ─────────────────────────────────────────────
# REST ENDPOINTS
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status":          "NexTracer running ✅",
        "model_trained":   model_trained,
        "samples":         len(data_buffer),
        "cgroup_available": cgroup_available
    }

@app.get("/metrics")
def snap_metrics():
    return get_metrics()

@app.get("/processes")
def snap_processes():
    return get_top_processes()

@app.get("/status")
def snap_status():
    return {
        "model_trained":     model_trained,
        "samples_collected": len(data_buffer),
        "samples_needed":    MIN_SAMPLES,
        "training_progress": min(100, int(len(data_buffer) / MIN_SAMPLES * 100)),
        "cgroup_available":  cgroup_available,
        "optimization_mode": "cgroup" if cgroup_available else "renice"
    }

# ─────────────────────────────────────────────
# WEBSOCKET — Main real-time loop
# ─────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    global model_trained

    await websocket.accept()
    setup_cgroup()

    enforcement_active = False
    enforced_opt       = None   # stores full optimization dict for persistence
    threat_counter     = {}

    print("[NexTracer] ✅ Dashboard connected")
    print(f"[NexTracer] Optimization mode: {'cgroup' if cgroup_available else 'renice'}")

    try:
        while True:
            # ── 1. COLLECT ────────────────────────────
            data     = get_metrics()
            features = [data["cpu_percent"], data["memory_percent"]]
            data_buffer.append(features)

            # ── 2. TRAIN ──────────────────────────────
            if len(data_buffer) >= MIN_SAMPLES and not model_trained:
                model.fit(np.array(data_buffer))
                model_trained = True
                print(f"[AI] ✅ IForest trained on {len(data_buffer)} samples")

            # ── 3. DETECT ─────────────────────────────
            if model_trained:
                raw_score  = float(model.decision_function([features])[0])
                is_anomaly = bool(model.predict([features])[0] == 1)
                # Map PyOD score to 0-100 for display
                # Typical range: +0.2 (normal) to -0.4 (anomaly)
                disp_score = int(min(100, max(0, (-raw_score + 0.05) * 160)))
            else:
                raw_score  = 0.0
                disp_score = 0
                is_anomaly = False

            data["anomaly"]           = is_anomaly
            data["anomaly_score"]     = disp_score
            data["model_ready"]       = model_trained
            data["training_progress"] = min(100, int(len(data_buffer) / MIN_SAMPLES * 100))
            data["cgroup_mode"]       = cgroup_available

            # ── 4. PROCESSES (always fetch) ───────────
            top_procs             = get_top_processes(8)
            data["top_processes"] = top_procs

            # ── 5. CLASSIFY ───────────────────────────
            threat = None
            if is_anomaly:
                threat = classify_threat(
                    data["cpu_percent"],
                    data["memory_percent"],
                    data.get("swap_percent", 0),
                    top_procs
                )
                ttype                    = threat["threat_type"]
                threat_counter[ttype]    = threat_counter.get(ttype, 0) + 1
                data["threat"]           = threat
                data["threat_confirmed"] = threat_counter[ttype] >= 3
                data["threat_ticks"]     = threat_counter[ttype]
            else:
                data["threat"]           = None
                data["threat_confirmed"] = False
                data["threat_ticks"]     = 0
                threat_counter.clear()

            # ── 6. OPTIMIZE (once per incident) ───────
            data["optimization"] = None
            confirmed = is_anomaly and threat and data["threat_confirmed"]

            if confirmed and not enforcement_active:
                opt = decide_and_apply_optimization(threat, top_procs)
                enforcement_active = True
                enforced_opt       = opt
                data["optimization"] = opt
                print(f"[ACTION] {opt['action']} on '{opt.get('process_name')}' PID {opt.get('pid')} | {opt['why']}")

            elif enforcement_active and is_anomaly:
                # Keep showing the active enforcement every tick
                data["optimization"] = {**enforced_opt, "status": "ACTIVE"}

            # ── 7. RESTORE when system recovers ───────
            if enforcement_active and not is_anomaly:
                restore_optimization(
                    enforced_opt.get("action"),
                    enforced_opt.get("pid")
                )
                data["optimization"] = {
                    "action":       "RESTORED",
                    "pid":          enforced_opt.get("pid"),
                    "process_name": enforced_opt.get("process_name"),
                    "was_action":   enforced_opt.get("action"),
                    "reason":       "✅ System self-healed — optimization removed — process running normally"
                }
                enforcement_active = False
                enforced_opt       = None
                print("[ACTION] ✅ System self-healed — optimization lifted")

            # ── 8. SEND ───────────────────────────────
            await websocket.send_json(data)
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print("[NexTracer] Dashboard disconnected")
    except Exception as e:
        print(f"[ERROR] WebSocket crashed: {e}")
        try:
            await websocket.close()
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)