"""
RAKSHA Live Agent -- real behavioral monitoring of the machine it runs on.

This is the "real" version of the behavioral-baseline pitch: instead of
replaying a scripted attack or scoring a static benchmark dataset, this
watches YOUR actual computer -- real running processes, real network
connections, real CPU load -- learns what's normal for a short baseline
window, then flags genuine deviations from that baseline as they happen.

Deliberately READ-ONLY. It never kills a process, blocks a connection, or
takes any action on the real system. It only observes and reports. Any
"containment" shown for live mode in the UI is informational/simulated,
never actually executed against your machine -- this is a safety choice,
not a missing feature.

Uses psutil, which works cross-platform (Windows/Mac/Linux) without
requiring admin rights for the data this uses (some fields may be
restricted without elevation on Windows, which is handled gracefully).
"""

import statistics
import threading
import time
from dataclasses import dataclass, asdict

import psutil


@dataclass
class LiveEvent:
    id: str
    timestamp: float
    kind: str  # process | connection | resource
    subject: str
    description: str
    anomaly_score: float


PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "::1")

# NAT64 translation prefix -- these addresses are how IPv6-only networks reach
# IPv4 destinations. They change constantly for completely ordinary traffic
# (any HTTPS request, any background sync) and are not a meaningful signal.
NAT64_PREFIX = "64:ff9b::"

# Common Windows background/system processes that start and stop constantly
# as part of normal OS housekeeping (updates, search indexing, telemetry,
# WMI, etc). Flagging these as "deviations" adds noise without adding
# security signal -- a real attacker's process is far more likely to be
# something that ISN'T on this very common, very boring list.
NOISY_PROCESS_NAMES = {
    "dllhost.exe", "backgroundtaskhost.exe", "rundll32.exe", "conhost.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "wmiprvse.exe",
    "microsoftedgeupdate.exe", "updater.exe", "vssvc.exe", "sihclient.exe",
    "taskhostw.exe", "smartscreen.exe", "runtimebroker.exe", "svchost.exe",
    "audiodg.exe", "ctfmon.exe", "textinputhost.exe", "widgets.exe",
    "widgetservice.exe", "gamebar.exe", "gamebarftserver.exe",
    "xboxpcappft.exe", "edgegameassist.exe", "usocoreworker.exe",
    "mpdefendercoreservice.exe", "securityhealthservice.exe",
}


def _is_private_or_local(ip: str) -> bool:
    if ip.startswith(PRIVATE_PREFIXES) or ip.startswith(NAT64_PREFIX):
        return True
    # 172.16.0.0 - 172.31.255.255
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


class LiveAgent:
    def __init__(self, baseline_seconds: int = 30, poll_interval: float = 3.0):
        self.baseline_seconds = baseline_seconds
        self.poll_interval = poll_interval

        self.running = False
        self.start_time = None
        self._thread = None
        self._lock = threading.Lock()

        self.known_process_names = set()
        self.known_remote_ips = set()
        self.cpu_baseline_samples = []
        self.events: list[LiveEvent] = []
        self.stats = {"process_count": 0, "connection_count": 0, "distinct_remote_ips": 0}
        self.permission_note = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.start_time = time.time()
        self.known_process_names = set()
        self.known_remote_ips = set()
        self.cpu_baseline_samples = []
        self.events = []
        self.permission_note = None
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._poll_once()
            except Exception as e:  # noqa: BLE001 -- keep the agent alive no matter what
                self.permission_note = f"Monitoring hit a non-fatal error: {e}"
            time.sleep(self.poll_interval)

    def _elapsed(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    def _in_baseline_phase(self) -> bool:
        return self._elapsed() < self.baseline_seconds

    def _poll_once(self):
        baselining = self._in_baseline_phase()

        # ---- Processes ----
        current_names = set()
        for p in psutil.process_iter(["name"]):
            try:
                n = p.info.get("name")
                if n:
                    current_names.add(n)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if baselining:
            self.known_process_names |= current_names
        else:
            new_names = current_names - self.known_process_names
            for name in new_names:
                if name.lower() in NOISY_PROCESS_NAMES:
                    continue
                self._emit(
                    "process", name,
                    f"New process observed that was not running during the baseline window: {name}",
                    0.55,
                )
            self.known_process_names |= new_names

        # ---- Network connections ----
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
            self.permission_note = (
                "Network connection details require elevated permissions on this OS. "
                "Process and CPU monitoring still work normally. "
                "Run as Administrator for full connection visibility."
            )

        current_ips = {
            c.raddr.ip for c in conns
            if c.raddr and c.status == psutil.CONN_ESTABLISHED
        }

        if baselining:
            self.known_remote_ips |= current_ips
        else:
            new_ips = {ip for ip in (current_ips - self.known_remote_ips) if not _is_private_or_local(ip)}
            # A single new destination is completely ordinary background
            # chatter (CDNs, cloud telemetry, update checks). A BURST of many
            # new destinations in one poll window is a much more meaningful
            # behavioral change -- closer to what real lateral movement or
            # C2 beaconing to multiple endpoints looks like -- so that's what
            # gets surfaced, instead of every individual connection.
            if len(new_ips) >= 8:
                sample = ", ".join(list(new_ips)[:3])
                self._emit(
                    "connection", f"{len(new_ips)} new destinations",
                    f"Burst of {len(new_ips)} outbound connections to IP addresses not seen "
                    f"during the baseline window (e.g. {sample}).",
                    0.6,
                )
            self.known_remote_ips |= new_ips

        # ---- CPU ----
        cpu = psutil.cpu_percent(interval=None)
        if baselining:
            self.cpu_baseline_samples.append(cpu)
        elif len(self.cpu_baseline_samples) >= 3:
            mean = statistics.mean(self.cpu_baseline_samples)
            stdev = statistics.pstdev(self.cpu_baseline_samples) or 1.0
            z = (cpu - mean) / stdev
            # Require both a statistically significant deviation AND a meaningful
            # absolute jump -- otherwise near-zero-variance baselines (e.g. an idle
            # machine sitting at 0-1% CPU) make trivial fluctuations look like huge
            # z-scores and flood the feed with noise.
            if z > 3 and (cpu - mean) > 15:
                self._emit(
                    "resource", "CPU",
                    f"CPU usage spiked to {cpu:.0f}%, {z:.1f} standard deviations above "
                    f"this machine's baseline average of {mean:.0f}%.",
                    min(0.95, 0.5 + z * 0.1),
                )

        with self._lock:
            self.stats = {
                "process_count": len(current_names),
                "connection_count": len(conns),
                "distinct_remote_ips": len(current_ips),
            }

    def _emit(self, kind: str, subject: str, description: str, score: float):
        with self._lock:
            evt = LiveEvent(
                id=f"live-{len(self.events)}",
                timestamp=time.time(),
                kind=kind,
                subject=subject,
                description=description,
                anomaly_score=round(score, 2),
            )
            self.events.append(evt)

    def state(self) -> dict:
        with self._lock:
            elapsed = self._elapsed()
            remaining = max(0.0, self.baseline_seconds - elapsed)
            return {
                "running": self.running,
                "baseline_building": self.running and remaining > 0,
                "baseline_seconds_remaining": round(remaining, 1),
                "elapsed_seconds": round(elapsed, 1),
                "known_process_count": len(self.known_process_names),
                "known_ip_count": len(self.known_remote_ips),
                "stats": dict(self.stats),
                "permission_note": self.permission_note,
                "events": [asdict(e) for e in self.events[-60:][::-1]],
            }


agent = LiveAgent()
