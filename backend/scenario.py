"""
RAKSHA scenario engine.

Simulates a realistic multi-stage attack against a mixed IT/OT critical
infrastructure environment (a water treatment utility), advancing through
stages on a wall-clock timer so a live demo plays out on its own.

This is intentionally deterministic and self-contained (no external model
calls) so it runs reliably offline during a hackathon demo. The *shape* of
the data (anomaly scores, MITRE mapping, blast radius, trust gating) is
exactly what a real behavioral-detection pipeline would produce -- this
module stands in for that pipeline so the rest of the system (API, graph,
SOAR, audit log, copilot) can be built and demoed against something real.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

STAGE_INTERVAL_SECONDS = 18  # how often the simulated attack advances


@dataclass
class GraphNode:
    id: str
    label: str
    kind: str  # user | endpoint | server | ot_asset | segment
    criticality: str  # low | medium | high | critical
    anomaly_score: float = 0.0
    status: str = "normal"  # normal | suspicious | compromised | contained


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    relation: str
    weight: float = 1.0


@dataclass
class AnomalyEvent:
    id: str
    timestamp: float
    asset_id: str
    description: str
    anomaly_score: float
    mitre_technique: str
    mitre_tactic: str


@dataclass
class Prediction:
    next_stage: str
    confidence: float
    rationale: str


@dataclass
class SoarAction:
    id: str
    timestamp: float
    action: str
    target_asset: str
    confidence: float
    blast_radius: str  # low | medium | high | critical
    business_impact: str
    auto_executed: bool
    approval_required: bool
    approved: Optional[bool] = None
    reason: str = ""


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    event_type: str
    detail: str
    prev_hash: str
    hash: str = ""


# ---------------------------------------------------------------------------
# Static topology: the assets that exist in this environment, before any
# attack activity. This is what the "asset inventory" layer would provide.
# ---------------------------------------------------------------------------

BASE_NODES = {
    "user.rkumar": GraphNode("user.rkumar", "R. Kumar (Finance)", "user", "low"),
    "ep.wks-fin-014": GraphNode("ep.wks-fin-014", "WKS-FIN-014", "endpoint", "low"),
    "srv.dc-01": GraphNode("srv.dc-01", "DC-01 (Domain Controller)", "server", "high"),
    "seg.ot-a": GraphNode("seg.ot-a", "OT-SEGMENT-A", "segment", "critical"),
    "ot.plc-water-03": GraphNode("ot.plc-water-03", "PLC-WATER-03 (Water Treatment)", "ot_asset", "critical"),
}

BASE_EDGES = {
    "e1": GraphEdge("e1", "user.rkumar", "ep.wks-fin-014", "logs into", 0.1),
    "e2": GraphEdge("e2", "ep.wks-fin-014", "srv.dc-01", "authenticates to", 0.1),
    "e3": GraphEdge("e3", "srv.dc-01", "seg.ot-a", "manages", 0.1),
    "e4": GraphEdge("e4", "seg.ot-a", "ot.plc-water-03", "controls", 0.1),
}

# ---------------------------------------------------------------------------
# The attack script. Each stage describes: the anomaly it produces, the
# MITRE mapping, the prediction shown *before* this stage would be known,
# and any SOAR action triggered once this stage fires.
# ---------------------------------------------------------------------------

STAGES = [
    {
        "name": "Phishing email opened",
        "asset": "user.rkumar",
        "description": "R. Kumar opened an email attachment with an unusual macro payload, deviating from established behavioral baseline.",
        "anomaly_score": 0.42,
        "mitre_technique": "T1566 - Phishing",
        "mitre_tactic": "Initial Access",
        "node_status": {"user.rkumar": "suspicious", "ep.wks-fin-014": "suspicious"},
        "prediction": Prediction(
            "Macro execution / scripting interpreter launch",
            0.64,
            "Phishing opens with unusual attachment types precede scripting activity in 64% of observed campaigns matching this profile.",
        ),
        "soar_action": None,
    },
    {
        "name": "Macro executes PowerShell",
        "asset": "ep.wks-fin-014",
        "description": "WKS-FIN-014 spawned an obfuscated PowerShell process from a Word process tree -- a pattern never seen on this endpoint before.",
        "anomaly_score": 0.68,
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "mitre_tactic": "Execution",
        "node_status": {"ep.wks-fin-014": "compromised"},
        "prediction": Prediction(
            "Credential dumping (LSASS access)",
            0.79,
            "Obfuscated PowerShell spawned from an Office process matches early-stage TTPs of 3 known ransomware-affiliated campaigns.",
        ),
        "soar_action": None,
    },
    {
        "name": "Credential dumping detected",
        "asset": "ep.wks-fin-014",
        "description": "Process accessed LSASS memory on WKS-FIN-014 -- signature-free behavioral match for credential dumping.",
        "anomaly_score": 0.81,
        "mitre_technique": "T1003 - OS Credential Dumping",
        "mitre_tactic": "Credential Access",
        "node_status": {"ep.wks-fin-014": "compromised"},
        "prediction": Prediction(
            "Lateral movement toward Domain Controller (DC-01)",
            0.85,
            "Credential dumping on a finance workstation is followed by lateral movement to a domain controller in 85% of correlated CERT-In advisories.",
        ),
        "soar_action": SoarAction(
            id="act-1",
            timestamp=0,
            action="Isolate endpoint",
            target_asset="ep.wks-fin-014",
            confidence=0.81,
            blast_radius="low",
            business_impact="Single finance workstation offline; no operational disruption.",
            auto_executed=True,
            approval_required=False,
            approved=True,
            reason="High confidence, low blast radius -- executed automatically per policy.",
        ),
    },
    {
        "name": "Lateral movement to Domain Controller",
        "asset": "srv.dc-01",
        "description": "Compromised credentials used to authenticate to DC-01 via SMB from a device already flagged as compromised.",
        "anomaly_score": 0.90,
        "mitre_technique": "T1021 - Remote Services",
        "mitre_tactic": "Lateral Movement",
        "node_status": {"srv.dc-01": "compromised"},
        "prediction": Prediction(
            "Pivot toward OT segment via DC-01 management access",
            0.78,
            "Domain controller compromise in utility environments precedes OT segment pivot attempts in the majority of CERT-In-tracked incidents on similarly-architected networks.",
        ),
        "soar_action": SoarAction(
            id="act-2",
            timestamp=0,
            action="Revoke domain admin credential",
            target_asset="srv.dc-01",
            confidence=0.90,
            blast_radius="high",
            business_impact="Revoking this credential may interrupt scheduled domain maintenance jobs.",
            auto_executed=False,
            approval_required=True,
            approved=None,
            reason="High blast radius on a critical asset -- held for analyst approval.",
        ),
    },
    {
        "name": "OT segment command injection attempt",
        "asset": "ot.plc-water-03",
        "description": "Unauthorized command message sent from DC-01 toward PLC-WATER-03 -- matches ICS unauthorized command injection pattern.",
        "anomaly_score": 0.97,
        "mitre_technique": "T0855 - Unauthorized Command Message",
        "mitre_tactic": "Impair Process Control (ICS)",
        "node_status": {"seg.ot-a": "suspicious", "ot.plc-water-03": "suspicious"},
        "prediction": Prediction(
            "Attempted disruption of water treatment process control",
            0.93,
            "Command injection targeting a PLC from a compromised domain controller is a near-terminal stage in ICS attack chains -- immediate containment recommended.",
        ),
        "soar_action": SoarAction(
            id="act-3",
            timestamp=0,
            action="Isolate OT segment (network-level, PLC untouched)",
            target_asset="seg.ot-a",
            confidence=0.97,
            blast_radius="critical",
            business_impact="Isolating the segment stops further commands from reaching the PLC while the water treatment process continues running on its last known-good state -- the PLC itself is never touched.",
            auto_executed=False,
            approval_required=True,
            approved=None,
            reason="Critical blast radius -- water supply infrastructure. Requires explicit human confirmation regardless of confidence.",
        ),
    },
]


def _hash_entry(prev_hash: str, payload: dict) -> str:
    blob = prev_hash + json.dumps(payload, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class ScenarioEngine:
    def __init__(self):
        self.start_time = time.time()
        self.nodes: dict[str, GraphNode] = {k: GraphNode(**asdict(v)) for k, v in BASE_NODES.items()}
        self.edges: dict[str, GraphEdge] = {k: GraphEdge(**asdict(v)) for k, v in BASE_EDGES.items()}
        self.events: list[AnomalyEvent] = []
        self.soar_actions: list[SoarAction] = []
        self.audit_log: list[AuditEntry] = []
        self.current_stage_index = -1
        self.pending_approvals: dict[str, SoarAction] = {}
        self._append_audit("system", "RAKSHA monitoring initialized. Baseline established for 5 assets.")

    def _append_audit(self, event_type: str, detail: str):
        prev_hash = self.audit_log[-1].hash if self.audit_log else "genesis"
        idx = len(self.audit_log)
        payload = {"index": idx, "event_type": event_type, "detail": detail}
        h = _hash_entry(prev_hash, payload)
        entry = AuditEntry(idx, time.time(), event_type, detail, prev_hash, h)
        self.audit_log.append(entry)

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def target_stage_index(self) -> int:
        idx = int(self.elapsed() // STAGE_INTERVAL_SECONDS)
        return min(idx, len(STAGES) - 1)

    def tick(self):
        """Advance the scenario to whatever stage the wall clock says we should be at."""
        target = self.target_stage_index()
        while self.current_stage_index < target:
            self.current_stage_index += 1
            self._fire_stage(self.current_stage_index)

    def _fire_stage(self, i: int):
        stage = STAGES[i]
        for node_id, status in stage["node_status"].items():
            if node_id in self.nodes:
                self.nodes[node_id].status = status
                self.nodes[node_id].anomaly_score = stage["anomaly_score"]

        event = AnomalyEvent(
            id=f"evt-{i}",
            timestamp=time.time(),
            asset_id=stage["asset"],
            description=stage["description"],
            anomaly_score=stage["anomaly_score"],
            mitre_technique=stage["mitre_technique"],
            mitre_tactic=stage["mitre_tactic"],
        )
        self.events.append(event)
        self._append_audit(
            "anomaly_detected",
            f"[{stage['mitre_technique']}] {stage['description']} (score {stage['anomaly_score']:.2f})",
        )

        action: Optional[SoarAction] = stage["soar_action"]
        if action:
            action.timestamp = time.time()
            self.soar_actions.append(action)
            if action.auto_executed:
                self._append_audit(
                    "soar_auto_action",
                    f"AUTO-EXECUTED: {action.action} on {action.target_asset} "
                    f"(confidence {action.confidence:.0%}, blast radius {action.blast_radius}).",
                )
                if action.target_asset in self.nodes:
                    self.nodes[action.target_asset].status = "contained"
            else:
                self.pending_approvals[action.id] = action
                self._append_audit(
                    "soar_pending_approval",
                    f"HELD FOR APPROVAL: {action.action} on {action.target_asset} "
                    f"(confidence {action.confidence:.0%}, blast radius {action.blast_radius}). {action.reason}",
                )

    def approve_action(self, action_id: str, approved: bool) -> Optional[SoarAction]:
        action = self.pending_approvals.pop(action_id, None)
        if not action:
            return None
        action.approved = approved
        if approved and action.target_asset in self.nodes:
            self.nodes[action.target_asset].status = "contained"
        self._append_audit(
            "human_decision",
            f"Analyst {'APPROVED' if approved else 'REJECTED'}: {action.action} on {action.target_asset}.",
        )
        return action

    def current_prediction(self) -> Optional[Prediction]:
        if self.current_stage_index < 0:
            return None
        return STAGES[self.current_stage_index]["prediction"]

    def cyber_health_score(self) -> int:
        if not self.events:
            return 98
        max_score = max(e.anomaly_score for e in self.events)
        return max(5, round(100 - max_score * 90))

    # -----------------------------------------------------------------
    # Executive / resilience metrics -- these summarize the same
    # underlying event/action data for a non-analyst audience (CISO,
    # judges) rather than introducing any new simulated inputs.
    # -----------------------------------------------------------------

    def time_to_detection_seconds(self) -> Optional[float]:
        if not self.events:
            return None
        return round(self.events[0].timestamp - self.start_time, 1)

    def containment_stats(self) -> dict:
        total = len(self.soar_actions)
        contained = len([a for a in self.soar_actions if a.auto_executed or a.approved])
        pct = round((contained / total) * 100) if total else 100
        return {
            "total_actions": total,
            "contained": contained,
            "pending": len(self.pending_approvals),
            "containment_success_pct": pct,
        }

    def systems_protected_pct(self) -> int:
        total = len(self.nodes)
        compromised = len([n for n in self.nodes.values() if n.status == "compromised"])
        if total == 0:
            return 100
        return round(((total - compromised) / total) * 100)

    def executive_summary(self) -> dict:
        critical_assets = [n for n in self.nodes.values() if n.criticality in ("high", "critical")]
        return {
            "current_risk_pct": max(0, 100 - self.cyber_health_score()),
            "critical_assets_total": len(critical_assets),
            "critical_assets_at_risk": len([n for n in critical_assets if n.status in ("suspicious", "compromised")]),
            "attack_stage": self.current_stage_index + 1,
            "attack_total_stages": len(STAGES),
            "time_to_detection_seconds": self.time_to_detection_seconds(),
            "systems_protected_pct": self.systems_protected_pct(),
            "containment": self.containment_stats(),
        }

    def mitre_coverage(self) -> list:
        """Aggregate observed events by MITRE tactic, in kill-chain order,
        for the ATT&CK visualizer. Tactics with no events still appear
        (at zero) so the bar chart reads as a full spectrum, not just the
        stages that happened to fire."""
        order = [
            "Initial Access",
            "Execution",
            "Credential Access",
            "Lateral Movement",
            "Impair Process Control (ICS)",
        ]
        by_tactic: dict = {t: [] for t in order}
        for e in self.events:
            by_tactic.setdefault(e.mitre_tactic, []).append(e)

        out = []
        for tactic in by_tactic:
            evts = by_tactic[tactic]
            latest = evts[-1] if evts else None
            out.append({
                "tactic": tactic,
                "count": len(evts),
                "max_score": max((e.anomaly_score for e in evts), default=0.0),
                "latest_technique": latest.mitre_technique if latest else None,
                "latest_description": latest.description if latest else None,
                "latest_score": latest.anomaly_score if latest else None,
            })
        return out

    def resilience_score(self) -> dict:
        """A resilience posture score, distinct from the incident-specific
        cyber_health_score. Baseline environment-hardening metrics are
        static configuration facts (patch levels, backup health, zero
        trust maturity) that don't change during an incident; the two
        metrics that DO move are attack resistance (derived from how much
        of the environment is currently under active attack) and critical
        asset protection (derived from real node state)."""
        attack_resistance = self.cyber_health_score()
        critical_protected = self.systems_protected_pct()

        baseline = {
            "recovery_readiness": 92,
            "backup_health": 100,
            "patch_compliance": 74,
            "zero_trust_maturity": 68,
        }

        components = {
            "recovery_readiness": baseline["recovery_readiness"],
            "attack_resistance": attack_resistance,
            "backup_health": baseline["backup_health"],
            "patch_compliance": baseline["patch_compliance"],
            "critical_assets_protected": critical_protected,
            "zero_trust_maturity": baseline["zero_trust_maturity"],
        }
        overall = round(sum(components.values()) / len(components))

        recommendations = [
            "Patch the domain controller -- lateral movement in this incident relied on an unpatched SMB path.",
            "Enable MFA for all domain admin accounts to reduce credential-dumping impact.",
            "Disable SMBv1 across the finance VLAN.",
            "Rotate stale service-account credentials on DC-01.",
        ]
        if self.nodes.get("ot.plc-water-03") and self.nodes["ot.plc-water-03"].status != "normal":
            recommendations.insert(0, "Review OT segment firewall rules so DC-to-PLC command traffic is denied by default, not just on detection.")
        if not self.events:
            recommendations = [
                "Maintain current patch cadence for domain controllers and OT gateways.",
                "Continue quarterly backup-restore verification drills.",
                "Expand zero-trust segmentation to the OT network boundary.",
            ]

        return {
            "overall": overall,
            "components": components,
            "recommendations": recommendations[:5],
        }

    def state(self) -> dict:
        self.tick()
        return {
            "elapsed_seconds": round(self.elapsed(), 1),
            "current_stage": self.current_stage_index,
            "total_stages": len(STAGES),
            "stage_name": STAGES[self.current_stage_index]["name"] if self.current_stage_index >= 0 else "Monitoring -- no active incident",
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges.values()],
            "events": [asdict(e) for e in self.events],
            "prediction": asdict(self.current_prediction()) if self.current_prediction() else None,
            "soar_actions": [asdict(a) for a in self.soar_actions],
            "pending_approvals": [asdict(a) for a in self.pending_approvals.values()],
            "audit_log": [asdict(a) for a in self.audit_log],
            "cyber_health_score": self.cyber_health_score(),
            "executive_summary": self.executive_summary(),
            "mitre_coverage": self.mitre_coverage(),
            "resilience": self.resilience_score(),
        }

    def reset(self):
        self.__init__()


engine = ScenarioEngine()
