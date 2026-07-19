"""
AI Cyber Copilot and incident report generator.

Answers analyst questions and produces compliance-ready incident reports by
reasoning directly over the live scenario state (graph, events, audit log)
-- the same data an analyst sees on the dashboard, just summarized in
natural language. Deterministic template-based NLG so it runs offline
without any external API dependency during the demo.
"""

import time
from scenario import ScenarioEngine


def answer_query(engine: ScenarioEngine, query: str) -> str:
    q = query.lower().strip()
    state_events = engine.events
    actions = engine.soar_actions

    if not state_events:
        return "No anomalies detected yet. All monitored assets are within normal behavioral baselines."

    if "why" in q and ("isolat" in q or "contain" in q or "block" in q):
        auto_actions = [a for a in actions if a.auto_executed]
        if auto_actions:
            a = auto_actions[-1]
            return (
                f"{a.target_asset} was isolated automatically because the confidence score reached "
                f"{a.confidence:.0%} with a '{a.blast_radius}' blast radius -- {a.reason.lower()} "
                f"The triggering event was: {state_events[min(len(state_events)-1, 2)].description}"
            )
        return "No automatic isolation has occurred yet. Any containment action is currently pending analyst approval."

    if "ot" in q or "plc" in q or "water" in q or "scada" in q:
        ot_events = [e for e in state_events if "plc" in e.asset_id or "ot." in e.asset_id or "seg." in e.asset_id]
        if ot_events:
            e = ot_events[-1]
            return (
                f"OT activity detected: {e.description} Mapped to {e.mitre_technique} "
                f"({e.mitre_tactic}). Anomaly score {e.anomaly_score:.2f}. "
                f"No direct action has been taken against the PLC itself -- containment is scoped to network isolation only."
            )
        return "No suspicious OT/ICS activity detected so far. All PLC and SCADA telemetry remains within baseline."

    if "next" in q or "predict" in q:
        pred = engine.current_prediction()
        if pred:
            return f"Predicted next stage: {pred.next_stage} (confidence {pred.confidence:.0%}). {pred.rationale}"
        return "No active incident to predict against."

    if "pending" in q or "approval" in q or "waiting" in q:
        if engine.pending_approvals:
            lines = [
                f"- {a.action} on {a.target_asset} (confidence {a.confidence:.0%}, blast radius {a.blast_radius})"
                for a in engine.pending_approvals.values()
            ]
            return "Actions awaiting analyst approval:\n" + "\n".join(lines)
        return "No actions are currently awaiting approval."

    if "score" in q or "health" in q or "risk" in q:
        return f"Current Cyber Health Score: {engine.cyber_health_score()}/100, based on the highest anomaly score observed so far ({max(e.anomaly_score for e in state_events):.2f})."

    if "today" in q or "all" in q or "summary" in q or "what happened" in q:
        lines = [f"- [{e.mitre_technique}] {e.description}" for e in state_events]
        return "Incident summary so far:\n" + "\n".join(lines)

    # default fallback: describe the latest event
    e = state_events[-1]
    return (
        f"Most recent finding: {e.description} Mapped to {e.mitre_technique} ({e.mitre_tactic}), "
        f"anomaly score {e.anomaly_score:.2f}. Ask about pending approvals, OT activity, "
        f"the predicted next stage, or the current risk score for more detail."
    )


def generate_incident_report(engine: ScenarioEngine) -> dict:
    if not engine.events:
        return {
            "generated_at": time.time(),
            "title": "No active incident",
            "summary": "No anomalies have been detected. No report to generate.",
            "timeline": [],
            "actions_taken": [],
            "recommendations": [],
        }

    timeline = [
        {
            "time": e.timestamp,
            "description": e.description,
            "mitre_technique": e.mitre_technique,
            "mitre_tactic": e.mitre_tactic,
            "anomaly_score": e.anomaly_score,
        }
        for e in engine.events
    ]

    actions_taken = [
        {
            "action": a.action,
            "target": a.target_asset,
            "confidence": a.confidence,
            "blast_radius": a.blast_radius,
            "auto_executed": a.auto_executed,
            "approved": a.approved,
        }
        for a in engine.soar_actions
    ]

    max_tactic = engine.events[-1].mitre_tactic
    recommendations = [
        "Rotate credentials for all accounts active on the affected finance workstation.",
        "Review domain controller access logs for the preceding 30 days for related lateral movement.",
        "Validate OT segment firewall rules restrict DC-to-PLC command traffic by default, not just on detection.",
        "Schedule a tabletop exercise replaying this incident using the Cyber Resilience Digital Twin.",
    ]

    return {
        "generated_at": time.time(),
        "title": f"Incident Report -- {engine.events[0].mitre_tactic} through {max_tactic}",
        "summary": (
            f"A {len(timeline)}-stage intrusion was detected beginning with {engine.events[0].description.lower()} "
            f"The attack progressed from {engine.events[0].mitre_tactic} to {max_tactic}, reaching a peak "
            f"anomaly score of {max(e.anomaly_score for e in engine.events):.2f}. "
            f"{len([a for a in engine.soar_actions if a.auto_executed])} containment action(s) were executed "
            f"automatically; {len([a for a in engine.soar_actions if not a.auto_executed])} were held for analyst approval "
            f"due to elevated blast radius."
        ),
        "timeline": timeline,
        "actions_taken": actions_taken,
        "recommendations": recommendations,
        "cyber_health_score": engine.cyber_health_score(),
    }
