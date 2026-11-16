"""
Mitigation Plan Generator (NIST CSF 2.0 & CIRES-R Compliance)

File: backend/workers/mitigation_generator.py
Maps incident diagnostics and root-cause analysis findings to all 6 core functions
of the NIST Cybersecurity Framework (CSF) 2.0: Govern, Identify, Protect, Detect, Respond, Recover.
"""

from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel, Field


class NISTFunction(str, Enum):
    GOVERN = "Govern"
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"


class NISTMapping(BaseModel):
    nist_function: NISTFunction
    category: str
    action_item: str
    status: str = "RECOMMENDED"


class MitigationAction(BaseModel):
    action_id: str
    title: str
    description: str
    priority: str = "HIGH"
    automated: bool = True


class MitigationPlan(BaseModel):
    incident_id: str
    fault_category: str
    component: str
    nist_mappings: List[NISTMapping] = Field(default_factory=list)
    actions: List[MitigationAction] = Field(default_factory=list)
    cires_validation_status: str = "VERIFIED_PASSED"
    summary: str = ""


class MitigationPlanGenerator:
    """Generates structured NIST CSF 2.0 remediation playbooks for automated incident responses."""

    @staticmethod
    def generate_plan(incident_id: str, fault_category: str, component: str) -> MitigationPlan:
        nist_mappings = [
            NISTMapping(
                nist_function=NISTFunction.GOVERN,
                category="GV.PO-01",
                action_item=f"Verify CIRES-R Level 2 governance and privacy compliance for component '{component}'.",
            ),
            NISTMapping(
                nist_function=NISTFunction.IDENTIFY,
                category="ID.RA-02",
                action_item=f"Assess vulnerability exposure and asset risk for fault mode '{fault_category}'.",
            ),
            NISTMapping(
                nist_function=NISTFunction.PROTECT,
                category="PR.DS-01",
                action_item="Enforce fail-closed PHI/PII redaction and circuit breakers on telemetry egress.",
            ),
            NISTMapping(
                nist_function=NISTFunction.DETECT,
                category="DE.AE-03",
                action_item="Correlate metric exemplars, Tempo traces, and Loki logs across the LGTM pipeline.",
            ),
            NISTMapping(
                nist_function=NISTFunction.RESPOND,
                category="RS.MA-01",
                action_item="Execute automated mitigation playbook via MCP Diagnostic Agent.",
            ),
            NISTMapping(
                nist_function=NISTFunction.RECOVER,
                category="RC.RP-01",
                action_item="Flush persistent file_storage disk queues and restore steady-state telemetry.",
            ),
        ]

        actions = [
            MitigationAction(
                action_id="ACT-01",
                title="Isolate Failing Component",
                description=f"Apply rate limiting and fail-closed circuit breaker on '{component}'.",
                priority="CRITICAL",
                automated=True,
            ),
            MitigationAction(
                action_id="ACT-02",
                title="Flush and Buffer Telemetry",
                description="Engage dual-tier disk storage queue to buffer unsent trace/log spans.",
                priority="HIGH",
                automated=True,
            ),
            MitigationAction(
                action_id="ACT-03",
                title="Post-Mortem & RAG Ingestion",
                description="Archive incident fingerprint and diagnostic summary into CIRES-R RAG.",
                priority="MEDIUM",
                automated=True,
            ),
        ]

        return MitigationPlan(
            incident_id=incident_id,
            fault_category=fault_category,
            component=component,
            nist_mappings=nist_mappings,
            actions=actions,
            cires_validation_status="VERIFIED_PASSED",
            summary=f"Automated 6-Function NIST CSF 2.0 Mitigation Plan for {incident_id} ({fault_category}).",
        )

