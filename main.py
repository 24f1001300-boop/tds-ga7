from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

app = FastAPI()


class ReleaseGateRequest(BaseModel):
    event: str
    ref: str | None = None
    permissions: Dict[str, str] = {}
    testsPassed: bool = False
    matrixComplete: bool = False
    failFast: bool = True
    actions: List[Dict[str, Any]] = []
    multiStage: bool = False
    runsAsRoot: bool = True
    secretMode: str = "unknown"
    criticalVulnerabilities: int = 0
    digestPinned: bool = False
    environmentApproval: bool = False


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations = []

    # Permissions
    if req.permissions != {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }:
        violations.append("EXCESS_PERMISSION")

    # PR trigger
    if req.event == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # Tests
    if not req.testsPassed or not req.matrixComplete or req.failFast:
        violations.append("TESTS_INCOMPLETE")

    # GitHub Actions
    for action in req.actions:
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner != "actions":
            if not (
                isinstance(ref, str)
                and len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")

    # Docker image
    if not req.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if req.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if req.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if req.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    if not req.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # Production checks
    if req.event == "push":
        if req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if not req.environmentApproval:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving order
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "block" if violations else "promote",
        "violations": violations,
    }
