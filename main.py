from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

app = FastAPI()


class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Dict[str, Any]] = []
    environmentApproval: bool = False


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations = []

    w = req.workflow
    img = req.image

    # 1. Least-privilege permissions
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if w.permissions != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull request trigger
    if req.event == "pull_request":
        if w.trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests
    if not w.testsPassed or not w.matrixComplete or w.failFast:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in w.actions:
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner != "actions":
            valid_sha = (
                isinstance(ref, str)
                and len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            )

            if not valid_sha:
                violations.append("MUTABLE_ACTION")

    # 5. Container security
    if not img.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if img.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if img.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if img.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    if not img.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # 6. Production deployment requirements
    if req.target == "production":
        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if not w.environmentApproval:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicate violation codes
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
