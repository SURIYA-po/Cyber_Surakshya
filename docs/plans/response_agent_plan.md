# Implementation Plan: Building the `ResponseAgent` (Response & Mitigation Node)

Cyber Surakshya currently features `DetectionAgent` (ML-based threat identification) and `AnalysisAgent` (rule/enrichment engine). The next logical evolution in our multi-agent SOC architecture is the **`ResponseAgent`** — an automated incident mitigation node responsible for executing containment policies, firewall rules, host isolation, and notification escalation.

---

## Architecture Overview

```mermaid
flowchart LR
    SecurityEvent --> DetectionAgent
    DetectionAgent -->|DetectionResult| AnalysisAgent
    AnalysisAgent -->|AnalysisResult| ResponseAgent
    ResponseAgent -->|ResponseResult| BlockedIPs / Containment
```

---

## Proposed Components

### 1. Platform Domain & Schemas
- `cyber_surakshya/platform/schemas/response_result.py`:
  - `ResponseAction` enum (`BLOCK_IP`, `UNBLOCK_IP`, `ISOLATE_HOST`, `RATE_LIMIT`, `QUARANTINE_FILE`, `NOTIFY_SOC`)
  - `ResponseStatus` enum (`PENDING`, `EXECUTED`, `FAILED`, `APPROVAL_REQUIRED`, `REVERTED`)
  - `ResponseResult` Pydantic model (`response_id`, `alert_id`, `action`, `target`, `status`, `rationale`, `audit`)

### 2. Policy Engine & Agent
- `agents/response/policy.py`:
  - `ResponsePolicyEngine`: evaluates threat severity & risk scores to select containment actions.
- `agents/response/response_agent.py`:
  - `ResponseAgent`: LangGraph node executing policy logic on `PlatformStateModel`.

### 3. Graph & API Integration
- `graph/builder.py`: register `ResponseAgent` into graph builder pipeline.
- `app.py`: expose `/response/actions` API for manual review and policy management.
