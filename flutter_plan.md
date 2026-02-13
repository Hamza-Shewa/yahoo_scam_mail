# Flutter/Dart Implementation Plan — Yahoo Smart Scanner

## Objective
Rebuild the current Python scanner into a **Flutter Desktop app + Dart scanning core** with full operational parity and safer UX.

### Required parity
- Two-pass scan (Pass 1 sender filter + Pass 2 deep analysis)
- Trusted sender/domain allowlist behavior
- JSON-driven rules (`trusted_senders.json`, `scam_data.json`)
- Actions: block, delete, block+delete (excluding trusted)
- Progress + cancel support for long operations
- Local report output

---

## Architecture Decisions (Locked)
- **UI:** Flutter Mobile (**Android first**)
- **State management:** `flutter_riverpod`
- **Routing:** `go_router` (minimal routes)
- **Models:** `freezed` + `json_serializable`
- **Storage:** local JSON in app data folder (safe atomic writes)
- **Security:** `flutter_secure_storage` for credentials
- **Design:** Material 3 (dark/light support)
- **Testing:** unit + widget + integration + golden (critical screens)

### Android-first constraints
- IMAP scanning runs only while app is in foreground for MVP (no background long-running service in MVP).
- Use Android secure storage/keystore via `flutter_secure_storage`.
- Add clear progress and interruption recovery because mobile sessions can be interrupted.

---

## Suggested Repo Layout
```text
scanner_app/
  lib/
    core/
      di/
      error/
      theme/
      utils/
    features/
      scan/
        domain/
        application/
        infrastructure/
        presentation/
      rules/
      trusted/
      actions/
  test/
  integration_test/
scanner_core/   # optional separate pure-Dart package for scan engine
```

---

## Phase 0 — Scope Baseline & Parity Contract

### Tasks
- [ ] P0-T1 Create a Python behavior matrix from:
  - `yahoo_smart_scanner.py`
  - `scanner_data.py`
  - `trusted_senders.json`
  - `scam_data.json`
- [ ] P0-T2 Define MVP in/out scope (Android first, no cloud sync).
- [ ] P0-T3 Define parity test set (sample emails + expected outputs).
- [ ] P0-T4 Freeze parity contract document.

### Deliverables
- Parity contract (`docs/parity_contract.md`)
- Feature checklist with pass/fail criteria

### Exit criteria
- No unresolved “how should this behave?” questions.

---

## Phase 1 — Project Bootstrap & Quality Guardrails

### Tasks
- [ ] P1-T1 Initialize Flutter mobile app and enable Android target.
- [ ] P1-T2 Add dependencies:
  - `flutter_riverpod`, `go_router`, `freezed_annotation`, `json_annotation`, `collection`, `intl`, `flutter_secure_storage`
- [ ] P1-T3 Add dev dependencies:
  - `build_runner`, `freezed`, `json_serializable`, `flutter_lints`, `mocktail`, `golden_toolkit`
- [ ] P1-T4 Create CI pipeline:
  - `flutter analyze`
  - `dart format --set-exit-if-changed .`
  - `flutter test`
- [ ] P1-T5 Add app-wide error boundary/logging strategy.

### Deliverables
- Running Flutter shell app
- Green CI for baseline PR

### Exit criteria
- `flutter analyze` and tests pass in CI on every PR.

---

## Phase 2 — Domain Modeling & Rule Contracts

### Tasks
- [ ] P2-T1 Implement entities (pure Dart):
  - `ScamEmail`, `ScamSender`, `BodyAnalysis`, `AuthStatus`
- [ ] P2-T2 Implement config models:
  - `TrustedData`, `ScamData`, `LookalikeMap`
- [ ] P2-T3 Add normalization utilities (lowercase, trim, dedupe).
- [ ] P2-T4 Add validation rules for malformed/partial JSON.
- [ ] P2-T5 Add model unit tests for all parsing paths.

### Deliverables
- Typed model layer with generated serializers
- Model test suite

### Exit criteria
- Existing JSON files deserialize/normalize exactly as expected.

---

## Phase 3 — Config Persistence & Migration Layer

### Tasks
- [ ] P3-T1 Implement config repositories:
  - `TrustedRepository`
  - `ScamRulesRepository`
- [ ] P3-T2 Implement safe write flow (temp + atomic replace).
- [ ] P3-T3 Add backup strategy before writes (`.bak`).
- [ ] P3-T4 Implement trusted sender operations:
  - add, remove, list, exists
- [ ] P3-T5 Implement scam data edit/validate/save API.
- [ ] P3-T6 Implement migration utility to import current JSON files.

### Deliverables
- Production-safe config management layer

### Exit criteria
- Config writes are crash-safe and rollback-capable.

---

## Phase 4 — IMAP Infrastructure (Yahoo)

### Tasks
- [ ] P4-T1 Select IMAP package (evaluate `enough_mail` first).
- [ ] P4-T2 Build `ImapClientService` abstraction:
  - connect/login/logout
  - select folder
  - search UIDs
  - fetch headers/body
  - copy/store/expunge
- [ ] P4-T3 Implement spam folder resolver (Spam/Junk/Bulk variants).
- [ ] P4-T4 Implement timeout/retry policy and error mapping.
- [ ] P4-T5 Implement cancellation token support.
- [ ] P4-T6 Add integration tests with mocked server responses.

### Deliverables
- Stable IMAP adapter with cancellation support

### Exit criteria
- Reliable Yahoo connectivity + cancellation without app freeze.

---

## Phase 5 — Pass 1 Scanner (Sender/Auth)

### Tasks
- [ ] P5-T1 Port sender analysis rules from Python:
  - suspicious exact domains
  - suspicious TLD suffixes
  - regex sender patterns
  - brand spoof checks
  - lookalike checks
  - SPF/DKIM/DMARC parsing
- [ ] P5-T2 Implement batched UID/header fetch loop.
- [ ] P5-T3 Implement suspicious sender aggregation map.
- [ ] P5-T4 Emit progress stream events (`processed`, `total`, `stage`).
- [ ] P5-T5 Add benchmark script for large mailbox simulation.

### Deliverables
- `RunPass1ScanUseCase`

### Exit criteria
- Pass 1 parity within agreed tolerance against Python output.

---

## Phase 6 — Pass 2 Scanner (Body/Heuristic)

### Tasks
- [ ] P6-T1 Port body extraction logic:
  - plain text + HTML fallback
  - image/link counters
- [ ] P6-T2 Port scoring logic:
  - scam keyword matching
  - urgency term scoring
  - URL and shortener checks
  - generic greeting/caps/attachment patterns
  - image-heavy low-text heuristic
- [ ] P6-T3 Implement reason de-duplication + score cap.
- [ ] P6-T4 Emit progress stream for deep analysis.
- [ ] P6-T5 Add fixture-based regression tests.

### Deliverables
- `RunPass2ScanUseCase`

### Exit criteria
- Score/reason output matches Python behavior for fixture set.

---

## Phase 7 — Action Engine (Block/Delete)

### Tasks
- [ ] P7-T1 Implement use-cases:
  - `BlockSendersUseCase`
  - `DeleteSendersUseCase`
  - `BlockAndDeleteUseCase`
- [ ] P7-T2 Enforce trusted exclusion in action layer.
- [ ] P7-T3 Add block-list file integration behavior.
- [ ] P7-T4 Add dry-run and confirmation metadata output.
- [ ] P7-T5 Add action-level progress stream events.

### Deliverables
- Action engine with safety controls

### Exit criteria
- No trusted sender is ever blocked/deleted by action flows.

---

## Phase 8 — Flutter Android UI (Material 3)

### Tasks
- [ ] P8-T1 Build app shell and navigation (`go_router`):
  - Scan
  - Potential senders
  - Trusted manager
  - Scam data manager
  - Settings
- [ ] P8-T2 Implement scan dashboard:
  - credential input (from secure storage)
  - start/stop actions
  - live stage progress + percentage + ETA
- [ ] P8-T3 Implement potential sender table:
  - sender, count, top reasons
  - trust toggle
  - one-click block/delete/block+delete
- [ ] P8-T4 Implement scam data editor:
  - validate JSON
  - prettify/format
  - save with backup
- [ ] P8-T5 Implement operation log panel + export.
- [ ] P8-T6 Add responsive mobile layout and accessibility checks.
- [ ] P8-T7 Handle mobile lifecycle safely (pause/resume while scanning, reconnect prompts).

### Deliverables
- End-to-end usable Android UI

### Exit criteria
- Operators can run full workflow on Android without terminal usage.

---

## Phase 9 — Security Hardening

### Tasks
- [ ] P9-T1 Migrate password storage to `flutter_secure_storage`.
- [ ] P9-T2 Add redaction policy for logs (`email`, `tokens`, `password`).
- [ ] P9-T3 Add destructive-action confirmation gate.
- [ ] P9-T4 Add optional inactivity auto-lock.
- [ ] P9-T5 Add secure defaults (no plaintext secrets files).

### Deliverables
- Security checklist + secure credential flow

### Exit criteria
- No plaintext credentials in disk artifacts or logs.

---

## Phase 10 — Testing Strategy & Quality Gates

### Tasks
- [ ] P10-T1 Unit tests (domain/use-cases):
  - parsing
  - rule checks
  - scoring
- [ ] P10-T2 Widget tests:
  - progress rendering
  - sender trust toggles
  - action button states
- [ ] P10-T3 Integration tests:
  - scan flow
  - action flow
  - config save/reload flow
- [ ] P10-T4 Golden tests for critical screens.
- [ ] P10-T5 CI quality gates:
  - analyze pass
  - test pass
  - coverage threshold (e.g., 75% minimum on core engine)

### Deliverables
- Automated validation suite in CI

### Exit criteria
- No release branch merge without green CI.

---

## Phase 11 — Packaging, UAT, Release

### Tasks
- [ ] P11-T1 Build signed Android release (`.aab`) for Play/internal distribution.
- [ ] P11-T2 Add first-run migration wizard for JSON import.
- [ ] P11-T3 Produce operator docs:
  - quick start
  - troubleshooting
  - recovery/backup steps
- [ ] P11-T4 UAT with real mailbox samples and sign-off sheet.
- [ ] P11-T5 Release candidate + rollback plan.

### Deliverables
- Installable Android release + release docs

### Exit criteria
- Stakeholder sign-off and stable release artifact.

---

## Suggested Timeline (6 Sprints)
- **Sprint 1:** Phase 0–2
- **Sprint 2:** Phase 3–4
- **Sprint 3:** Phase 5
- **Sprint 4:** Phase 6–7
- **Sprint 5:** Phase 8
- **Sprint 6:** Phase 9–11

---

## Critical Path
1. Phase 0 → 1 → 2
2. Phase 2 → 3 and 4
3. Phase 4 + 5 + 6 → 7
4. Phase 3 + 7 → 8
5. Phase 8 → 9 → 10 → 11

---

## Project Definition of Done
- Parity checklist from Phase 0 is fully green.
- Existing JSON rule files are fully compatible.
- Full scan + trusted management + one-click actions are production-ready.
- Security baseline is enforced (no plaintext credential handling).
- CI and Android packaging are stable for repeatable releases.
