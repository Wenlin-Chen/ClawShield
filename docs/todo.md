# Function Gap TODO Sweep

This TODO list captures high-impact missing functions in the current ClawShield release and marks quick wins completed in this update.

## Completed quick wins

- [x] **Audit session drill-down filters in Dashboard UI**
  - Added text search across session/actor/task/resource and finding text.
  - Added decision filter (`allow`, `warn`, `block`) for runtime events.
  - Added severity filter (`low`..`critical`) for findings.
  - Added one-click filter reset and filtered-count visibility.

## Important missing functions (next priorities)

- [ ] **Export audit history (JSON/CSV)** for incident response handoff.
- [ ] **Session detail view** with full event + finding correlation timeline.
- [ ] **Configurable policy mode switch** (`monitor`, `balanced`, `strict`) in UI.
- [ ] **Interactive action approvals** for selected risky events.
- [ ] **Rule customization UI** for blocked paths/domains/commands.
- [ ] **Setup doctor in frontend** to validate plugin/backend/tool mappings.
- [ ] **Saved filter presets** for repeat investigations.
