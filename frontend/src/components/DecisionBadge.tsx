import type { Decision, Severity } from "../types/api";

type BadgeProps = {
  label: Decision | Severity;
};

function DecisionBadge({ label }: BadgeProps) {
  return <span className={`badge badge-${label}`}>{label}</span>;
}

export default DecisionBadge;

