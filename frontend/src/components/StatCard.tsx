type StatCardProps = {
  label: string;
  value: number | string;
  tone?: "neutral" | "danger" | "warning";
};

function StatCard({ label, value, tone = "neutral" }: StatCardProps) {
  return (
    <div className={`card stat-card tone-${tone}`}>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
    </div>
  );
}

export default StatCard;

