import type { FindingRecord, ScanFinding } from "../types/api";
import DecisionBadge from "./DecisionBadge";

type FindingsTableProps = {
  findings: Array<FindingRecord | ScanFinding>;
};

function isStoredFinding(
  finding: FindingRecord | ScanFinding,
): finding is FindingRecord {
  return "description" in finding;
}

function FindingsTable({ findings }: FindingsTableProps) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.title}-${index}`}>
              <td>{finding.title}</td>
              <td>
                <DecisionBadge label={finding.severity} />
              </td>
              <td>{finding.category}</td>
              <td className="mono">
                {isStoredFinding(finding) ? finding.evidence : finding.evidence}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default FindingsTable;

