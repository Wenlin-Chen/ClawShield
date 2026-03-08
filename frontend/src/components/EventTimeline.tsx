import type { EventRecord } from "../types/api";
import DecisionBadge from "./DecisionBadge";

type EventTimelineProps = {
  events: EventRecord[];
};

function EventTimeline({ events }: EventTimelineProps) {
  return (
    <div className="timeline">
      {events.map((event) => (
        <article className="card timeline-item" key={event.id}>
          <div className="timeline-header">
            <div>
              <p className="eyebrow">{event.actor}</p>
              <h3>{event.event_type}</h3>
            </div>
            <DecisionBadge label={event.decision} />
          </div>
          <p>{event.task}</p>
          <p className="mono">{event.target_resource}</p>
          <p className="muted">{event.reasons.join(" ")}</p>
        </article>
      ))}
    </div>
  );
}

export default EventTimeline;

