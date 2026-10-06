import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import './AuditLog.css';

interface AuditEvent {
  event_id: string;
  session_id: string;
  agent_id: string;
  action_type: string;
  tool: string;
  target: string;
  decision: string;
  risk_level: string;
  rule_id: string;
  timestamp: string;
}

function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 2000);
    return () => clearInterval(interval);
  }, []);

  async function loadEvents() {
    try {
      const result = await invoke<AuditEvent[]>('get_audit_events');
      setEvents(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return <div className="audit-log loading">Loading audit events...</div>;
  }

  if (error) {
    return <div className="audit-log error">Error: {error}</div>;
  }

  return (
    <div className="audit-log">
      <h2>Audit Log</h2>
      {events.length === 0 ? (
        <div className="empty-state">
          <p>No audit events found.</p>
          <p className="hint">
            Run <code>agentguard logs</code> to view events from the CLI.
          </p>
        </div>
      ) : (
        <div className="events-list">
          {events.map((event) => (
            <div key={event.event_id} className="event-card">
              <div className="event-header">
                <span className={`decision ${event.decision.toLowerCase()}`}>
                  {event.decision}
                </span>
                <span className="timestamp">{event.timestamp}</span>
              </div>
              <div className="event-body">
                <p>
                  <strong>Tool:</strong> {event.tool}
                </p>
                <p>
                  <strong>Target:</strong> {event.target}
                </p>
                <p>
                  <strong>Rule:</strong> {event.rule_id}
                </p>
                <p>
                  <strong>Risk:</strong> {event.risk_level}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default AuditLog;
