import { useState, useEffect } from 'react';
import './ApprovalQueue.css';

interface ApprovalRequest {
  approval_id: string;
  action_id: string;
  session_id: string;
  tool: string;
  target: string;
  reason: string;
  requested_at: string;
}

function ApprovalQueue() {
  const [requests, setRequests] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // In a real implementation, this would fetch from the Tauri backend
    setLoading(false);
  }, []);

  const handleApprove = (id: string) => {
    // In a real implementation, this would approve via Tauri backend
    setRequests(requests.filter((r) => r.approval_id !== id));
  };

  const handleDeny = (id: string) => {
    // In a real implementation, this would deny via Tauri backend
    setRequests(requests.filter((r) => r.approval_id !== id));
  };

  if (loading) {
    return <div className="approval-queue loading">Loading requests...</div>;
  }

  return (
    <div className="approval-queue">
      <h2>Approval Queue</h2>
      {requests.length === 0 ? (
        <div className="empty-state">
          <p>No pending approval requests.</p>
          <p className="hint">
            Run <code>agentguard approve</code> to manage approvals from the CLI.
          </p>
        </div>
      ) : (
        <div className="requests-list">
          {requests.map((req) => (
            <div key={req.approval_id} className="request-card">
              <div className="request-header">
                <span className="tool">{req.tool}</span>
                <span className="timestamp">{req.requested_at}</span>
              </div>
              <div className="request-body">
                <p>
                  <strong>Target:</strong> {req.target}
                </p>
                <p>
                  <strong>Reason:</strong> {req.reason}
                </p>
              </div>
              <div className="request-actions">
                <button
                  className="btn btn-approve"
                  onClick={() => handleApprove(req.approval_id)}
                >
                  Approve
                </button>
                <button
                  className="btn btn-deny"
                  onClick={() => handleDeny(req.approval_id)}
                >
                  Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ApprovalQueue;
