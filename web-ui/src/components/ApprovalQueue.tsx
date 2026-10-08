import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
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
    loadRequests();
    const interval = setInterval(loadRequests, 2000);
    return () => clearInterval(interval);
  }, []);

  async function loadRequests() {
    try {
      const result = await invoke<ApprovalRequest[]>('get_pending_approvals');
      setRequests(result);
    } catch (e) {
      console.error('Failed to load approval requests:', e);
    } finally {
      setLoading(false);
    }
  }

  const handleApprove = async (id: string) => {
    try {
      await invoke('approve_action', { approvalId: id });
      setRequests(requests.filter((r) => r.approval_id !== id));
    } catch (e) {
      console.error('Failed to approve:', e);
    }
  };

  const handleDeny = async (id: string) => {
    try {
      await invoke('deny_action', { approvalId: id });
      setRequests(requests.filter((r) => r.approval_id !== id));
    } catch (e) {
      console.error('Failed to deny:', e);
    }
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
