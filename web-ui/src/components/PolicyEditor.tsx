import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './PolicyEditor.css';

function PolicyEditor() {
  const [policy, setPolicy] = useState('');
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadPolicy();
  }, []);

  async function loadPolicy() {
    try {
      const result = await invoke<string>('load_policy');
      setPolicy(result);
    } catch (e) {
      console.error('Failed to load policy:', e);
    } finally {
      setLoading(false);
    }
  }

  const handleSave = async () => {
    try {
      await invoke('save_policy', { policyContent: policy });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      console.error('Failed to save policy:', e);
    }
  };

  if (loading) {
    return <div className="policy-editor loading">Loading policy...</div>;
  }

  return (
    <div className="policy-editor">
      <h2>Policy Editor</h2>
      <div className="editor-container">
        <textarea
          className="policy-textarea"
          value={policy}
          onChange={(e) => setPolicy(e.target.value)}
          spellCheck={false}
        />
      </div>
      <div className="editor-actions">
        <button className="btn btn-primary" onClick={handleSave}>
          Save Policy
        </button>
        {saved && <span className="saved-indicator">Saved!</span>}
      </div>
      <div className="policy-help">
        <h3>Policy Syntax</h3>
        <ul>
          <li>
            <code>allow</code> — Explicitly allow
          </li>
          <li>
            <code>deny</code> — Explicitly deny
          </li>
          <li>
            <code>ask</code> — Require approval
          </li>
        </ul>
      </div>
    </div>
  );
}

export default PolicyEditor;
