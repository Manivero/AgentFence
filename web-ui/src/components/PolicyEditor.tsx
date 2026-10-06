import { useState } from 'react';
import './PolicyEditor.css';

function PolicyEditor() {
  const [policy, setPolicy] = useState(`version: 1

defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny

shell:
  allow:
    - git
    - cargo
  ask:
    - npm
  deny:
    - powershell

network:
  allow:
    - github.com
    - crates.io
  deny:
    - evil.com

mcp:
  allow:
    - github
  deny:
    - shell
`);

  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    // In a real implementation, this would save via Tauri backend
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

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
