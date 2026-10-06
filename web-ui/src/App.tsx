import { useState } from 'react';
import AuditLog from './components/AuditLog';
import PolicyEditor from './components/PolicyEditor';
import ApprovalQueue from './components/ApprovalQueue';
import './App.css';

type Tab = 'audit' | 'policy' | 'approvals';

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('audit');

  return (
    <div className="app">
      <header className="header">
        <h1>AgentFence</h1>
        <p className="subtitle">Local Policy / Approval / Audit Broker</p>
      </header>

      <nav className="nav">
        <button
          className={activeTab === 'audit' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => setActiveTab('audit')}
        >
          Audit Log
        </button>
        <button
          className={activeTab === 'policy' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => setActiveTab('policy')}
        >
          Policy Editor
        </button>
        <button
          className={activeTab === 'approvals' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => setActiveTab('approvals')}
        >
          Approvals
        </button>
      </nav>

      <main className="main">
        {activeTab === 'audit' && <AuditLog />}
        {activeTab === 'policy' && <PolicyEditor />}
        {activeTab === 'approvals' && <ApprovalQueue />}
      </main>

      <footer className="footer">
        <p>Protection Mode: COOPERATIVE | Security Boundary: LIMITED</p>
      </footer>
    </div>
  );
}

export default App;
