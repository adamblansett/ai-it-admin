import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  Database,
  KeyRound,
  LayoutDashboard,
  ShieldCheck,
  Users,
} from 'lucide-react';
import {
  fetchAccessAuditRuns,
  fetchAccessFindings,
  fetchAlerts,
  fetchApprovals,
  fetchAuditEvents,
  fetchDirectoryUsers,
  fetchEntitlements,
  fetchHealth,
  fetchIncidents,
  fetchOverview,
  fetchProvisioningPlans,
  fetchRemediationDrafts,
  fetchRoleTemplates,
  fetchRunbooks,
  fetchServices,
  seedDemoData,
  verifyAuditChain,
} from './api/client';
import { AccessAuditView } from './components/AccessAuditView';
import { GovernanceView } from './components/GovernanceView';
import { IdentityView } from './components/IdentityView';
import { OverviewView } from './components/OverviewView';
import { RunbooksView } from './components/RunbooksView';
import { TelemetryView } from './components/TelemetryView';
import type {
  AccessAuditRun,
  AccessFinding,
  ActorContext,
  ActorRole,
  ApprovalRequestItem,
  AuditChainVerify,
  AuditEventItem,
  DirectoryUser,
  HealthStatus,
  Incident,
  OverviewSummary,
  ProvisioningPlan,
  RemediationDraft,
  RoleTemplate,
  RunbookItem,
  SaaSEntitlement,
  ServiceCheck,
  TelemetryAlert,
} from './types/itAdmin';

const NAV_TABS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'identity', label: 'Identity & SCIM', icon: Users },
  { id: 'telemetry', label: 'Health & Triage', icon: Activity },
  { id: 'access_audit', label: 'Access Audits', icon: KeyRound },
  { id: 'runbooks', label: 'Runbooks RAG', icon: BookOpen },
  { id: 'governance', label: 'Approvals & Audit', icon: ShieldCheck },
] as const;

const ROLE_EMAILS: Record<ActorRole, string> = {
  it_approver: 'it-approver@acme-it.local',
  operator: 'operator@acme-it.local',
  viewer: 'viewer@acme-it.local',
  admin: 'admin@acme-it.local',
};

export default function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [offline, setOffline] = useState(false);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [actor, setActor] = useState<ActorContext>({
    email: ROLE_EMAILS.it_approver,
    role: 'it_approver',
  });
  const [banner, setBanner] = useState<{ text: string; isError: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const [overview, setOverview] = useState<OverviewSummary | null>(null);
  const [templates, setTemplates] = useState<RoleTemplate[]>([]);
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [plans, setPlans] = useState<ProvisioningPlan[]>([]);
  const [services, setServices] = useState<ServiceCheck[]>([]);
  const [alerts, setAlerts] = useState<TelemetryAlert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [entitlements, setEntitlements] = useState<SaaSEntitlement[]>([]);
  const [scans, setScans] = useState<AccessAuditRun[]>([]);
  const [findings, setFindings] = useState<AccessFinding[]>([]);
  const [runbooks, setRunbooks] = useState<RunbookItem[]>([]);
  const [drafts, setDrafts] = useState<RemediationDraft[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequestItem[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [chainStatus, setChainStatus] = useState<AuditChainVerify | null>(null);

  const notify = useCallback((text: string, isError = false) => {
    setBanner({ text, isError });
  }, []);

  const refreshWorkspace = useCallback(async () => {
    try {
      const [
        ov,
        tmpls,
        usr,
        pln,
        svcs,
        alrts,
        incs,
        ents,
        scns,
        fnds,
        rbs,
        drfts,
        apps,
        evs,
        chain,
      ] = await Promise.all([
        fetchOverview(actor),
        fetchRoleTemplates(actor),
        fetchDirectoryUsers(actor),
        fetchProvisioningPlans(actor),
        fetchServices(actor),
        fetchAlerts(actor),
        fetchIncidents(actor),
        fetchEntitlements(actor),
        fetchAccessAuditRuns(actor),
        fetchAccessFindings(actor),
        fetchRunbooks(actor),
        fetchRemediationDrafts(actor),
        fetchApprovals(actor),
        fetchAuditEvents(actor),
        verifyAuditChain(actor),
      ]);
      setOverview(ov);
      setTemplates(tmpls);
      setUsers(usr);
      setPlans(pln);
      setServices(svcs);
      setAlerts(alrts);
      setIncidents(incs);
      setEntitlements(ents);
      setScans(scns);
      setFindings(fnds);
      setRunbooks(rbs);
      setDrafts(drfts);
      setApprovals(apps);
      setAuditEvents(evs);
      setChainStatus(chain);
    } catch {
      // Keep UI resilient if secondary APIs are unavailable during offline preview
    }
  }, [actor]);

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      try {
        const h = await fetchHealth();
        if (!cancelled) {
          setHealth(h);
          setOffline(false);
        }
        await refreshWorkspace();
      } catch {
        if (!cancelled) {
          setOffline(true);
        }
      }
    }
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, [refreshWorkspace]);

  async function handleLoadDemo(reset = false) {
    setBusy(true);
    try {
      const res = await seedDemoData(actor, reset);
      notify(res.message);
      await refreshWorkspace();
    } catch (err) {
      notify(err instanceof Error ? err.message : 'Demo seed failed', true);
    } finally {
      setBusy(false);
    }
  }

  function handleRoleChange(role: ActorRole) {
    const email = ROLE_EMAILS[role];
    setActor({ email, role });
    notify(`Switched active actor to ${email} (${role}).`);
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
              Phase 1 — Core Professional &amp; Enterprise Operations
            </p>
            <h1 className="mt-0.5 text-xl font-bold tracking-tight text-slate-900">
              AI IT Administrator
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <label className="flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700">
              <span>Role:</span>
              <select
                aria-label="Actor Role"
                value={actor.role}
                onChange={(e) => handleRoleChange(e.target.value as ActorRole)}
                className="bg-transparent font-semibold text-indigo-700 focus:outline-none"
              >
                <option value="it_approver">IT Approver</option>
                <option value="operator">Operator</option>
                <option value="viewer">Viewer</option>
                <option value="admin">Admin</option>
              </select>
            </label>

            <button
              type="button"
              onClick={() => handleLoadDemo(true)}
              disabled={busy || offline || (actor.role !== 'it_approver' && actor.role !== 'admin')}
              className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
            >
              <Database className="h-3.5 w-3.5" />
              {busy ? 'Loading...' : 'Reset Demo Data'}
            </button>

            <div className="flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3.5 py-1.5 text-xs font-medium">
              <Activity
                className={`h-3.5 w-3.5 ${
                  health?.status === 'ok'
                    ? 'text-emerald-600'
                    : offline
                    ? 'text-amber-600'
                    : 'text-slate-400'
                }`}
              />
              <span>
                {health?.status === 'ok'
                  ? `API Healthy (${health.llm_provider})`
                  : offline
                  ? 'Offline Starter Preview'
                  : 'Checking API...'}
              </span>
            </div>
          </div>
        </div>

        <nav
          aria-label="IT Admin Modules"
          className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-6 pb-2"
        >
          {NAV_TABS.map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition ${
                  active
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl space-y-5 px-6 py-6">
        {banner && (
          <div
            role="status"
            className={`flex items-center justify-between rounded-xl border px-4 py-2.5 text-xs font-medium ${
              banner.isError
                ? 'border-rose-200 bg-rose-50 text-rose-800'
                : 'border-emerald-200 bg-emerald-50 text-emerald-800'
            }`}
          >
            <span>{banner.text}</span>
            <button
              type="button"
              onClick={() => setBanner(null)}
              className="ml-4 text-xs underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewView
            overview={overview}
            approvals={approvals}
            services={services}
            onNavigate={setActiveTab}
            onLoadDemo={() => handleLoadDemo(false)}
            busy={busy}
          />
        )}

        {activeTab === 'identity' && (
          <IdentityView
            actor={actor}
            templates={templates}
            users={users}
            plans={plans}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'telemetry' && (
          <TelemetryView
            actor={actor}
            services={services}
            alerts={alerts}
            incidents={incidents}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'access_audit' && (
          <AccessAuditView
            actor={actor}
            entitlements={entitlements}
            scans={scans}
            findings={findings}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'runbooks' && (
          <RunbooksView
            actor={actor}
            runbooks={runbooks}
            incidents={incidents}
            drafts={drafts}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'governance' && (
          <GovernanceView
            actor={actor}
            approvals={approvals}
            auditEvents={auditEvents}
            chainStatus={chainStatus}
            onChainVerified={setChainStatus}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}
      </main>
    </div>
  );
}
