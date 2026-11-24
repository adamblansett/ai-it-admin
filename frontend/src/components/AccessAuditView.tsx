import { useState } from 'react';
import { KeyRound, Play, ShieldAlert } from 'lucide-react';
import { requestFindingRemediation, runAccessAuditScan } from '../api/client';
import type {
  AccessAuditRun,
  AccessFinding,
  ActorContext,
  SaaSEntitlement,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface AccessAuditViewProps {
  actor: ActorContext;
  entitlements: SaaSEntitlement[];
  scans: AccessAuditRun[];
  findings: AccessFinding[];
  onRefresh: () => Promise<void>;
  onNotify: (text: string, isError?: boolean) => void;
}

export function AccessAuditView({
  actor,
  entitlements,
  scans,
  findings,
  onRefresh,
  onNotify,
}: AccessAuditViewProps) {
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [busy, setBusy] = useState(false);

  const canMutate = actor.role !== 'viewer';
  const latestScan = scans[0] ?? null;

  const filteredFindings =
    typeFilter === 'all'
      ? findings
      : findings.filter((f) => f.finding_type === typeFilter);

  const orphanedCount = findings.filter(
    (f) => f.finding_type === 'orphaned_account' && f.status !== 'remediated',
  ).length;
  const staleCount = findings.filter(
    (f) => f.finding_type === 'stale_token' && f.status !== 'remediated',
  ).length;
  const driftCount = findings.filter(
    (f) => f.finding_type === 'privilege_drift' && f.status !== 'remediated',
  ).length;
  const mfaCount = findings.filter(
    (f) => f.finding_type === 'missing_mfa' && f.status !== 'remediated',
  ).length;

  async function handleRunScan() {
    setBusy(true);
    try {
      const res = await runAccessAuditScan(actor, 'all_saas');
      onNotify(
        `Access scan complete: ${res.total_entitlements_scanned} entitlements scanned, ${res.findings_count} findings flagged.`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Access audit scan failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleRequestApproval(findingId: string) {
    setBusy(true);
    try {
      await requestFindingRemediation(actor, findingId);
      onNotify('Queued remediation request for IT Approver sign-off.');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to request remediation', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-indigo-600" />
              <h2 className="text-sm font-semibold text-slate-900">
                SaaS Access Control &amp; Entitlement Audit
              </h2>
            </div>
            <p className="mt-1 text-xs text-slate-600">
              Detects orphaned accounts, stale API tokens (&gt;90d), privilege drift against RBAC
              templates, and missing MFA across SaaS applications.
            </p>
          </div>
          <button
            type="button"
            disabled={busy || !canMutate}
            onClick={handleRunScan}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {busy ? 'Scanning...' : 'Run Access Audit Scan'}
          </button>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-rose-200 bg-rose-50/70 p-3">
            <p className="text-[11px] font-semibold uppercase text-rose-700">Orphaned Accounts</p>
            <p className="mt-1 text-xl font-bold text-rose-900">{orphanedCount}</p>
          </div>
          <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-3">
            <p className="text-[11px] font-semibold uppercase text-amber-800">Stale Tokens</p>
            <p className="mt-1 text-xl font-bold text-amber-900">{staleCount}</p>
          </div>
          <div className="rounded-lg border border-orange-200 bg-orange-50/70 p-3">
            <p className="text-[11px] font-semibold uppercase text-orange-800">Privilege Drift</p>
            <p className="mt-1 text-xl font-bold text-orange-900">{driftCount}</p>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <p className="text-[11px] font-semibold uppercase text-slate-600">Missing MFA</p>
            <p className="mt-1 text-xl font-bold text-slate-900">{mfaCount}</p>
          </div>
        </div>

        {latestScan && (
          <p className="mt-3 text-[11px] text-slate-500">
            Latest scan ({latestScan.scope}): {latestScan.llm_summary}
          </p>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-rose-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Findings ({filteredFindings.length})
            </h3>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {[
              { id: 'all', label: 'All' },
              { id: 'orphaned_account', label: 'Orphaned' },
              { id: 'stale_token', label: 'Stale Tokens' },
              { id: 'privilege_drift', label: 'Privilege Drift' },
              { id: 'missing_mfa', label: 'Missing MFA' },
            ].map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setTypeFilter(f.id)}
                className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ${
                  typeFilter === f.id
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3 space-y-2.5">
          {filteredFindings.length === 0 ? (
            <p className="text-xs text-slate-500">
              No findings match the current filter. Run an access audit scan to check SaaS apps.
            </p>
          ) : (
            filteredFindings.map((item) => (
              <div
                key={item.id}
                className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3"
              >
                <div className="max-w-2xl">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold text-slate-900">
                      {item.app_name} · {item.user_email}
                    </span>
                    <StatusBadge value={item.finding_type} />
                    <StatusBadge value={item.severity} />
                    <StatusBadge value={item.status} />
                  </div>
                  <p className="mt-1 text-xs text-slate-700">{item.detail}</p>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Recommended: {item.recommended_action}
                  </p>
                </div>

                {item.status === 'open' && (
                  <button
                    type="button"
                    disabled={busy || !canMutate}
                    onClick={() => handleRequestApproval(item.id)}
                    className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
                  >
                    Request Approval
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-900">
          Monitored SaaS Entitlements ({entitlements.length})
        </h3>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 text-[11px] uppercase text-slate-500">
              <tr>
                <th className="py-2 pr-3">Application</th>
                <th className="py-2 pr-3">User</th>
                <th className="py-2 pr-3">Assigned Role</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">MFA</th>
                <th className="py-2">Expected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {entitlements.map((e) => (
                <tr key={e.id}>
                  <td className="py-2 pr-3 font-semibold text-slate-900">{e.app_name}</td>
                  <td className="py-2 pr-3 text-slate-700">{e.user_email}</td>
                  <td className="py-2 pr-3">
                    <span className="font-mono text-[11px]">{e.assigned_role}</span>
                    {e.is_privileged && (
                      <span className="ml-1.5 rounded bg-amber-100 px-1 text-[10px] font-bold text-amber-900">
                        PRIV
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-3">
                    <StatusBadge value={e.account_status} />
                  </td>
                  <td className="py-2 pr-3">{e.mfa_enabled ? 'Enabled' : 'Disabled'}</td>
                  <td className="py-2">{e.expected_by_role ? 'Yes' : 'Drift'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
