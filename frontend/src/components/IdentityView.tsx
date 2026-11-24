import { useState } from 'react';
import { Check, ShieldAlert, UserPlus, X } from 'lucide-react';
import { decideApproval, previewProvisioningPlan } from '../api/client';
import type {
  ActorContext,
  DirectoryUser,
  ProvisioningPlan,
  RoleTemplate,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface IdentityViewProps {
  actor: ActorContext;
  templates: RoleTemplate[];
  users: DirectoryUser[];
  plans: ProvisioningPlan[];
  onRefresh: () => Promise<void>;
  onNotify: (text: string, isError?: boolean) => void;
}

export function IdentityView({
  actor,
  templates,
  users,
  plans,
  onRefresh,
  onNotify,
}: IdentityViewProps) {
  const [planType, setPlanType] = useState<'joiner' | 'mover' | 'leaver'>('joiner');
  const [targetEmail, setTargetEmail] = useState('taylor.brooks@acme-it.local');
  const [targetName, setTargetName] = useState('Taylor Brooks');
  const [toRoleCode, setToRoleCode] = useState('eng-backend');
  const [scimProvider, setScimProvider] = useState<'okta' | 'entra_id' | 'google_workspace'>(
    'okta',
  );
  const [extraApp, setExtraApp] = useState('');
  const [extraRole, setExtraRole] = useState('admin');
  const [extraPrivileged, setExtraPrivileged] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const canApprove = actor.role === 'it_approver' || actor.role === 'admin';

  async function handlePreview(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const requestedExtraApps = extraApp.trim()
        ? [
            {
              app: extraApp.trim(),
              role: extraRole.trim() || 'admin',
              privileged: extraPrivileged,
            },
          ]
        : [];
      const plan = await previewProvisioningPlan(actor, {
        plan_type: planType,
        target_email: targetEmail.trim(),
        target_name: targetName.trim(),
        to_role_code: planType === 'leaver' ? null : toRoleCode || templates[0]?.code || null,
        scim_provider: scimProvider,
        requested_extra_apps: requestedExtraApps,
      });
      onNotify(
        `Created ${plan.plan_type} SCIM dry-run plan for ${plan.target_email} (${plan.risk_level} risk).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to generate SCIM plan', true);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDecision(approvalId: string, decision: 'approved' | 'rejected') {
    setSubmitting(true);
    try {
      await decideApproval(
        actor,
        approvalId,
        decision,
        `${decision} from Identity SCIM view`,
      );
      onNotify(`SCIM provisioning plan ${decision}.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Approval action failed', true);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <UserPlus className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-semibold text-slate-900">
            Joiner / Mover / Leaver SCIM Dry-Run Planner
          </h2>
        </div>
        <p className="mt-1 text-xs text-slate-600">
          Preview exact SCIM operations and least-privilege deviations before any directory
          mutation. Changes apply only after IT Approver sign-off.
        </p>

        <form onSubmit={handlePreview} className="mt-4 grid gap-3 sm:grid-cols-3">
          <div>
            <label className="block text-[11px] font-semibold text-slate-700">
              Lifecycle Type
            </label>
            <select
              aria-label="Lifecycle Type"
              value={planType}
              onChange={(e) => setPlanType(e.target.value as 'joiner' | 'mover' | 'leaver')}
              className="mt-1 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            >
              <option value="joiner">Joiner (Onboard)</option>
              <option value="mover">Mover (Role Transfer)</option>
              <option value="leaver">Leaver (Offboard)</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-700">Target Email</label>
            <input
              aria-label="Target Email"
              type="email"
              required
              value={targetEmail}
              onChange={(e) => setTargetEmail(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-700">Full Name</label>
            <input
              aria-label="Full Name"
              type="text"
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            />
          </div>

          {planType !== 'leaver' && (
            <div>
              <label className="block text-[11px] font-semibold text-slate-700">
                Target Role Template
              </label>
              <select
                aria-label="Target Role Template"
                value={toRoleCode}
                onChange={(e) => setToRoleCode(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
              >
                {templates.length === 0 ? (
                  <option value="eng-backend">eng-backend</option>
                ) : (
                  templates.map((t) => (
                    <option key={t.id} value={t.code}>
                      {t.code} — {t.name}
                    </option>
                  ))
                )}
              </select>
            </div>
          )}

          <div>
            <label className="block text-[11px] font-semibold text-slate-700">
              SCIM Provider
            </label>
            <select
              aria-label="SCIM Provider"
              value={scimProvider}
              onChange={(e) =>
                setScimProvider(e.target.value as 'okta' | 'entra_id' | 'google_workspace')
              }
              className="mt-1 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            >
              <option value="okta">Okta</option>
              <option value="entra_id">Microsoft Entra ID</option>
              <option value="google_workspace">Google Workspace</option>
            </select>
          </div>

          {planType !== 'leaver' && (
            <div>
              <label className="block text-[11px] font-semibold text-slate-700">
                Extra App Override (Optional)
              </label>
              <div className="mt-1 flex gap-1.5">
                <input
                  aria-label="Extra App"
                  placeholder="e.g. AWS"
                  value={extraApp}
                  onChange={(e) => setExtraApp(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
                />
                <input
                  aria-label="Extra Role"
                  placeholder="admin"
                  value={extraRole}
                  onChange={(e) => setExtraRole(e.target.value)}
                  className="w-24 rounded-lg border border-slate-300 px-2 py-1.5 text-xs"
                />
              </div>
              <label className="mt-1 inline-flex items-center gap-1 text-[11px] text-slate-600">
                <input
                  type="checkbox"
                  checked={extraPrivileged}
                  onChange={(e) => setExtraPrivileged(e.target.checked)}
                />
                Privileged override
              </label>
            </div>
          )}

          <div className="flex items-end sm:col-span-3">
            <button
              type="submit"
              disabled={submitting || actor.role === 'viewer'}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? 'Generating...' : 'Preview SCIM Dry-Run Plan'}
            </button>
          </div>
        </form>
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-900">
          SCIM Provisioning Plans ({plans.length})
        </h3>
        {plans.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-5 text-xs text-slate-500">
            No provisioning plans generated yet.
          </div>
        ) : (
          plans.map((plan) => (
            <article
              key={plan.id}
              className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-bold uppercase text-indigo-700">
                      {plan.plan_type}
                    </span>
                    <span className="text-sm font-semibold text-slate-900">
                      {plan.target_name} ({plan.target_email})
                    </span>
                    <StatusBadge value={plan.status} />
                    <StatusBadge value={plan.risk_level} />
                  </div>
                  <p className="mt-1 text-xs text-slate-600">
                    Provider: {plan.scim_provider} · Role: {plan.from_role_code ?? 'none'} →{' '}
                    {plan.to_role_code ?? 'terminated'}
                  </p>
                </div>

                {plan.status === 'pending_approval' && plan.approval_id && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={!canApprove || submitting}
                      onClick={() => handleDecision(plan.approval_id!, 'approved')}
                      className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-40"
                    >
                      <Check className="h-3.5 w-3.5" />
                      Approve &amp; Apply
                    </button>
                    <button
                      type="button"
                      disabled={!canApprove || submitting}
                      onClick={() => handleDecision(plan.approval_id!, 'rejected')}
                      className="inline-flex items-center gap-1 rounded-lg border border-rose-300 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-100 disabled:opacity-40"
                    >
                      <X className="h-3.5 w-3.5" />
                      Reject
                    </button>
                  </div>
                )}
              </div>

              {plan.least_privilege_warnings_json.length > 0 && (
                <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-2.5 text-xs text-amber-900">
                  <div className="flex items-center gap-1.5 font-semibold">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    Least-Privilege Warnings
                  </div>
                  <ul className="mt-1 list-disc pl-4">
                    {plan.least_privilege_warnings_json.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="mt-3 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                {plan.scim_diff_json.map((op, idx) => (
                  <div
                    key={idx}
                    className={`rounded-lg border px-2.5 py-2 text-[11px] ${
                      op.action.startsWith('revoke') || op.action === 'suspend_user'
                        ? 'border-rose-200 bg-rose-50/70 text-rose-900'
                        : 'border-slate-200 bg-slate-50 text-slate-800'
                    }`}
                  >
                    <span className="font-mono font-semibold">{op.action}</span>{' '}
                    <span>→ {op.target}</span>
                    {op.privileged && (
                      <span className="ml-1.5 rounded bg-amber-200 px-1 text-[10px] font-bold text-amber-900">
                        PRIV
                      </span>
                    )}
                  </div>
                ))}
              </div>
              <p className="mt-2.5 text-[11px] text-slate-500">{plan.llm_rationale}</p>
            </article>
          ))
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-900">
          Directory Users ({users.length})
        </h3>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 text-[11px] uppercase text-slate-500">
              <tr>
                <th className="py-2 pr-3">Employee</th>
                <th className="py-2 pr-3">Department</th>
                <th className="py-2 pr-3">Role Template</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Active Apps</th>
                <th className="py-2">MFA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="py-2 pr-3">
                    <div className="font-semibold text-slate-900">{u.full_name}</div>
                    <div className="text-[11px] text-slate-500">{u.email}</div>
                  </td>
                  <td className="py-2 pr-3 text-slate-700">{u.department}</td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-slate-700">
                    {u.role_template_code ?? '—'}
                  </td>
                  <td className="py-2 pr-3">
                    <StatusBadge value={u.employment_status} />
                  </td>
                  <td className="py-2 pr-3 font-semibold text-slate-900">
                    {u.active_entitlements_count}
                  </td>
                  <td className="py-2">{u.mfa_enrolled ? 'Enrolled' : 'Missing'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
