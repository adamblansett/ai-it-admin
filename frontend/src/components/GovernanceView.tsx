import { useState } from 'react';
import { Check, EyeOff, ShieldCheck, X } from 'lucide-react';
import { decideApproval, redactPiiText, verifyAuditChain } from '../api/client';
import type {
  ActorContext,
  ApprovalRequestItem,
  AuditChainVerify,
  AuditEventItem,
  PiiRedactResult,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface GovernanceViewProps {
  actor: ActorContext;
  approvals: ApprovalRequestItem[];
  auditEvents: AuditEventItem[];
  chainStatus: AuditChainVerify | null;
  onChainVerified: (status: AuditChainVerify) => void;
  onRefresh: () => Promise<void>;
  onNotify: (text: string, isError?: boolean) => void;
}

export function GovernanceView({
  actor,
  approvals,
  auditEvents,
  chainStatus,
  onChainVerified,
  onRefresh,
  onNotify,
}: GovernanceViewProps) {
  const [notesById, setNotesById] = useState<Record<string, string>>({});
  const [piiInput, setPiiInput] = useState(
    'Incident log for alice@acme-it.local on 10.24.0.15 with AWS AKIA1234567890ABCDEF and token=ghp_supersecret1234567890ab',
  );
  const [piiResult, setPiiResult] = useState<PiiRedactResult | null>(null);
  const [busy, setBusy] = useState(false);

  const canApprove = actor.role === 'it_approver' || actor.role === 'admin';

  async function handleDecision(approvalId: string, decision: 'approved' | 'rejected') {
    setBusy(true);
    try {
      const notes = notesById[approvalId] ?? '';
      await decideApproval(actor, approvalId, decision, notes);
      onNotify(`Approval request ${decision}.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Approval decision failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyChain() {
    setBusy(true);
    try {
      const status = await verifyAuditChain(actor);
      onChainVerified(status);
      onNotify(status.message, !status.valid);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Chain verification failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleTestPii() {
    setBusy(true);
    try {
      const res = await redactPiiText(actor, piiInput);
      setPiiResult(res);
      onNotify(`Scrubbed ${res.total_redactions} sensitive token(s)/PII item(s).`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'PII redaction preview failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Human-in-the-Loop Approval Queue ({approvals.length})
            </h2>
            <p className="mt-1 text-xs text-slate-600">
              High-impact SCIM directory mutations, SaaS access revocations, and change-controlled
              remediations require explicit <span className="font-mono">it_approver</span> or{' '}
              <span className="font-mono">admin</span> sign-off.
            </p>
          </div>
          {!canApprove && (
            <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-[11px] font-semibold text-amber-800">
              Read-only for role &quot;{actor.role}&quot;
            </span>
          )}
        </div>

        <div className="mt-4 space-y-3">
          {approvals.length === 0 ? (
            <p className="text-xs text-slate-500">No approval requests recorded yet.</p>
          ) : (
            approvals.map((app) => (
              <article
                key={app.id}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3.5"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-bold text-slate-900">{app.summary}</span>
                      <StatusBadge value={app.risk_level} />
                      <StatusBadge value={app.status} />
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      {app.entity_type} · {app.action_requested} · requested by {app.requested_by}
                    </p>
                    {app.decided_by && (
                      <p className="mt-0.5 text-[11px] text-slate-600">
                        Decided by {app.decided_by}: {app.decision_notes}
                      </p>
                    )}
                  </div>

                  {app.status === 'pending' && (
                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        aria-label={`Decision notes for ${app.id}`}
                        placeholder="Decision rationale..."
                        value={notesById[app.id] ?? ''}
                        onChange={(e) =>
                          setNotesById((prev) => ({ ...prev, [app.id]: e.target.value }))
                        }
                        className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs"
                      />
                      <button
                        type="button"
                        disabled={!canApprove || busy}
                        onClick={() => handleDecision(app.id, 'approved')}
                        className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-40"
                      >
                        <Check className="h-3.5 w-3.5" />
                        Approve
                      </button>
                      <button
                        type="button"
                        disabled={!canApprove || busy}
                        onClick={() => handleDecision(app.id, 'rejected')}
                        className="inline-flex items-center gap-1 rounded-lg border border-rose-300 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-100 disabled:opacity-40"
                      >
                        <X className="h-3.5 w-3.5" />
                        Reject
                      </button>
                    </div>
                  )}
                </div>
              </article>
            ))
          )}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <EyeOff className="h-4 w-4 text-indigo-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Outbound Cloud PII &amp; Credential Redaction Guard
            </h3>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={handleTestPii}
            className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
          >
            Test Redaction
          </button>
        </div>

        <textarea
          aria-label="PII Redaction Input"
          rows={2}
          value={piiInput}
          onChange={(e) => setPiiInput(e.target.value)}
          className="mt-3 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
        />

        {piiResult && (
          <div className="mt-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs">
            <p className="font-semibold text-emerald-900">
              Redacted {piiResult.total_redactions} secret/PII token(s):
            </p>
            <p className="mt-1 font-mono text-[11px] text-emerald-950">
              {piiResult.redacted_text}
            </p>
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Tamper-Evident SHA-256 Audit Chain ({auditEvents.length} Events)
            </h3>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={handleVerifyChain}
            className="rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-800 hover:bg-emerald-100"
          >
            Verify Integrity
          </button>
        </div>

        {chainStatus && (
          <div
            className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
              chainStatus.valid
                ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                : 'border-rose-200 bg-rose-50 text-rose-900'
            }`}
          >
            <span className="font-semibold">{chainStatus.message}</span> · Head hash:{' '}
            <code className="font-mono text-[11px]">{chainStatus.head_hash.slice(0, 16)}...</code>
          </div>
        )}

        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 text-[11px] uppercase text-slate-500">
              <tr>
                <th className="py-2 pr-3">Seq</th>
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Actor</th>
                <th className="py-2 pr-3">Target</th>
                <th className="py-2">Event Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {auditEvents.slice(0, 15).map((ev) => (
                <tr key={ev.id}>
                  <td className="py-2 pr-3 font-mono font-semibold text-slate-900">
                    #{ev.sequence_no}
                  </td>
                  <td className="py-2 pr-3 text-slate-800">
                    <span className="font-semibold">{ev.event_type}</span> ({ev.action})
                  </td>
                  <td className="py-2 pr-3 text-slate-600">
                    {ev.actor_email} ({ev.actor_role})
                  </td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-slate-600">
                    {ev.entity_type}
                  </td>
                  <td className="py-2 font-mono text-[11px] text-slate-500">
                    {ev.event_hash.slice(0, 14)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
