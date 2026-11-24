import {
  Activity,
  AlertTriangle,
  BookOpen,
  Database,
  KeyRound,
  ShieldCheck,
  Users,
} from 'lucide-react';
import type {
  ApprovalRequestItem,
  OverviewSummary,
  ServiceCheck,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface OverviewViewProps {
  overview: OverviewSummary | null;
  approvals: ApprovalRequestItem[];
  services: ServiceCheck[];
  onNavigate: (tab: string) => void;
  onLoadDemo: () => void;
  busy: boolean;
}

export function OverviewView({
  overview,
  approvals,
  services,
  onNavigate,
  onLoadDemo,
  busy,
}: OverviewViewProps) {
  const pendingApprovals = approvals.filter((a) => a.status === 'pending');
  const attentionServices = services.filter((s) => s.needs_attention);

  const cards = [
    {
      label: 'Active Directory Users',
      value: overview ? String(overview.active_users) : '—',
      sub: `${overview?.pending_provisioning_plans ?? 0} pending SCIM plans`,
      icon: Users,
      tab: 'identity',
    },
    {
      label: 'Services Monitored',
      value: overview ? `${overview.services_total - overview.services_unhealthy}/${overview.services_total}` : '—',
      sub: `${overview?.expiring_certs_count ?? 0} certs expiring · ${overview?.quota_warnings_count ?? 0} quota alerts`,
      icon: Activity,
      tab: 'telemetry',
    },
    {
      label: 'Open Incidents / Alerts',
      value: overview ? `${overview.open_incidents_count} / ${overview.firing_alerts_count}` : '—',
      sub: 'Deduplicated alerts & runbook triage',
      icon: AlertTriangle,
      tab: 'telemetry',
    },
    {
      label: 'Access Audit Findings',
      value: overview ? String(overview.open_access_findings) : '—',
      sub: `${overview?.critical_findings_count ?? 0} critical · ${overview?.stale_tokens_count ?? 0} stale tokens`,
      icon: KeyRound,
      tab: 'access_audit',
    },
    {
      label: 'Indexed Runbooks',
      value: overview ? String(overview.runbooks_count) : '—',
      sub: 'Advisory-only zero-blind-shell RAG',
      icon: BookOpen,
      tab: 'runbooks',
    },
    {
      label: 'Pending HITL Gates',
      value: overview ? String(overview.pending_approvals_count) : '—',
      sub: overview?.audit_chain_valid ? 'SHA-256 audit chain verified' : 'Check audit chain',
      icon: ShieldCheck,
      tab: 'governance',
    },
  ];

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              IT Operations &amp; Security Control Plane
            </h2>
            <p className="mt-1 text-xs text-slate-600">
              Self-hosted AI IT administration for Joiner/Mover/Leaver SCIM diffs, health &amp;
              certificate monitoring, SaaS access audits, and advisory runbook remediation.
            </p>
          </div>
          <button
            type="button"
            onClick={onLoadDemo}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <Database className="h-3.5 w-3.5" />
            {busy ? 'Initializing...' : 'Load Demo Environment'}
          </button>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <button
              key={card.label}
              type="button"
              onClick={() => onNavigate(card.tab)}
              className="flex flex-col rounded-xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:border-indigo-300"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">{card.label}</span>
                <Icon className="h-4 w-4 text-indigo-600" />
              </div>
              <span className="mt-2 text-2xl font-bold text-slate-900">{card.value}</span>
              <span className="mt-1 text-xs text-slate-600">{card.sub}</span>
            </button>
          );
        })}
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Pending Approval Queue ({pendingApprovals.length})
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('governance')}
              className="text-xs font-semibold text-indigo-600 hover:underline"
            >
              Review All
            </button>
          </div>
          {pendingApprovals.length === 0 ? (
            <p className="mt-3 text-xs text-slate-500">
              No pending approval requests. Load the demo environment or preview a SCIM plan.
            </p>
          ) : (
            <ul className="mt-3 space-y-2.5">
              {pendingApprovals.slice(0, 4).map((item) => (
                <li
                  key={item.id}
                  className="flex items-start justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 p-3"
                >
                  <div>
                    <p className="text-xs font-semibold text-slate-900">{item.summary}</p>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      {item.entity_type} · requested by {item.requested_by}
                    </p>
                  </div>
                  <StatusBadge value={item.risk_level} />
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Infrastructure Alerts Snapshot ({attentionServices.length} Services)
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('telemetry')}
              className="text-xs font-semibold text-indigo-600 hover:underline"
            >
              Open Telemetry
            </button>
          </div>
          {attentionServices.length === 0 ? (
            <p className="mt-3 text-xs text-slate-500">
              All monitored services are healthy within cert and quota thresholds.
            </p>
          ) : (
            <ul className="mt-3 space-y-2.5">
              {attentionServices.map((svc) => (
                <li
                  key={svc.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 p-3"
                >
                  <div>
                    <p className="text-xs font-semibold text-slate-900">{svc.service_name}</p>
                    <p className="mt-0.5 text-[11px] text-slate-600">
                      Quota: {svc.quota_used_pct.toFixed(0)}% · Error: {svc.error_rate_pct.toFixed(1)}%
                      {svc.cert_days_remaining !== null && ` · Cert: ${svc.cert_days_remaining}d`}
                    </p>
                  </div>
                  <StatusBadge value={svc.status} />
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>
    </div>
  );
}
