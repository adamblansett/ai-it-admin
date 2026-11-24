import { useState } from 'react';
import { Activity, AlertOctagon, Flame, Wrench } from 'lucide-react';
import {
  ingestAlert,
  triageIncident,
  updateIncidentStatus,
} from '../api/client';
import type {
  ActorContext,
  Incident,
  ServiceCheck,
  TelemetryAlert,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface TelemetryViewProps {
  actor: ActorContext;
  services: ServiceCheck[];
  alerts: TelemetryAlert[];
  incidents: Incident[];
  onRefresh: () => Promise<void>;
  onNotify: (text: string, isError?: boolean) => void;
}

export function TelemetryView({
  actor,
  services,
  alerts,
  incidents,
  onRefresh,
  onNotify,
}: TelemetryViewProps) {
  const [serviceName, setServiceName] = useState('auth-gateway');
  const [alertName, setAlertName] = useState('http_5xx_rate_high');
  const [source, setSource] = useState<
    'prometheus' | 'healthcheck' | 'cert_monitor' | 'quota_monitor'
  >('prometheus');
  const [severity, setSeverity] = useState<'sev1' | 'sev2' | 'sev3' | 'sev4'>('sev2');
  const [metricValue, setMetricValue] = useState('9.2');
  const [summary, setSummary] = useState(
    'Auth Gateway 5xx errors spiking above 5% SLO threshold.',
  );
  const [busy, setBusy] = useState(false);

  const firingAlerts = alerts.filter((a) => a.status === 'firing');
  const canMutate = actor.role !== 'viewer';

  async function handleIngestAlert(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await ingestAlert(actor, {
        service_name: serviceName.trim(),
        alert_name: alertName.trim(),
        source,
        severity,
        metric_value: Number(metricValue) || 0,
        threshold_value: 5.0,
        summary: summary.trim(),
      });
      onNotify(
        res.deduplicated
          ? `Alert deduplicated by fingerprint (occurrences: ${res.alert.occurrence_count}).`
          : `New alert created (${res.alert.fingerprint.slice(0, 8)}).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Alert ingestion failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleTriage(targetService?: string) {
    setBusy(true);
    try {
      const inc = await triageIncident(actor, {
        service_name: targetService || null,
      });
      onNotify(
        `Triaged ${inc.incident_key} (${inc.severity.toUpperCase()}) with ${inc.cited_runbook_ids_json.length} cited runbook(s).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Incident triage failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleIncidentStatus(
    incidentId: string,
    status: 'mitigating' | 'resolved',
  ) {
    setBusy(true);
    try {
      const updated = await updateIncidentStatus(actor, incidentId, status, actor.email);
      onNotify(`Incident ${updated.incident_key} transitioned to ${updated.status}.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Status update failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-indigo-600" />
            <h2 className="text-sm font-semibold text-slate-900">
              Service Health, TLS Certificates &amp; Quota Monitoring ({services.length})
            </h2>
          </div>
          <button
            type="button"
            disabled={busy || !canMutate || firingAlerts.length === 0}
            onClick={() => handleTriage()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <Wrench className="h-3.5 w-3.5" />
            Triage Firing Alerts ({firingAlerts.length})
          </button>
        </div>

        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 text-[11px] uppercase text-slate-500">
              <tr>
                <th className="py-2 pr-3">Service</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Latency / Error</th>
                <th className="py-2 pr-3">Quota Used</th>
                <th className="py-2 pr-3">TLS Cert Expiry</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {services.map((svc) => (
                <tr key={svc.id}>
                  <td className="py-2.5 pr-3">
                    <div className="font-semibold text-slate-900">{svc.service_name}</div>
                    <div className="text-[11px] text-slate-500">{svc.endpoint_url}</div>
                  </td>
                  <td className="py-2.5 pr-3">
                    <StatusBadge value={svc.status} />
                  </td>
                  <td className="py-2.5 pr-3 text-slate-700">
                    {svc.latency_ms.toFixed(0)} ms · {svc.error_rate_pct.toFixed(2)}% err
                  </td>
                  <td className="py-2.5 pr-3">
                    <span
                      className={`font-semibold ${
                        svc.quota_warning ? 'text-rose-700' : 'text-slate-700'
                      }`}
                    >
                      {svc.quota_used_pct.toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    {svc.cert_days_remaining === null ? (
                      '—'
                    ) : (
                      <span
                        className={`font-semibold ${
                          svc.cert_expiring_soon ? 'text-amber-700' : 'text-slate-700'
                        }`}
                      >
                        {svc.cert_days_remaining}d remaining
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2">
            <Flame className="h-4 w-4 text-amber-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Ingest &amp; Deduplicate Alert
            </h3>
          </div>
          <p className="mt-1 text-xs text-slate-600">
            Repeating matching alerts increment the existing fingerprint occurrence counter instead
            of flooding responders.
          </p>

          <form onSubmit={handleIngestAlert} className="mt-3 grid gap-2.5 sm:grid-cols-2">
            <input
              aria-label="Alert Service Name"
              value={serviceName}
              onChange={(e) => setServiceName(e.target.value)}
              placeholder="service_name"
              required
              className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            />
            <input
              aria-label="Alert Name"
              value={alertName}
              onChange={(e) => setAlertName(e.target.value)}
              placeholder="alert_name"
              required
              className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            />
            <select
              aria-label="Alert Source"
              value={source}
              onChange={(e) =>
                setSource(
                  e.target.value as
                    | 'prometheus'
                    | 'healthcheck'
                    | 'cert_monitor'
                    | 'quota_monitor',
                )
              }
              className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
            >
              <option value="prometheus">Prometheus</option>
              <option value="healthcheck">Healthcheck</option>
              <option value="cert_monitor">Cert Monitor</option>
              <option value="quota_monitor">Quota Monitor</option>
            </select>
            <div className="flex gap-2">
              <select
                aria-label="Alert Severity"
                value={severity}
                onChange={(e) =>
                  setSeverity(e.target.value as 'sev1' | 'sev2' | 'sev3' | 'sev4')
                }
                className="w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
              >
                <option value="sev1">SEV1</option>
                <option value="sev2">SEV2</option>
                <option value="sev3">SEV3</option>
                <option value="sev4">SEV4</option>
              </select>
              <input
                aria-label="Metric Value"
                value={metricValue}
                onChange={(e) => setMetricValue(e.target.value)}
                className="w-20 rounded-lg border border-slate-300 px-2 py-1.5 text-xs"
              />
            </div>
            <input
              aria-label="Alert Summary"
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              required
              className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs sm:col-span-2"
            />
            <button
              type="submit"
              disabled={busy || !canMutate}
              className="rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50 sm:col-span-2"
            >
              Send Telemetry Alert
            </button>
          </form>

          <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Deduplicated Alert Stream ({alerts.length})
          </h4>
          <ul className="mt-2 space-y-2">
            {alerts.map((al) => (
              <li
                key={al.id}
                className="flex items-start justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 p-2.5 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-900">
                      {al.service_name} · {al.alert_name}
                    </span>
                    <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-bold text-indigo-800">
                      ×{al.occurrence_count}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-slate-600">{al.summary}</p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <StatusBadge value={al.severity} />
                  <StatusBadge value={al.status} />
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-rose-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Triaged Incidents ({incidents.length})
            </h3>
          </div>
          <div className="mt-3 space-y-3">
            {incidents.length === 0 ? (
              <p className="text-xs text-slate-500">No incidents created yet.</p>
            ) : (
              incidents.map((inc) => (
                <article
                  key={inc.id}
                  className="rounded-lg border border-slate-200 bg-slate-50 p-3.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-indigo-700">
                        {inc.incident_key}
                      </span>
                      <StatusBadge value={inc.severity} />
                      <StatusBadge value={inc.status} />
                    </div>
                    {inc.status !== 'resolved' && canMutate && (
                      <div className="flex gap-1.5">
                        {inc.status !== 'mitigating' && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => handleIncidentStatus(inc.id, 'mitigating')}
                            className="rounded border border-amber-300 bg-amber-50 px-2 py-1 text-[11px] font-semibold text-amber-800"
                          >
                            Mitigate
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => handleIncidentStatus(inc.id, 'resolved')}
                          className="rounded bg-emerald-600 px-2 py-1 text-[11px] font-semibold text-white"
                        >
                          Resolve
                        </button>
                      </div>
                    )}
                  </div>
                  <h4 className="mt-1.5 text-xs font-semibold text-slate-900">{inc.title}</h4>
                  <p className="mt-1 text-[11px] leading-relaxed text-slate-600">
                    {inc.root_cause_hypothesis}
                  </p>
                  <p className="mt-1.5 text-[11px] text-slate-500">
                    Alerts correlated: {inc.alert_count} · Cited runbooks:{' '}
                    {inc.cited_runbook_ids_json.length}
                  </p>
                </article>
              ))
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
