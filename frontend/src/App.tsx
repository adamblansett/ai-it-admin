import { useEffect, useState } from 'react';
import { Activity, Cpu, ShieldCheck } from 'lucide-react';

interface HealthStatus {
  status: string;
  service: string;
  app_name: string;
  version: string;
  environment: string;
  llm_provider: string;
}

const PLANNED_CAPABILITIES = [
  { title: 'User Provisioning', summary: 'Joiner/mover/leaver role templates with least-privilege SCIM/Okta change previews.' },
  { title: 'Health Monitoring', summary: 'Service telemetry correlation, certificate/quota warnings, and runbook lookup.' },
  { title: 'Access Control Audits', summary: 'Stale token, orphaned account, and privilege-drift detection across SaaS apps.' },
  { title: 'Incident Triage', summary: 'Alert deduplication, severity classification, and cited root-cause hypotheses.' },
];

export default function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function checkHealth() {
      try {
        const response = await fetch('/api/v1/health');
        if (!response.ok) {
          if (!cancelled) setOffline(true);
          return;
        }
        const payload = (await response.json()) as HealthStatus;
        if (!cancelled) {
          setHealth(payload);
          setOffline(false);
        }
      } catch {
        if (!cancelled) setOffline(true);
      }
    }
    void checkHealth();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-6 py-5">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
              Phase 1 — Core Professional & Enterprise Operations
            </p>
            <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-900">AI IT Administrator</h1>
            <p className="mt-1 text-sm text-slate-600">Open-source, self-hosted AI IT administration platform for user provisioning, infrastructure health monitoring, access control audits, and incident triage ticketing.</p>
          </div>
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
      </header>

      <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">
        <section className="grid gap-4 sm:grid-cols-2">
          {PLANNED_CAPABILITIES.map((item) => (
            <article
              key={item.title}
              className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
            >
              <h2 className="text-sm font-semibold text-slate-900">{item.title}</h2>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{item.summary}</p>
            </article>
          ))}
        </section>

        <section className="grid gap-4 sm:grid-cols-2">
          <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5">
            <Cpu className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600" />
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Local-First LLM Routing</h3>
              <p className="mt-1 text-xs text-slate-600">
                Supports offline deterministic mock execution, local Ollama inference, and guarded
                cloud fallback.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5">
            <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Production Security Baseline</h3>
              <p className="mt-1 text-xs text-slate-600">
                Ships with fail-fast production secret validation, ASGI security headers, and
                human-in-the-loop review boundaries.
              </p>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
