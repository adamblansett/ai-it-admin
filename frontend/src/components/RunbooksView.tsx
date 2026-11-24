import { useState } from 'react';
import { BookOpen, Search, ShieldBan, Terminal } from 'lucide-react';
import {
  createRunbook,
  requestRemediationAssist,
  searchRunbooks,
} from '../api/client';
import type {
  ActorContext,
  Incident,
  RemediationDraft,
  RunbookItem,
  RunbookSearchHit,
} from '../types/itAdmin';
import { StatusBadge } from './StatusBadge';

interface RunbooksViewProps {
  actor: ActorContext;
  runbooks: RunbookItem[];
  incidents: Incident[];
  drafts: RemediationDraft[];
  onRefresh: () => Promise<void>;
  onNotify: (text: string, isError?: boolean) => void;
}

export function RunbooksView({
  actor,
  runbooks,
  incidents,
  drafts,
  onRefresh,
  onNotify,
}: RunbooksViewProps) {
  const [queryText, setQueryText] = useState(
    'Investigate auth-gateway 5xx surge and JWKS cache saturation',
  );
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [requestApproval, setRequestApproval] = useState(true);
  const [searchHits, setSearchHits] = useState<RunbookSearchHit[]>([]);
  const [showNewForm, setShowNewForm] = useState(false);

  const [newSlug, setNewSlug] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [newService, setNewService] = useState('payments-api');
  const [newMarkdown, setNewMarkdown] = useState(
    '# Remediation Runbook\nVerify readiness probe and inspect downstream queue lag.',
  );
  const [busy, setBusy] = useState(false);

  const canMutate = actor.role !== 'viewer';

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const hits = await searchRunbooks(actor, queryText.trim(), null, 3);
      setSearchHits(hits);
      onNotify(`Found ${hits.length} matching runbook(s).`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Runbook search failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerateRemediation() {
    setBusy(true);
    try {
      const draft = await requestRemediationAssist(actor, {
        query_text: queryText.trim(),
        incident_id: selectedIncidentId || null,
        request_approval: requestApproval,
      });
      onNotify(
        `Generated advisory-only remediation draft (${draft.cited_runbooks_json.length} cited runbook(s)).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Remediation generation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateRunbook(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await createRunbook(actor, {
        slug: newSlug.trim(),
        title: newTitle.trim(),
        service_name: newService.trim(),
        category: 'incident',
        severity_scope: 'sev1,sev2',
        content_markdown: newMarkdown.trim(),
        safe_commands: [
          {
            label: 'Check Service Readiness',
            command: `curl -fsS https://${newService.trim()}.internal/ready`,
            read_only: true,
          },
        ],
        tags: [newService.trim(), 'incident'],
      });
      setNewSlug('');
      setNewTitle('');
      setShowNewForm(false);
      onNotify('Indexed new operational runbook.');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to create runbook', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-indigo-600" />
              <h2 className="text-sm font-semibold text-slate-900">
                RAG Runbook Search &amp; Advisory Remediation Assistant
              </h2>
            </div>
            <p className="mt-1 text-xs text-slate-600">
              Retrieves cited operational runbooks using deterministic hybrid search and enforces
              zero blind shell execution (<span className="font-mono">advisory_only</span>).
            </p>
          </div>
          <button
            type="button"
            disabled={!canMutate}
            onClick={() => setShowNewForm((prev) => !prev)}
            className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-50"
          >
            {showNewForm ? 'Close Form' : '+ Add Runbook'}
          </button>
        </div>

        {showNewForm && (
          <form
            onSubmit={handleCreateRunbook}
            className="mt-4 grid gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 sm:grid-cols-3"
          >
            <input
              aria-label="Runbook Slug"
              placeholder="rb-payments-timeout"
              required
              value={newSlug}
              onChange={(e) => setNewSlug(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs"
            />
            <input
              aria-label="Runbook Title"
              placeholder="Payments API Upstream Timeout"
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs"
            />
            <input
              aria-label="Runbook Service"
              placeholder="payments-api"
              required
              value={newService}
              onChange={(e) => setNewService(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs"
            />
            <textarea
              aria-label="Runbook Markdown"
              rows={3}
              required
              value={newMarkdown}
              onChange={(e) => setNewMarkdown(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs sm:col-span-3"
            />
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white sm:col-span-3"
            >
              Index Runbook
            </button>
          </form>
        )}

        <form onSubmit={handleSearch} className="mt-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <input
              aria-label="Runbook Symptom Query"
              value={queryText}
              onChange={(e) => setQueryText(e.target.value)}
              placeholder="Describe incident symptom or error signature..."
              className="rounded-lg border border-slate-300 px-3 py-2 text-xs sm:col-span-2"
            />
            <select
              aria-label="Target Incident"
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="rounded-lg border border-slate-300 px-2.5 py-2 text-xs"
            >
              <option value="">No specific incident</option>
              {incidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.incident_key} — {inc.service_name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="inline-flex items-center gap-1.5 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={requestApproval}
                onChange={(e) => setRequestApproval(e.target.checked)}
              />
              Queue draft for change-control approval
            </label>
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              >
                <Search className="h-3.5 w-3.5" />
                Search Runbooks
              </button>
              <button
                type="button"
                disabled={busy || !canMutate}
                onClick={handleGenerateRemediation}
                className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
              >
                <Terminal className="h-3.5 w-3.5" />
                Generate Advisory Plan
              </button>
            </div>
          </div>
        </form>

        {searchHits.length > 0 && (
          <div className="mt-4 space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Top Cited Search Results
            </h3>
            {searchHits.map((hit) => (
              <div
                key={hit.runbook_id}
                className="rounded-lg border border-indigo-100 bg-indigo-50/50 p-3 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-indigo-950">
                    {hit.title} ({hit.service_name})
                  </span>
                  <span className="font-mono text-[11px] font-bold text-indigo-700">
                    score {hit.score.toFixed(2)}
                  </span>
                </div>
                <p className="mt-1 text-slate-700">{hit.excerpt}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-900">
          Advisory Remediation Drafts ({drafts.length})
        </h3>
        {drafts.map((draft) => (
          <article
            key={draft.id}
            className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-semibold text-slate-900">{draft.query_text}</p>
              <div className="flex items-center gap-1.5">
                <StatusBadge value={draft.execution_mode} />
                <StatusBadge value={draft.status} />
              </div>
            </div>

            <p className="mt-2 text-xs text-slate-600">{draft.diagnosis_summary}</p>

            {draft.blocked_shell_patterns_json.length > 0 && (
              <div className="mt-2.5 rounded-lg border border-rose-200 bg-rose-50 p-2.5 text-xs text-rose-800">
                <div className="flex items-center gap-1.5 font-semibold">
                  <ShieldBan className="h-3.5 w-3.5" />
                  Zero-Blind-Shell Guardrail Blocked Unsafe Patterns
                </div>
                <ul className="mt-1 list-disc pl-4 text-[11px]">
                  {draft.blocked_shell_patterns_json.map((p, idx) => (
                    <li key={idx}>{p}</li>
                  ))}
                </ul>
              </div>
            )}

            <ol className="mt-3 space-y-2">
              {draft.proposed_steps_json.map((step) => (
                <li
                  key={step.step_no}
                  className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900">
                      {step.step_no}. {step.title}
                    </span>
                    <span className="text-[10px] font-semibold uppercase text-indigo-700">
                      Manual Operator Step
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-slate-600">{step.instruction}</p>
                  {step.command && (
                    <code className="mt-1.5 block rounded bg-slate-900 px-2.5 py-1.5 font-mono text-[11px] text-emerald-300">
                      {step.command}
                    </code>
                  )}
                </li>
              ))}
            </ol>
          </article>
        ))}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-900">
          Runbook Library ({runbooks.length})
        </h3>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {runbooks.map((rb) => (
            <div key={rb.id} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-900">{rb.title}</span>
                <span className="font-mono text-[11px] text-indigo-700">{rb.service_name}</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-600">{rb.slug}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
