interface StatusBadgeProps {
  value: string;
}

const BADGE_STYLES: Record<string, string> = {
  healthy: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  active: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  approved: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  applied: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  remediated: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  resolved: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  sev4: 'border-slate-200 bg-slate-100 text-slate-700',

  degraded: 'border-amber-200 bg-amber-50 text-amber-800',
  onboarding: 'border-indigo-200 bg-indigo-50 text-indigo-700',
  pending: 'border-amber-200 bg-amber-50 text-amber-800',
  pending_approval: 'border-amber-200 bg-amber-50 text-amber-800',
  acknowledged: 'border-amber-200 bg-amber-50 text-amber-800',
  mitigating: 'border-amber-200 bg-amber-50 text-amber-800',
  medium: 'border-amber-200 bg-amber-50 text-amber-800',
  sev3: 'border-amber-200 bg-amber-50 text-amber-800',
  triaged: 'border-indigo-200 bg-indigo-50 text-indigo-700',
  advisory_only: 'border-indigo-200 bg-indigo-50 text-indigo-700',
  draft: 'border-slate-200 bg-slate-100 text-slate-700',

  outage: 'border-rose-200 bg-rose-50 text-rose-700',
  critical: 'border-rose-200 bg-rose-50 text-rose-700',
  sev1: 'border-rose-200 bg-rose-50 text-rose-700',
  firing: 'border-rose-200 bg-rose-50 text-rose-700',
  orphaned: 'border-rose-200 bg-rose-50 text-rose-700',
  terminated: 'border-rose-200 bg-rose-50 text-rose-700',
  rejected: 'border-rose-200 bg-rose-50 text-rose-700',
  high: 'border-orange-200 bg-orange-50 text-orange-800',
  sev2: 'border-orange-200 bg-orange-50 text-orange-800',
  open: 'border-orange-200 bg-orange-50 text-orange-800',

  suspended: 'border-slate-200 bg-slate-100 text-slate-600',
  dismissed: 'border-slate-200 bg-slate-100 text-slate-600',
};

export function StatusBadge({ value }: StatusBadgeProps) {
  const key = value.toLowerCase();
  const classes =
    BADGE_STYLES[key] ?? 'border-slate-200 bg-slate-100 text-slate-700';
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${classes}`}
    >
      {value.replace(/_/g, ' ')}
    </span>
  );
}
