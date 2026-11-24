import type {
  AccessAuditRun,
  AccessFinding,
  ActorContext,
  AlertIngestInput,
  AlertIngestResult,
  ApprovalRequestItem,
  AuditChainVerify,
  AuditEventItem,
  DirectoryUser,
  HealthStatus,
  Incident,
  OverviewSummary,
  PiiRedactResult,
  ProvisioningPlan,
  ProvisioningPreviewInput,
  RemediationAssistInput,
  RemediationDraft,
  RoleTemplate,
  RunbookCreateInput,
  RunbookItem,
  RunbookSearchHit,
  SaaSEntitlement,
  SeedSummary,
  ServiceCheck,
  TelemetryAlert,
} from '../types/itAdmin';

export class ApiClientError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
  }
}

async function requestJson<T>(
  path: string,
  actor: ActorContext,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('X-Actor-Email', actor.email);
  headers.set('X-Actor-Role', actor.role);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as {
        detail?: string | { message?: string };
      };
      if (typeof payload.detail === 'string') {
        message = payload.detail;
      } else if (payload.detail && typeof payload.detail.message === 'string') {
        message = payload.detail.message;
      }
    } catch {
      // ignore non-JSON body
    }
    throw new ApiClientError(message, response.status);
  }
  return (await response.json()) as T;
}

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch('/api/v1/health');
  if (!response.ok) {
    throw new ApiClientError('API health check failed', response.status);
  }
  return (await response.json()) as HealthStatus;
}

export function fetchOverview(actor: ActorContext): Promise<OverviewSummary> {
  return requestJson<OverviewSummary>('/api/v1/overview', actor);
}

export function seedDemoData(actor: ActorContext, reset = false): Promise<SeedSummary> {
  return requestJson<SeedSummary>(`/api/v1/seed/demo?reset=${reset}`, actor, {
    method: 'POST',
  });
}

// Identity & SCIM Provisioning
export function fetchRoleTemplates(actor: ActorContext): Promise<RoleTemplate[]> {
  return requestJson<RoleTemplate[]>('/api/v1/identity/templates', actor);
}

export function fetchDirectoryUsers(actor: ActorContext): Promise<DirectoryUser[]> {
  return requestJson<DirectoryUser[]>('/api/v1/identity/users', actor);
}

export function fetchProvisioningPlans(actor: ActorContext): Promise<ProvisioningPlan[]> {
  return requestJson<ProvisioningPlan[]>('/api/v1/identity/plans', actor);
}

export function previewProvisioningPlan(
  actor: ActorContext,
  payload: ProvisioningPreviewInput,
): Promise<ProvisioningPlan> {
  return requestJson<ProvisioningPlan>('/api/v1/identity/plans/preview', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// Telemetry & Incident Triage
export function fetchServices(actor: ActorContext): Promise<ServiceCheck[]> {
  return requestJson<ServiceCheck[]>('/api/v1/telemetry/services', actor);
}

export function ingestServiceCheck(
  actor: ActorContext,
  payload: {
    service_name: string;
    environment: string;
    endpoint_url: string;
    status: 'healthy' | 'degraded' | 'outage';
    latency_ms: number;
    error_rate_pct: number;
    quota_used_pct: number;
    cert_expires_at?: string | null;
  },
): Promise<ServiceCheck> {
  return requestJson<ServiceCheck>('/api/v1/telemetry/services/ingest', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function fetchAlerts(actor: ActorContext): Promise<TelemetryAlert[]> {
  return requestJson<TelemetryAlert[]>('/api/v1/telemetry/alerts', actor);
}

export function ingestAlert(
  actor: ActorContext,
  payload: AlertIngestInput,
): Promise<AlertIngestResult> {
  return requestJson<AlertIngestResult>('/api/v1/telemetry/alerts/ingest', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function fetchIncidents(actor: ActorContext): Promise<Incident[]> {
  return requestJson<Incident[]>('/api/v1/telemetry/incidents', actor);
}

export function triageIncident(
  actor: ActorContext,
  payload: { service_name?: string | null; alert_ids?: string[]; title?: string | null },
): Promise<Incident> {
  return requestJson<Incident>('/api/v1/telemetry/incidents/triage', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function updateIncidentStatus(
  actor: ActorContext,
  incidentId: string,
  status: 'open' | 'triaged' | 'mitigating' | 'resolved',
  assignedTo?: string | null,
): Promise<Incident> {
  return requestJson<Incident>(`/api/v1/telemetry/incidents/${incidentId}/status`, actor, {
    method: 'PATCH',
    body: JSON.stringify({ status, assigned_to: assignedTo ?? null }),
  });
}

// Access Control Audits
export function fetchEntitlements(actor: ActorContext): Promise<SaaSEntitlement[]> {
  return requestJson<SaaSEntitlement[]>('/api/v1/access-audit/entitlements', actor);
}

export function runAccessAuditScan(
  actor: ActorContext,
  scope = 'all_saas',
): Promise<AccessAuditRun> {
  return requestJson<AccessAuditRun>('/api/v1/access-audit/scans', actor, {
    method: 'POST',
    body: JSON.stringify({ scope }),
  });
}

export function fetchAccessAuditRuns(actor: ActorContext): Promise<AccessAuditRun[]> {
  return requestJson<AccessAuditRun[]>('/api/v1/access-audit/scans', actor);
}

export function fetchAccessFindings(actor: ActorContext): Promise<AccessFinding[]> {
  return requestJson<AccessFinding[]>('/api/v1/access-audit/findings', actor);
}

export function requestFindingRemediation(
  actor: ActorContext,
  findingId: string,
): Promise<AccessFinding> {
  return requestJson<AccessFinding>(
    `/api/v1/access-audit/findings/${findingId}/request-remediation`,
    actor,
    { method: 'POST' },
  );
}

// Runbooks & Advisory Remediation
export function fetchRunbooks(actor: ActorContext): Promise<RunbookItem[]> {
  return requestJson<RunbookItem[]>('/api/v1/runbooks', actor);
}

export function createRunbook(
  actor: ActorContext,
  payload: RunbookCreateInput,
): Promise<RunbookItem> {
  return requestJson<RunbookItem>('/api/v1/runbooks', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function searchRunbooks(
  actor: ActorContext,
  query: string,
  serviceName?: string | null,
  topK = 3,
): Promise<RunbookSearchHit[]> {
  return requestJson<RunbookSearchHit[]>('/api/v1/runbooks/search', actor, {
    method: 'POST',
    body: JSON.stringify({
      query,
      service_name: serviceName || null,
      top_k: topK,
    }),
  });
}

export function requestRemediationAssist(
  actor: ActorContext,
  payload: RemediationAssistInput,
): Promise<RemediationDraft> {
  return requestJson<RemediationDraft>('/api/v1/runbooks/assist', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function fetchRemediationDrafts(actor: ActorContext): Promise<RemediationDraft[]> {
  return requestJson<RemediationDraft[]>('/api/v1/runbooks/drafts', actor);
}

// Governance & HITL Approvals
export function fetchApprovals(actor: ActorContext): Promise<ApprovalRequestItem[]> {
  return requestJson<ApprovalRequestItem[]>('/api/v1/governance/approvals', actor);
}

export function decideApproval(
  actor: ActorContext,
  approvalId: string,
  decision: 'approved' | 'rejected',
  notes: string,
): Promise<ApprovalRequestItem> {
  return requestJson<ApprovalRequestItem>(
    `/api/v1/governance/approvals/${approvalId}/decide`,
    actor,
    {
      method: 'POST',
      body: JSON.stringify({ decision, notes }),
    },
  );
}

export function fetchAuditEvents(actor: ActorContext): Promise<AuditEventItem[]> {
  return requestJson<AuditEventItem[]>('/api/v1/governance/audit/events', actor);
}

export function verifyAuditChain(actor: ActorContext): Promise<AuditChainVerify> {
  return requestJson<AuditChainVerify>('/api/v1/governance/audit/events/verify', actor);
}

export function redactPiiText(actor: ActorContext, text: string): Promise<PiiRedactResult> {
  return requestJson<PiiRedactResult>('/api/v1/governance/pii/redact', actor, {
    method: 'POST',
    body: JSON.stringify({ text }),
  });
}
