import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import type { ApprovalRequestItem, RemediationDraft } from '../types/itAdmin';

function jsonResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  };
}

function createFetchRouter() {
  const approvals: ApprovalRequestItem[] = [
    {
      id: 'app-1',
      entity_type: 'provisioning_plan',
      entity_id: 'plan-1',
      action_requested: 'scim_joiner_provisioning',
      summary: 'Joiner SCIM plan for jordan.rivera@acme-it.local',
      diff_preview_json: [],
      risk_level: 'high',
      status: 'pending',
      requested_by: 'operator@acme-it.local',
      decided_by: null,
      decision_notes: null,
      created_at: '2026-11-24T12:00:00Z',
      decided_at: null,
    },
  ];

  const drafts: RemediationDraft[] = [
    {
      id: 'draft-1',
      incident_id: 'inc-1',
      query_text: 'Auth gateway 5xx surge',
      diagnosis_summary: 'Deterministic advisory remediation plan',
      cited_runbooks_json: [
        {
          runbook_id: 'rb-1',
          slug: 'rb-auth-gateway-5xx-surge',
          title: 'Auth Gateway 5xx Surge',
          service_name: 'auth-gateway',
          score: 0.92,
          excerpt: 'Inspect Redis cache hit ratio.',
        },
      ],
      proposed_steps_json: [
        {
          step_no: 1,
          title: '[rb-auth-gateway-5xx-surge] Check Ready',
          instruction: 'Verify using runbook (read-only).',
          command: 'curl -fsS https://auth.internal.acme/ready',
          requires_manual_execution: true,
        },
      ],
      blocked_shell_patterns_json: [],
      execution_mode: 'advisory_only',
      llm_provider: 'mock',
      pii_redacted: false,
      status: 'draft',
      approval_id: null,
      created_by: 'it-approver@acme-it.local',
      created_at: '2026-11-24T12:00:00Z',
    },
  ];

  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();

    if (url === '/api/v1/health') {
      return jsonResponse({
        status: 'ok',
        service: 'ai-it-admin',
        app_name: 'AI IT Administrator',
        version: '0.1.0',
        environment: 'test',
        llm_provider: 'mock',
        db_ready: true,
      });
    }
    if (url === '/api/v1/overview') {
      return jsonResponse({
        active_users: 5,
        pending_provisioning_plans: 2,
        services_total: 5,
        services_unhealthy: 2,
        expiring_certs_count: 1,
        quota_warnings_count: 1,
        firing_alerts_count: 2,
        open_incidents_count: 2,
        open_access_findings: 4,
        critical_findings_count: 2,
        stale_tokens_count: 2,
        orphaned_accounts_count: 2,
        privilege_drift_count: 2,
        runbooks_count: 5,
        pending_approvals_count: approvals.filter((a) => a.status === 'pending').length,
        audit_events_count: 8,
        audit_chain_valid: true,
        llm_provider: 'mock',
      });
    }
    if (url === '/api/v1/identity/templates') {
      return jsonResponse([
        {
          id: 't-1',
          code: 'eng-backend',
          name: 'Backend Software Engineer',
          department: 'Engineering',
          description: 'Standard engineering access',
          allowed_groups_json: ['okta-engineering'],
          allowed_apps_json: [{ app: 'GitHub', role: 'maintainer', privileged: false }],
          requires_mfa: true,
          created_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }
    if (url === '/api/v1/identity/users') {
      return jsonResponse([
        {
          id: 'u-1',
          employee_id: 'EMP-1001',
          email: 'maya.patel@acme-it.local',
          full_name: 'Maya Patel',
          department: 'Platform',
          title: 'Staff SRE',
          role_template_code: 'eng-sre',
          employment_status: 'active',
          manager_email: 'vp-infra@acme-it.local',
          last_login_at: '2026-11-24T10:00:00Z',
          mfa_enrolled: true,
          created_at: '2026-11-24T09:00:00Z',
          updated_at: '2026-11-24T10:00:00Z',
          active_entitlements_count: 2,
        },
      ]);
    }
    if (url === '/api/v1/identity/plans') {
      return jsonResponse([
        {
          id: 'plan-1',
          plan_type: 'joiner',
          target_email: 'jordan.rivera@acme-it.local',
          target_name: 'Jordan Rivera',
          department: 'Engineering',
          from_role_code: null,
          to_role_code: 'eng-backend',
          scim_provider: 'okta',
          scim_diff_json: [],
          least_privilege_warnings_json: [],
          risk_level: 'high',
          llm_rationale: 'SCIM dry-run reviewed.',
          llm_provider: 'mock',
          status: 'pending_approval',
          approval_id: 'app-1',
          requested_by: 'operator@acme-it.local',
          created_at: '2026-11-24T12:00:00Z',
          applied_at: null,
        },
      ]);
    }
    if (url === '/api/v1/identity/plans/plan-1/scim-payload') {
      return jsonResponse({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
        failOnErrors: 1,
        plan_id: 'plan-1',
        plan_type: 'joiner',
        scim_provider: 'okta',
        Operations: [{ method: 'POST', path: '/Users', bulkId: 'op-1', data: {} }],
      });
    }
    if (url === '/api/v1/identity/plans/preview' && init?.method === 'POST') {
      return jsonResponse({
        id: 'plan-new',
        plan_type: 'joiner',
        target_email: 'taylor.brooks@acme-it.local',
        target_name: 'Taylor Brooks',
        department: 'Engineering',
        from_role_code: null,
        to_role_code: 'eng-backend',
        scim_provider: 'okta',
        scim_diff_json: [],
        least_privilege_warnings_json: [],
        risk_level: 'low',
        llm_rationale: 'SCIM dry-run reviewed.',
        llm_provider: 'mock',
        status: 'pending_approval',
        approval_id: 'app-new',
        requested_by: 'operator@acme-it.local',
        created_at: '2026-11-24T12:00:00Z',
        applied_at: null,
      });
    }
    if (url === '/api/v1/telemetry/services') {
      return jsonResponse([
        {
          id: 'svc-1',
          service_name: 'edge-ingress',
          environment: 'production',
          endpoint_url: 'https://edge.acme-it.local/healthz',
          status: 'healthy',
          latency_ms: 18.5,
          error_rate_pct: 0.01,
          cpu_pct: 24,
          memory_pct: 36,
          quota_used_pct: 51,
          cert_expires_at: '2026-12-05T12:00:00Z',
          last_checked_at: '2026-11-24T12:00:00Z',
          metadata_json: {},
          cert_days_remaining: 11,
          cert_expiring_soon: true,
          quota_warning: false,
          needs_attention: true,
        },
      ]);
    }
    if (url === '/api/v1/telemetry/alerts') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/telemetry/incidents') {
      return jsonResponse([
        {
          id: 'inc-1',
          incident_key: 'INC-1001',
          title: 'Auth Gateway 5xx Surge',
          service_name: 'auth-gateway',
          severity: 'sev2',
          status: 'triaged',
          alert_count: 3,
          deduplicated_fingerprints_json: ['abc123'],
          root_cause_hypothesis: 'JWKS cache contention',
          cited_runbook_ids_json: ['rb-1'],
          recommended_steps_json: ['Check readiness'],
          llm_provider: 'mock',
          pii_redacted: false,
          assigned_to: null,
          created_by: 'it-approver@acme-it.local',
          created_at: '2026-11-24T12:00:00Z',
          updated_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }
    if (url === '/api/v1/access-audit/entitlements') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/access-audit/scans' && init?.method === 'POST') {
      return jsonResponse({
        id: 'scan-1',
        scope: 'all_saas',
        total_entitlements_scanned: 10,
        findings_count: 5,
        critical_count: 2,
        high_count: 2,
        medium_count: 1,
        stale_tokens_count: 2,
        orphaned_accounts_count: 2,
        privilege_drift_count: 1,
        llm_summary: 'Scan complete.',
        llm_provider: 'mock',
        run_by: 'it-approver@acme-it.local',
        created_at: '2026-11-24T12:00:00Z',
      });
    }
    if (url === '/api/v1/access-audit/scans') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/access-audit/findings') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/runbooks') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/runbooks/drafts') {
      return jsonResponse(drafts);
    }
    if (url === '/api/v1/runbooks/assist' && init?.method === 'POST') {
      return jsonResponse(drafts[0]);
    }
    if (url === '/api/v1/governance/approvals') {
      return jsonResponse(approvals);
    }
    if (url === '/api/v1/governance/approvals/app-1/decide' && init?.method === 'POST') {
      approvals[0] = {
        ...approvals[0],
        status: 'approved',
        decided_by: 'it-approver@acme-it.local',
        decision_notes: 'Approved in UI test',
      };
      return jsonResponse(approvals[0]);
    }
    if (url === '/api/v1/governance/audit/events') {
      return jsonResponse([]);
    }
    if (url === '/api/v1/governance/audit/events/verify') {
      return jsonResponse({
        valid: true,
        total_events: 8,
        head_hash: 'deadbeef12345678',
        broken_sequence_no: null,
        message: 'All 8 audit events verified intact.',
      });
    }
    if (url === '/api/v1/integrations/webhooks') {
      return jsonResponse([
        {
          id: 'wh-1',
          name: 'SRE On-Call Slack',
          channel_type: 'slack',
          target_url: 'https://hooks.slack.com/services/T00000000/B00000000/DEMOEXAMPLETOKEN',
          subscribed_events_json: ['incident.triaged'],
          enabled: true,
          signing_secret_configured: false,
          last_delivery_status: null,
          last_delivered_at: null,
          created_by: 'it-approver@acme-it.local',
          created_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }
    if (url === '/api/v1/integrations/webhooks/wh-1/test' && init?.method === 'POST') {
      return jsonResponse({
        webhook_id: 'wh-1',
        channel_type: 'slack',
        target_url: 'https://hooks.slack.com/services/T00000000/B00000000/DEMOEXAMPLETOKEN',
        dry_run: true,
        delivery_status: 'dry_run_ok',
        pii_redacted_count: 2,
        headers_preview: { 'Content-Type': 'application/json' },
        payload_preview: { text: '[AI IT Admin] scrubbed' },
      });
    }
    return jsonResponse({ detail: `Unhandled route: ${url}` }, 404);
  });
}

describe('AI IT Administrator control plane', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders control plane, switches roles, and executes domain workflows', async () => {
    const mockFetch = createFetchRouter();
    vi.stubGlobal('fetch', mockFetch);

    render(<App />);

    expect(
      screen.getByRole('heading', { name: 'AI IT Administrator' }),
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/API Healthy \(mock\)/i)).toBeInTheDocument();
    });
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/health');

    // Switch actor role to operator and confirm header propagation
    const roleSelect = screen.getByLabelText('Actor Role');
    fireEvent.change(roleSelect, { target: { value: 'operator' } });

    await waitFor(() => {
      const callsWithOperator = mockFetch.mock.calls.filter(([, reqInit]) => {
        const headers = new Headers(reqInit?.headers);
        return headers.get('X-Actor-Role') === 'operator';
      });
      expect(callsWithOperator.length).toBeGreaterThan(0);
    });

    // Navigate to Identity & SCIM and preview a dry-run plan
    fireEvent.click(screen.getByRole('button', { name: /Identity & SCIM/i }));
    expect(
      screen.getByText(/Joiner \/ Mover \/ Leaver SCIM Dry-Run Planner/i),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Preview SCIM Dry-Run Plan/i }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/identity/plans/preview',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    // Export SCIM 2.0 RFC 7644 BulkRequest JSON
    fireEvent.click(screen.getByRole('button', { name: /Export SCIM 2\.0 JSON/i }));
    await waitFor(() => {
      expect(screen.getByText(/RFC 7644 SCIM 2\.0 BulkRequest Payload/i)).toBeInTheDocument();
    });

    // Navigate to Health & Triage
    fireEvent.click(screen.getByRole('button', { name: /Health & Triage/i }));
    expect(screen.getByText(/edge-ingress/i)).toBeInTheDocument();

    // Navigate to Access Audits and run scan
    fireEvent.click(screen.getByRole('button', { name: /Access Audits/i }));
    fireEvent.click(screen.getByRole('button', { name: /Run Access Audit Scan/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/access-audit/scans',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    // Navigate to Runbooks RAG and generate advisory plan
    fireEvent.click(screen.getByRole('button', { name: /Runbooks RAG/i }));
    expect(screen.getByText(/advisory only/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Generate Advisory Plan/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/runbooks/assist',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    // Switch back to IT Approver and approve pending gate in Approvals & Audit
    fireEvent.change(roleSelect, { target: { value: 'it_approver' } });
    fireEvent.click(screen.getByRole('button', { name: /Approvals & Audit/i }));
    expect(
      screen.getByText(/Joiner SCIM plan for jordan\.rivera@acme-it\.local/i),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/governance/approvals/app-1/decide',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    // Dry-run test notification webhook
    fireEvent.click(screen.getByRole('button', { name: /Dry-Run Test/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/integrations/webhooks/wh-1/test',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });
});
