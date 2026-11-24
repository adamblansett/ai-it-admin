export type ActorRole = 'viewer' | 'operator' | 'it_approver' | 'admin';

export interface ActorContext {
  email: string;
  role: ActorRole;
}

export interface HealthStatus {
  status: string;
  service: string;
  app_name: string;
  version: string;
  environment: string;
  llm_provider: string;
  db_ready?: boolean;
}

export interface OverviewSummary {
  active_users: number;
  pending_provisioning_plans: number;
  services_total: number;
  services_unhealthy: number;
  expiring_certs_count: number;
  quota_warnings_count: number;
  firing_alerts_count: number;
  open_incidents_count: number;
  open_access_findings: number;
  critical_findings_count: number;
  stale_tokens_count: number;
  orphaned_accounts_count: number;
  privilege_drift_count: number;
  runbooks_count: number;
  pending_approvals_count: number;
  audit_events_count: number;
  audit_chain_valid: boolean;
  llm_provider: string;
}

export interface RoleAppGrant {
  app: string;
  role: string;
  privileged: boolean;
}

export interface RoleTemplate {
  id: string;
  code: string;
  name: string;
  department: string;
  description: string;
  allowed_groups_json: string[];
  allowed_apps_json: RoleAppGrant[];
  requires_mfa: boolean;
  created_at: string;
}

export interface DirectoryUser {
  id: string;
  employee_id: string;
  email: string;
  full_name: string;
  department: string;
  title: string;
  role_template_code: string | null;
  employment_status: string;
  manager_email: string;
  last_login_at: string | null;
  mfa_enrolled: boolean;
  created_at: string;
  updated_at: string;
  active_entitlements_count: number;
}

export interface ScimOperation {
  action: string;
  resource_type: string;
  target: string;
  details: Record<string, unknown>;
  privileged: boolean;
}

export interface ProvisioningPlan {
  id: string;
  plan_type: 'joiner' | 'mover' | 'leaver' | string;
  target_email: string;
  target_name: string;
  department: string;
  from_role_code: string | null;
  to_role_code: string | null;
  scim_provider: string;
  scim_diff_json: ScimOperation[];
  least_privilege_warnings_json: string[];
  risk_level: string;
  llm_rationale: string;
  llm_provider: string;
  status: string;
  approval_id: string | null;
  requested_by: string;
  created_at: string;
  applied_at: string | null;
}

export interface ProvisioningPreviewInput {
  plan_type: 'joiner' | 'mover' | 'leaver';
  target_email: string;
  target_name?: string;
  department?: string;
  from_role_code?: string | null;
  to_role_code?: string | null;
  scim_provider: 'okta' | 'entra_id' | 'google_workspace';
  requested_extra_apps?: RoleAppGrant[];
}

export interface ServiceCheck {
  id: string;
  service_name: string;
  environment: string;
  endpoint_url: string;
  status: 'healthy' | 'degraded' | 'outage' | string;
  latency_ms: number;
  error_rate_pct: number;
  cpu_pct: number;
  memory_pct: number;
  quota_used_pct: number;
  cert_expires_at: string | null;
  last_checked_at: string;
  metadata_json: Record<string, unknown>;
  cert_days_remaining: number | null;
  cert_expiring_soon: boolean;
  quota_warning: boolean;
  needs_attention: boolean;
}

export interface TelemetryAlert {
  id: string;
  fingerprint: string;
  service_name: string;
  alert_name: string;
  source: string;
  severity: string;
  metric_value: number;
  threshold_value: number;
  summary: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  status: string;
  incident_id: string | null;
}

export interface AlertIngestInput {
  service_name: string;
  alert_name: string;
  source: 'prometheus' | 'healthcheck' | 'cert_monitor' | 'quota_monitor';
  severity: 'sev1' | 'sev2' | 'sev3' | 'sev4';
  metric_value: number;
  threshold_value: number;
  summary: string;
}

export interface AlertIngestResult {
  alert: TelemetryAlert;
  deduplicated: boolean;
}

export interface Incident {
  id: string;
  incident_key: string;
  title: string;
  service_name: string;
  severity: string;
  status: string;
  alert_count: number;
  deduplicated_fingerprints_json: string[];
  root_cause_hypothesis: string;
  cited_runbook_ids_json: string[];
  recommended_steps_json: string[];
  llm_provider: string;
  pii_redacted: boolean;
  assigned_to: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface SaaSEntitlement {
  id: string;
  app_name: string;
  user_email: string;
  account_status: string;
  assigned_role: string;
  is_privileged: boolean;
  mfa_enabled: boolean;
  token_created_at: string | null;
  token_last_used_at: string | null;
  last_login_at: string | null;
  expected_by_role: boolean;
  created_at: string;
}

export interface AccessAuditRun {
  id: string;
  scope: string;
  total_entitlements_scanned: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  stale_tokens_count: number;
  orphaned_accounts_count: number;
  privilege_drift_count: number;
  llm_summary: string;
  llm_provider: string;
  run_by: string;
  created_at: string;
}

export interface AccessFinding {
  id: string;
  audit_run_id: string;
  entitlement_id: string;
  finding_type: string;
  severity: string;
  app_name: string;
  user_email: string;
  detail: string;
  recommended_action: string;
  status: string;
  approval_id: string | null;
  created_at: string;
}

export interface SafeCommandItem {
  label: string;
  command: string;
  read_only: boolean;
}

export interface RunbookItem {
  id: string;
  slug: string;
  title: string;
  service_name: string;
  category: string;
  severity_scope: string;
  content_markdown: string;
  safe_commands_json: SafeCommandItem[];
  tags_json: string[];
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface RunbookCreateInput {
  slug: string;
  title: string;
  service_name: string;
  category: string;
  severity_scope: string;
  content_markdown: string;
  safe_commands: SafeCommandItem[];
  tags: string[];
}

export interface RunbookSearchHit {
  runbook_id: string;
  slug: string;
  title: string;
  service_name: string;
  category: string;
  score: number;
  excerpt: string;
  safe_commands: SafeCommandItem[];
}

export interface RemediationStep {
  step_no: number;
  title: string;
  instruction: string;
  command: string | null;
  requires_manual_execution: boolean;
}

export interface CitedRunbook {
  runbook_id: string;
  slug: string;
  title: string;
  service_name: string;
  score: number;
  excerpt: string;
}

export interface RemediationDraft {
  id: string;
  incident_id: string | null;
  query_text: string;
  diagnosis_summary: string;
  cited_runbooks_json: CitedRunbook[];
  proposed_steps_json: RemediationStep[];
  blocked_shell_patterns_json: string[];
  execution_mode: string;
  llm_provider: string;
  pii_redacted: boolean;
  status: string;
  approval_id: string | null;
  created_by: string;
  created_at: string;
}

export interface RemediationAssistInput {
  query_text: string;
  incident_id?: string | null;
  service_name?: string | null;
  request_approval: boolean;
}

export interface ApprovalRequestItem {
  id: string;
  entity_type: string;
  entity_id: string;
  action_requested: string;
  summary: string;
  diff_preview_json: unknown;
  risk_level: string;
  status: string;
  requested_by: string;
  decided_by: string | null;
  decision_notes: string | null;
  created_at: string;
  decided_at: string | null;
}

export interface AuditEventItem {
  id: string;
  sequence_no: number;
  event_type: string;
  actor_email: string;
  actor_role: string;
  entity_type: string;
  entity_id: string;
  action: string;
  details_json: Record<string, unknown>;
  prev_hash: string;
  event_hash: string;
  created_at: string;
}

export interface AuditChainVerify {
  valid: boolean;
  total_events: number;
  head_hash: string;
  broken_sequence_no: number | null;
  message: string;
}

export interface RedactionFinding {
  category: string;
  count: number;
  placeholder: string;
}

export interface PiiRedactResult {
  redacted_text: string;
  findings: RedactionFinding[];
  total_redactions: number;
}

export interface SeedSummary {
  seeded: boolean;
  message: string;
  role_templates?: number;
  directory_users?: number;
  services?: number;
}
