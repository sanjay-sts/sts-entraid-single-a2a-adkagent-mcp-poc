/**
 * Predefined test scenarios covering the tool x scope x role matrix.
 * Each scenario specifies the expected outcome for different roles.
 *
 * graphDependency:
 *   'none'     – tool never calls Graph API (time tools, simulated delete)
 *   'fallback' – calls Graph but falls back to token claims on 401 (get_user_profile)
 *   'required' – calls Graph with no fallback; fails when OBO flow unavailable
 *
 * abacAttrs (optional):
 *   null       – scenario doesn't depend on ABAC attributes
 *   { archiver: true } – scenario requires this ABAC attribute to succeed
 *
 * forceExpectDeny (optional):
 *   true       – always denied regardless of role/attrs (e.g., guardrail forbid)
 */

// Flip to true when OBO is configured: ENTRA_CLIENT_SECRET set in .env,
// Azure app has delegated Graph permissions (User.Read, Files.Read, Mail.Send),
// and admin consent is granted. Graph tools will then use OBO token exchange.
const GRAPH_OBO_ENABLED = true;

const testScenarios = [
  // === get_user_profile ===
  {
    id: 'profile_basic',
    tool: 'get_user_profile',
    scopeKey: 'basic',
    prompt: 'Show my Microsoft profile',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: ['User.Read'],
    graphDependency: 'fallback',
    description: 'Fetch profile with basic scopes',
  },

  // === list_files ===
  {
    id: 'files_basic',
    tool: 'list_files',
    scopeKey: 'basic',
    prompt: 'List my OneDrive files',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: ['Files.Read'],
    graphDependency: 'required',
    description: 'List files with basic scopes (missing Files.Read)',
  },
  {
    id: 'files_correct',
    tool: 'list_files',
    scopeKey: 'files',
    prompt: 'List my OneDrive files',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: ['Files.Read'],
    graphDependency: 'required',
    description: 'List files with files scope',
  },

  // === send_email ===
  {
    id: 'email_basic',
    tool: 'send_email',
    scopeKey: 'basic',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
    graphDependency: 'required',
    description: 'Send email with basic scopes (missing Mail.Send)',
  },
  {
    id: 'email_correct',
    tool: 'send_email',
    scopeKey: 'email',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
    graphDependency: 'required',
    description: 'Send email with email scope',
  },

  // === delete_resource ===
  {
    id: 'delete_basic',
    tool: 'delete_resource',
    scopeKey: 'basic',
    prompt: 'Delete resource with ID test-resource-123',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Delete resource with basic scopes (simulated)',
  },
  {
    id: 'delete_destructive',
    tool: 'delete_resource',
    scopeKey: 'destructive',
    prompt: 'Delete resource with ID test-resource-123',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Delete resource with destructive scope (simulated)',
  },

  // === get_current_time ===
  {
    id: 'time_current',
    tool: 'get_current_time',
    scopeKey: 'basic',
    prompt: 'What time is it in Tokyo?',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Get current time (admin only, no Graph scopes)',
  },

  // === convert_timezone ===
  {
    id: 'time_convert',
    tool: 'convert_timezone',
    scopeKey: 'basic',
    prompt: 'Convert 3pm EST to PST',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Convert timezone (admin only)',
  },

  // === get_time_difference ===
  {
    id: 'time_diff',
    tool: 'get_time_difference',
    scopeKey: 'basic',
    prompt: 'What is the time difference between New York and London?',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Time difference (admin only)',
  },

  // === Viewer restrictions ===
  {
    id: 'viewer_files',
    tool: 'list_files',
    scopeKey: 'files',
    prompt: 'List my OneDrive files',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: ['Files.Read'],
    graphDependency: 'required',
    description: 'Viewer trying to list files (role denied)',
  },
  {
    id: 'viewer_email',
    tool: 'send_email',
    scopeKey: 'email',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
    graphDependency: 'required',
    description: 'Viewer trying to send email (role denied)',
  },

  // === Developer restrictions ===
  {
    id: 'dev_email',
    tool: 'send_email',
    scopeKey: 'email',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
    graphDependency: 'required',
    description: 'Developer trying to send email (role denied)',
  },
  {
    id: 'dev_time',
    tool: 'get_current_time',
    scopeKey: 'basic',
    prompt: 'What time is it in Tokyo?',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Developer trying time tool (role denied)',
  },

  // === S3 Tools ===
  {
    id: 's3_buckets',
    tool: 'list_s3_buckets',
    scopeKey: 'basic',
    prompt: 'List my S3 buckets',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List S3 buckets (no Graph dependency)',
  },
  {
    id: 's3_objects',
    tool: 'list_s3_objects',
    scopeKey: 'basic',
    prompt: 'List objects in bucket sts-use1-mcp-poc-data',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List S3 objects (no Graph dependency)',
  },
  {
    id: 's3_info',
    tool: 'get_s3_object_info',
    scopeKey: 'basic',
    prompt: 'Get info about sample.txt in bucket sts-use1-mcp-poc-data',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Get S3 object metadata (all roles)',
  },
  {
    id: 'viewer_s3_buckets',
    tool: 'list_s3_buckets',
    scopeKey: 'basic',
    prompt: 'List my S3 buckets',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Viewer trying to list S3 buckets (role denied)',
  },

  // === delete_s3_object (Cedar ABAC-only — no RBAC role grants access) ===
  // Only users with archiver=true attribute can delete, and only in archive/ path.
  // Admin role alone is NOT sufficient. Guardrail forbids protected/ for everyone.
  {
    id: 's3_delete_admin_archive',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file archive/old-report.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: [],
    requiredScopes: [],
    graphDependency: 'none',
    forceExpectDeny: true,
    description: 'Admin delete in archive/ (ABAC deny — no archiver attr)',
  },
  {
    id: 's3_delete_admin_protected',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file protected/critical.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: [],
    requiredScopes: [],
    graphDependency: 'none',
    forceExpectDeny: true,
    description: 'Admin delete in protected/ (guardrail forbid)',
  },
  {
    id: 's3_delete_archiver_archive',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file archive/old-report.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    abacAttrs: { archiver: true },
    requiredScopes: [],
    graphDependency: 'none',
    description: 'archiver=true delete in archive/ (ABAC allow)',
  },
  {
    id: 's3_delete_archiver_protected',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file protected/critical.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: [],
    abacAttrs: { archiver: true },
    requiredScopes: [],
    graphDependency: 'none',
    forceExpectDeny: true,
    description: 'archiver=true delete in protected/ (guardrail forbid)',
  },
  {
    id: 's3_delete_archiver_normal',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file data/file.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: [],
    abacAttrs: { archiver: true },
    requiredScopes: [],
    graphDependency: 'none',
    forceExpectDeny: true,
    description: 'archiver=true delete in data/ (ABAC deny — wrong path)',
  },
  {
    id: 's3_delete_no_archiver',
    tool: 'delete_s3_object',
    scopeKey: 'basic',
    prompt: 'Delete the file archive/old-report.csv from bucket sts-use1-mcp-poc-data',
    rolesAllowed: [],
    requiredScopes: [],
    graphDependency: 'none',
    forceExpectDeny: true,
    description: 'Any role without archiver attr (ABAC deny)',
  },

  // === ServiceNow tools ===
  // NOTE: dept-scoped tools (list_articles, list_incidents, create_incident,
  // update_incident) use the user's `department` claim at runtime; expected
  // outcome below reflects ROLE only. Cross-dept denials are visible in the
  // result/audit log when the user's dept differs from the target KB/incident.
  {
    id: 'sn_kb_list',
    tool: 'list_knowledge_bases',
    scopeKey: 'basic',
    prompt: 'List the available ServiceNow knowledge bases',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List ServiceNow KBs (role-only RBAC)',
  },
  {
    id: 'sn_articles_it_admin_or_dept_match',
    tool: 'list_articles',
    scopeKey: 'basic',
    prompt: 'List the articles in the IT KB',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List IT articles (admin: always; dev/viewer: only if dept=IT)',
  },
  {
    id: 'sn_articles_hr_admin_or_dept_match',
    tool: 'list_articles',
    scopeKey: 'basic',
    prompt: 'List the articles in the HR KB',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List HR articles (admin: always; dev/viewer: only if dept=HR)',
  },
  {
    id: 'sn_articles_finance_admin_or_dept_match',
    tool: 'list_articles',
    scopeKey: 'basic',
    prompt: 'List the articles in the Finance KB',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List Finance articles (admin: always; dev/viewer: only if dept=Finance)',
  },
  {
    id: 'sn_get_article',
    tool: 'get_article',
    scopeKey: 'basic',
    prompt: 'Get the ServiceNow article with sys_id art-it-0001',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Fetch one article by sys_id (role-only RBAC)',
  },
  {
    id: 'sn_list_incidents_admin_or_dev',
    tool: 'list_incidents',
    scopeKey: 'basic',
    prompt: 'List my open ServiceNow incidents',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'List incidents (admin always; dev defaults to own dept; viewer never)',
  },
  {
    id: 'sn_list_incidents_viewer_denied',
    tool: 'list_incidents',
    scopeKey: 'basic',
    prompt: 'List the ServiceNow incidents for IT',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Viewer never has a permit for list_incidents',
  },
  {
    id: 'sn_get_incident',
    tool: 'get_incident',
    scopeKey: 'basic',
    prompt: 'Get ServiceNow incident inc-it-0001',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Fetch one incident by sys_id (admin/developer)',
  },
  {
    id: 'sn_create_incident_admin_or_dev',
    tool: 'create_incident',
    scopeKey: 'basic',
    prompt: 'Create a ServiceNow incident: "Wi-Fi outage on floor 4"',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Create an incident (admin always; dev with dept context)',
  },
  {
    id: 'sn_update_incident_admin_or_dev',
    tool: 'update_incident',
    scopeKey: 'basic',
    prompt: 'Resolve ServiceNow incident inc-it-0001',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: [],
    graphDependency: 'none',
    description: 'Update an incident (admin always; dev via fetch-then-check dept match)',
  },
];

/**
 * Compute scenarios with `shouldSucceed` based on role, ABAC attributes,
 * Graph OBO status, and the scopes the scenario's scopeKey would request.
 *
 * Decision logic:
 *   1. forceExpectDeny                → TOOL denial (guardrail)
 *   2. Role not allowed              → TOOL denial
 *   3. ABAC required but not met     → TOOL denial
 *   4. OBO disabled + Graph req'd    → RESOURCE denial (Graph 401)
 *   5. Otherwise                     → ALLOW
 */
export function getScenariosForRole(role, activeAbacAttrs = {}) {
  return testScenarios.map(scenario => {
    // Guardrail forbid — always denied regardless of role/attrs
    if (scenario.forceExpectDeny) {
      return { ...scenario, shouldSucceed: false, denialExpected: 'tool' };
    }

    const roleAllowed = scenario.rolesAllowed.includes(role);

    // For ABAC scenarios, check if the active ABAC attrs satisfy requirements
    let abacSatisfied = true;
    if (scenario.abacAttrs && roleAllowed) {
      abacSatisfied = Object.entries(scenario.abacAttrs).every(
        ([key, val]) => activeAbacAttrs[key] === val
      );
    }

    let shouldSucceed;
    let denialExpected;

    if (!roleAllowed) {
      shouldSucceed = false;
      denialExpected = 'tool';
    } else if (!abacSatisfied) {
      shouldSucceed = false;
      denialExpected = 'tool';
    } else if (!GRAPH_OBO_ENABLED && scenario.graphDependency === 'required') {
      shouldSucceed = false;
      denialExpected = 'resource';
    } else {
      shouldSucceed = true;
      denialExpected = null;
    }

    return {
      ...scenario,
      shouldSucceed,
      denialExpected,
    };
  });
}
