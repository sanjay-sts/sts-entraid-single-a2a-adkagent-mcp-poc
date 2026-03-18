/**
 * Predefined test scenarios covering the tool x scope x role matrix.
 * Each scenario specifies the expected outcome for different roles.
 *
 * graphDependency:
 *   'none'     – tool never calls Graph API (time tools, simulated delete)
 *   'fallback' – calls Graph but falls back to token claims on 401 (get_user_profile)
 *   'required' – calls Graph with no fallback; fails when OBO flow unavailable
 */

// Flip to true when OBO is configured: ENTRA_CLIENT_SECRET set in .env,
// Azure app has delegated Graph permissions (User.Read, Files.Read, Mail.Send),
// and admin consent is granted. Graph tools will then use OBO token exchange.
const GRAPH_OBO_ENABLED = false;

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
];

/**
 * Compute scenarios with `shouldSucceed` based on role, Graph OBO status,
 * and the scopes the scenario's scopeKey would request.
 *
 * Decision logic:
 *   1. Role not allowed           → TOOL denial
 *   2. OBO disabled + Graph req'd → RESOURCE denial (Graph 401)
 *   3. OBO enabled + scope miss   → RESOURCE denial (Graph 403)
 *   4. Otherwise                  → ALLOW
 */
export function getScenariosForRole(role) {
  // Import dynamically to avoid circular deps - graphScopes is a plain object
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { graphScopes } = require('../authConfig');

  return testScenarios.map(scenario => {
    const roleAllowed = scenario.rolesAllowed.includes(role);

    // Check scopes that the scenario's scopeKey would provide
    const scenarioScopes = graphScopes[scenario.scopeKey] || [];
    const hasScope = scenario.requiredScopes.length === 0 ||
      scenario.requiredScopes.every(s => scenarioScopes.includes(s));

    let shouldSucceed;
    let denialExpected;

    if (!roleAllowed) {
      // Role check fires first — MCP rejects before Graph is called
      shouldSucceed = false;
      denialExpected = 'tool';
    } else if (!GRAPH_OBO_ENABLED && scenario.graphDependency === 'required') {
      // Role allowed, but Graph API will 401 because OBO isn't implemented
      shouldSucceed = false;
      denialExpected = 'resource';
    } else if (GRAPH_OBO_ENABLED && !hasScope) {
      // OBO works, but the token lacks the required Graph scope
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

export default testScenarios;
