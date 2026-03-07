/**
 * Predefined test scenarios covering the tool x scope x role matrix.
 * Each scenario specifies the expected outcome for different roles.
 */
const testScenarios = [
  // === get_user_profile ===
  {
    id: 'profile_basic',
    tool: 'get_user_profile',
    scopeKey: 'basic',
    prompt: 'Show my Microsoft profile',
    rolesAllowed: ['admin', 'developer', 'viewer'],
    requiredScopes: ['User.Read'],
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
    description: 'List files with basic scopes (missing Files.Read)',
    expectScopeDenial: true,
  },
  {
    id: 'files_correct',
    tool: 'list_files',
    scopeKey: 'files',
    prompt: 'List my OneDrive files',
    rolesAllowed: ['admin', 'developer'],
    requiredScopes: ['Files.Read'],
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
    description: 'Send email with basic scopes (missing Mail.Send)',
    expectScopeDenial: true,
  },
  {
    id: 'email_correct',
    tool: 'send_email',
    scopeKey: 'email',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
    description: 'Send email with email scope',
  },

  // === delete_resource ===
  {
    id: 'delete_basic',
    tool: 'delete_resource',
    scopeKey: 'basic',
    prompt: 'Delete resource with ID test-resource-123',
    rolesAllowed: ['admin'],
    requiredScopes: ['Files.ReadWrite.All'],
    description: 'Delete resource with basic scopes',
    expectScopeDenial: true,
  },
  {
    id: 'delete_destructive',
    tool: 'delete_resource',
    scopeKey: 'destructive',
    prompt: 'Delete resource with ID test-resource-123',
    rolesAllowed: ['admin'],
    requiredScopes: ['Files.ReadWrite.All'],
    description: 'Delete resource with destructive scope',
  },

  // === get_current_time ===
  {
    id: 'time_current',
    tool: 'get_current_time',
    scopeKey: 'basic',
    prompt: 'What time is it in Tokyo?',
    rolesAllowed: ['admin'],
    requiredScopes: [],
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
    description: 'Viewer trying to list files (role denied)',
  },
  {
    id: 'viewer_email',
    tool: 'send_email',
    scopeKey: 'email',
    prompt: 'Send an email to test@example.com with subject "Test" and body "Hello"',
    rolesAllowed: ['admin'],
    requiredScopes: ['Mail.Send'],
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
    description: 'Developer trying to send email (role denied)',
  },
  {
    id: 'dev_time',
    tool: 'get_current_time',
    scopeKey: 'basic',
    prompt: 'What time is it in Tokyo?',
    rolesAllowed: ['admin'],
    requiredScopes: [],
    description: 'Developer trying time tool (role denied)',
  },
];

/**
 * Compute scenarios with `shouldSucceed` based on role + the scopes the
 * scenario's own scopeKey would request (from graphScopes config).
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

    return {
      ...scenario,
      shouldSucceed: roleAllowed && hasScope,
      denialExpected: !roleAllowed ? 'tool' : (!hasScope ? 'scope' : null),
    };
  });
}

export default testScenarios;
