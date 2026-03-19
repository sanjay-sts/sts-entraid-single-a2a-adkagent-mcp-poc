/**
 * AWS Cognito configuration for Amplify Auth v6.
 * Parallel to authConfig.js (Entra ID / MSAL).
 */

export const cognitoConfig = {
  Auth: {
    Cognito: {
      userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID,
      userPoolClientId: process.env.REACT_APP_COGNITO_CLIENT_ID,
      loginWith: {
        oauth: {
          domain: process.env.REACT_APP_COGNITO_DOMAIN,
          scopes: ['openid', 'profile', 'email', 'ai-agent-api/access_as_user'],
          redirectSignIn: ['http://localhost:10003'],
          redirectSignOut: ['http://localhost:10003'],
          responseType: 'code',
        },
      },
    },
  },
};
