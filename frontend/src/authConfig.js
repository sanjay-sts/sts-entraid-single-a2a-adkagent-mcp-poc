import { LogLevel } from '@azure/msal-browser';

export const msalConfig = {
  auth: {
    clientId: process.env.REACT_APP_ENTRA_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.REACT_APP_ENTRA_TENANT_ID}`,
    redirectUri: 'http://localhost:10003',
    postLogoutRedirectUri: 'http://localhost:10003',
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        if (level === LogLevel.Error) console.error(message);
        if (level === LogLevel.Warning) console.warn(message);
      },
      logLevel: LogLevel.Warning,
    },
  },
};

// Custom API scope for your backend (you need to create this in Azure Portal)
const API_SCOPE = `api://${process.env.REACT_APP_ENTRA_CLIENT_ID}/access_as_user`;

export const loginRequest = {
  scopes: ['openid', 'profile', 'User.Read'],
};

// Scopes for calling your backend API (includes custom scope + Graph scopes)
export const graphScopes = {
  basic: [API_SCOPE, 'User.Read'],
  files: [API_SCOPE, 'User.Read', 'Files.Read'],
  email: [API_SCOPE, 'User.Read', 'Mail.Send'],
  full: [API_SCOPE, 'User.Read', 'Files.Read', 'Mail.Send'],
  destructive: [API_SCOPE, 'User.Read', 'Files.Read', 'Files.ReadWrite.All', 'Mail.Send'],
};
