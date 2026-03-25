/**
 * Unified AuthProvider wrapping both MSAL (Entra ID) and Amplify (Cognito).
 *
 * Exposes a single useAuth() hook with provider-agnostic interface:
 *   { provider, isAuthenticated, user, getAccessToken, login, logout }
 *
 * Provider selection is persisted in localStorage.
 */

import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import { PublicClientApplication, EventType, InteractionRequiredAuthError } from '@azure/msal-browser';
import { MsalProvider, useMsal, useAccount } from '@azure/msal-react';
import { Amplify } from 'aws-amplify';
import { signInWithRedirect, signOut, getCurrentUser, fetchAuthSession } from 'aws-amplify/auth';
import { Hub } from 'aws-amplify/utils';
import { msalConfig, loginRequest, graphScopes } from './authConfig';
import { cognitoConfig } from './cognitoConfig';

const PROVIDER_KEY = 'auth_provider';

const AuthContext = createContext({
  provider: null,        // 'entra' | 'cognito' | null
  isAuthenticated: false,
  user: null,            // { email, name }
  getAccessToken: async () => '',
  login: async () => {},
  logout: async () => {},
  switchProvider: () => {},
});

export const useAuth = () => useContext(AuthContext);

// ---------------------------------------------------------------------------
// MSAL singleton — created once, reused
// ---------------------------------------------------------------------------
let msalInstance = null;
let msalInitPromise = null;

function getMsalInstance() {
  if (!msalInstance && process.env.REACT_APP_ENTRA_CLIENT_ID) {
    msalInstance = new PublicClientApplication(msalConfig);
    msalInstance.addEventCallback((event) => {
      if (event.eventType === EventType.LOGIN_SUCCESS && event.payload?.account) {
        msalInstance.setActiveAccount(event.payload.account);
      }
    });
  }
  return msalInstance;
}

// MSAL Browser v3 requires initialize() before any API call
async function ensureMsalReady() {
  const inst = getMsalInstance();
  if (!inst) return null;
  if (!msalInitPromise) {
    msalInitPromise = inst.initialize().then(() => {
      if (!inst.getActiveAccount() && inst.getAllAccounts().length > 0) {
        inst.setActiveAccount(inst.getAllAccounts()[0]);
      }
    });
  }
  await msalInitPromise;
  return inst;
}

// ---------------------------------------------------------------------------
// Amplify — configure once
// ---------------------------------------------------------------------------
let amplifyConfigured = false;
function ensureAmplifyConfigured() {
  if (!amplifyConfigured && process.env.REACT_APP_COGNITO_USER_POOL_ID) {
    Amplify.configure(cognitoConfig);
    amplifyConfigured = true;
  }
}

// ---------------------------------------------------------------------------
// Inner provider for Entra (needs MsalProvider context)
// ---------------------------------------------------------------------------
function EntraAuthInner({ children, onContext }) {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});

  useEffect(() => {
    if (account) {
      onContext({
        provider: 'entra',
        isAuthenticated: true,
        user: { email: account.username, name: account.name || account.username },
        msalInstance: instance,
        msalAccount: account,
      });
    } else {
      onContext({ provider: 'entra', isAuthenticated: false, user: null });
    }
  }, [account, instance, onContext]);

  return children;
}

// ---------------------------------------------------------------------------
// Main AuthProvider
// ---------------------------------------------------------------------------
export default function AuthProvider({ children }) {
  const [provider, setProvider] = useState(() => localStorage.getItem(PROVIDER_KEY) || null);
  const [entraCtx, setEntraCtx] = useState({ isAuthenticated: false, user: null });
  const [cognitoUser, setCognitoUser] = useState(null);
  const [cognitoReady, setCognitoReady] = useState(false);
  const cognitoInitRef = useRef(false);

  // --- Cognito: check current session on mount ---
  useEffect(() => {
    if (provider !== 'cognito') return;
    if (cognitoInitRef.current) return;
    cognitoInitRef.current = true;

    ensureAmplifyConfigured();

    async function checkSession() {
      try {
        const user = await getCurrentUser();
        const session = await fetchAuthSession();
        const idToken = session.tokens?.idToken;
        setCognitoUser({
          email: idToken?.payload?.email || user.signInDetails?.loginId || user.username,
          name: idToken?.payload?.name || idToken?.payload?.email || user.username,
        });
      } catch {
        setCognitoUser(null);
      }
      setCognitoReady(true);
    }
    checkSession();

    // Listen for auth events
    const unsubscribe = Hub.listen('auth', ({ payload }) => {
      if (payload.event === 'signedIn' || payload.event === 'tokenRefresh') {
        checkSession();
      }
      if (payload.event === 'signedOut') {
        setCognitoUser(null);
      }
    });
    return () => unsubscribe();
  }, [provider]);

  // --- Provider switching ---
  const switchProvider = useCallback((p) => {
    if (p) {
      localStorage.setItem(PROVIDER_KEY, p);
    } else {
      localStorage.removeItem(PROVIDER_KEY);
    }
    setProvider(p);
    // Reset Cognito init flag so next mount re-checks
    cognitoInitRef.current = false;
    setCognitoReady(false);
    setCognitoUser(null);
  }, []);

  // --- Login ---
  const login = useCallback(async (targetProvider) => {
    if (targetProvider === 'entra') {
      const inst = await ensureMsalReady();
      if (inst) {
        await inst.loginPopup(loginRequest);
      }
      switchProvider(targetProvider);
    } else if (targetProvider === 'cognito') {
      // Save provider BEFORE redirect — signInWithRedirect navigates away,
      // so any code after it won't execute until the page reloads.
      switchProvider(targetProvider);
      ensureAmplifyConfigured();
      await signInWithRedirect();
    }
  }, [switchProvider]);

  // --- Logout ---
  const logout = useCallback(async () => {
    if (provider === 'entra') {
      const inst = await ensureMsalReady();
      if (inst) {
        await inst.logoutPopup({ postLogoutRedirectUri: '/' });
      }
    } else if (provider === 'cognito') {
      try {
        await signOut();
      } catch { /* ignore */ }
    }
    switchProvider(null);
  }, [provider, switchProvider]);

  // --- Get access token ---
  const getAccessToken = useCallback(async (scopeKey = 'basic') => {
    if (provider === 'entra') {
      const inst = await ensureMsalReady();
      const acct = inst?.getActiveAccount();
      if (!inst || !acct) return '';
      const scopes = graphScopes[scopeKey] || graphScopes.basic;
      try {
        const resp = await inst.acquireTokenSilent({ scopes, account: acct });
        return resp.accessToken;
      } catch (err) {
        if (err instanceof InteractionRequiredAuthError) {
          const resp = await inst.acquireTokenPopup({ scopes });
          return resp.accessToken;
        }
        throw err;
      }
    }
    if (provider === 'cognito') {
      ensureAmplifyConfigured();
      try {
        const session = await fetchAuthSession({ forceRefresh: false });
        return session.tokens?.accessToken?.toString() || '';
      } catch {
        return '';
      }
    }
    return '';
  }, [provider]);

  // --- Determine auth state ---
  let isAuthenticated = false;
  let user = null;

  if (provider === 'entra') {
    isAuthenticated = entraCtx.isAuthenticated;
    user = entraCtx.user;
  } else if (provider === 'cognito') {
    isAuthenticated = !!cognitoUser;
    user = cognitoUser;
  }

  const value = {
    provider,
    isAuthenticated,
    user,
    getAccessToken,
    login,
    logout,
    switchProvider,
    // Expose MSAL internals for components that still need them (e.g., multi-account)
    _msalInstance: provider === 'entra' ? getMsalInstance() : null,
    _cognitoReady: cognitoReady,
  };

  // Wrap in MsalProvider when Entra is selected (so useMsal hooks work in EntraAuthInner)
  if (provider === 'entra') {
    const inst = getMsalInstance();
    if (inst) {
      return (
        <AuthContext.Provider value={value}>
          <MsalProvider instance={inst}>
            <EntraAuthInner onContext={setEntraCtx}>
              {children}
            </EntraAuthInner>
          </MsalProvider>
        </AuthContext.Provider>
      );
    }
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
