import React from 'react';
import { useMsal } from '@azure/msal-react';
import { loginRequest } from '../authConfig';

export default function AuthStatus() {
  const { instance, accounts } = useMsal();
  const activeAccount = instance.getActiveAccount();

  const handleLogin = () => {
    instance.loginPopup(loginRequest).catch(console.error);
  };

  const handleAddAccount = () => {
    instance.loginPopup({ ...loginRequest, prompt: 'select_account' }).catch(console.error);
  };

  const handleLogout = () => {
    instance.logoutPopup({ postLogoutRedirectUri: '/' });
  };

  const handleAccountSwitch = (e) => {
    const account = accounts.find(a => a.homeAccountId === e.target.value);
    if (account) {
      instance.setActiveAccount(account);
      // Force re-render by dispatching a custom event
      window.dispatchEvent(new Event('msal-account-change'));
    }
  };

  if (!activeAccount) {
    return (
      <div className="auth-status">
        <button onClick={handleLogin}>Sign In with Microsoft</button>
      </div>
    );
  }

  return (
    <div className="auth-status">
      {accounts.length > 1 ? (
        <select
          className="account-switcher"
          value={activeAccount.homeAccountId}
          onChange={handleAccountSwitch}
        >
          {accounts.map(acct => (
            <option key={acct.homeAccountId} value={acct.homeAccountId}>
              {acct.username}
            </option>
          ))}
        </select>
      ) : (
        <span className="auth-username">{activeAccount.username}</span>
      )}
      <button className="btn-secondary" onClick={handleAddAccount}>Add Account</button>
      <button onClick={handleLogout}>Sign Out</button>
    </div>
  );
}
