(() => {
  'use strict';

  const fromBase64url = value => {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  };
  const toBase64url = value => {
    const bytes = new Uint8Array(value);
    let binary = '';
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const csrf = () => document.querySelector('[name="csrf_token"]')?.value ||
    document.getElementById('passkey-account')?.dataset.csrf || '';

  async function post(url, body) {
    const response = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Passkey operation failed');
    return data;
  }

  function credentialJSON(credential, registration) {
    const response = registration ? {
      attestationObject: toBase64url(credential.response.attestationObject),
      clientDataJSON: toBase64url(credential.response.clientDataJSON),
      transports: credential.response.getTransports?.() || []
    } : {
      authenticatorData: toBase64url(credential.response.authenticatorData),
      clientDataJSON: toBase64url(credential.response.clientDataJSON),
      signature: toBase64url(credential.response.signature),
      userHandle: credential.response.userHandle ? toBase64url(credential.response.userHandle) : null
    };
    return {
      id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type,
      response, clientExtensionResults: credential.getClientExtensionResults()
    };
  }

  function creationOptions(options) {
    const key = options.publicKey;
    key.challenge = fromBase64url(key.challenge);
    key.user.id = fromBase64url(key.user.id);
    key.excludeCredentials?.forEach(item => { item.id = fromBase64url(item.id); });
    return options;
  }

  function requestOptions(options) {
    const key = options.publicKey;
    key.challenge = fromBase64url(key.challenge);
    key.allowCredentials?.forEach(item => { item.id = fromBase64url(item.id); });
    return options;
  }

  const loginButton = document.getElementById('passkey-login');
  const username = document.getElementById('username');
  const usernameError = document.getElementById('username-passkey-error');
  if (loginButton && username && usernameError) username.addEventListener('input', () => {
    if (!username.value.trim()) return;
    username.classList.remove('is-invalid');
    username.removeAttribute('aria-invalid');
    username.removeAttribute('aria-describedby');
    usernameError.textContent = '';
  });
  if (loginButton) loginButton.addEventListener('click', async () => {
    const message = document.getElementById('passkey-message');
    const form = document.getElementById('login-form');
    const fields = Object.fromEntries(new FormData(form));
    if (!fields.username?.trim()) {
      username.classList.add('is-invalid');
      username.setAttribute('aria-invalid', 'true');
      username.setAttribute('aria-describedby', 'username-passkey-error');
      usernameError.textContent = 'Enter your email or username to continue with a passkey.';
      message.textContent = '';
      username.focus();
      return;
    }
    loginButton.disabled = true;
    message.textContent = 'Waiting for your passkey…';
    try {
      delete fields.password;
      delete fields.mfa_code;
      const { token, options } = await post('/oauth2/passkey/start', fields);
      const credential = await navigator.credentials.get(requestOptions(options));
      const result = await post('/oauth2/passkey/finish', {
        token, credential: credentialJSON(credential, false)
      });
      window.location.assign(result.redirect_url);
    } catch (error) {
      message.textContent = error.name === 'NotAllowedError' ?
        'Passkey sign-in was cancelled.' : (error.message === 'Passkey sign-in is unavailable' ? 'A registered passkey is required. Sign in with your password and authenticator code, then add a passkey in Account security.' : (error.message || 'Passkey sign-in failed.'));
      loginButton.disabled = false;
    }
  });

  const account = document.getElementById('passkey-account');
  if (!account) return;
  const message = document.getElementById('passkey-message');
  const list = document.getElementById('passkey-list');
  const button = document.getElementById('passkey-add');
  const label = document.getElementById('passkey-label');
  const isFresh = account.dataset.fresh === 'true';

  async function refresh(afterRemoval = false) {
    const response = await fetch('/account/passkeys', { credentials: 'same-origin' });
    if (response.status === 401) {
      button.disabled = true;
      label.disabled = true;
      list.replaceChildren();
      message.textContent = afterRemoval ?
        'Passkey removed. Your sign-in session ended for security. Sign in again through your application.' :
        'Your sign-in session ended. Sign in again through your application.';
      return;
    }
    if (!response.ok) throw new Error('Could not load your passkeys.');
    const data = await response.json();
    list.replaceChildren();
    if (data.passkeys.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-secondary';
      empty.textContent = 'No passkeys registered yet.';
      list.append(empty);
    }
    for (const item of data.passkeys) {
      const row = document.createElement('div');
      row.className = 'd-flex align-items-center justify-content-between gap-2 border rounded p-2 mb-2';
      const description = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = item.label;
      const detail = document.createElement('div');
      detail.className = 'text-secondary small';
      detail.textContent = 'Added ' + new Date(item.created_at).toLocaleString() +
        (item.last_used_at ? ' · Used ' + new Date(item.last_used_at).toLocaleString() : ' · Not used yet');
      description.append(title, detail);
      const actions = document.createElement('div');
      actions.className = 'btn-list flex-nowrap';
      const rename = document.createElement('button');
      rename.className = 'btn btn-sm btn-outline-secondary';
      rename.textContent = 'Rename';
      rename.disabled = !isFresh;
      rename.addEventListener('click', async () => {
        const next = window.prompt('Passkey name', item.label);
        if (!next || next.trim() === item.label) return;
        try { await post('/account/passkeys/rename', { id: item.id, label: next.trim() }); await refresh(); }
        catch (error) { message.textContent = error.message; }
      });
      const remove = document.createElement('button');
      remove.className = 'btn btn-sm btn-outline-danger';
      remove.textContent = 'Remove';
      remove.disabled = !isFresh;
      remove.addEventListener('click', async () => {
        if (!window.confirm('Remove this passkey?')) return;
        try { await post('/account/passkeys/revoke', { id: item.id }); await refresh(true); }
        catch (error) { message.textContent = error.message; }
      });
      actions.append(rename, remove);
      row.append(description, actions);
      list.append(row);
    }
  }

  button?.addEventListener('click', async () => {
    button.disabled = true;
    message.textContent = 'Waiting for your passkey…';
    try {
      const { token, options } = await post('/account/passkeys/register/start', {});
      const credential = await navigator.credentials.create(creationOptions(options));
      await post('/account/passkeys/register/finish', {
        token, label: label.value.trim() || 'Passkey', credential: credentialJSON(credential, true)
      });
      message.textContent = 'Passkey added. Add another one as a backup.';
      await refresh();
    } catch (error) {
      message.textContent = error.name === 'NotAllowedError' ?
        'Passkey registration was cancelled.' : (error.message || 'Passkey registration failed.');
    } finally { button.disabled = false; }
  });
  refresh().catch(error => { message.textContent = error.message; });
})();
