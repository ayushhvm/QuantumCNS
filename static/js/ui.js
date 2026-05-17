/**
 * PQChat v2.0 — UI Controller
 *
 * Handles all DOM interactions:
 *  - Chat panel: send/receive messages, contact list
 *  - Crypto Terminal: live ratchet log, session key viewer
 *  - Fingerprint display + "Mark as Verified" button
 *  - Amendment (3): "Reset Session" button
 *  - Amendment (4): DEGRADED MODE banner
 *  - Socket.IO event binding
 *
 * Requires:
 *  - socket.io.js (CDN)
 *  - ratchet_client.js (defines RatchetManager, SymmetricRatchetClient)
 *  - crypto_client.js  (defines PQChatClient)
 */

'use strict';

const PQChatUI = (() => {

  // ─── State ────────────────────────────────────────────────────────────

  let socket   = null;
  let pqClient = null;
  let currentPeer = null;

  const el = (id) => document.getElementById(id);

  // ─── Socket Setup ─────────────────────────────────────────────────────

  function initSocket(username, token) {
    socket = io({ query: { token } });

    socket.on('connect', () => {
      log('Connected to server');
      setStatus('Connected', 'status-ok');
    });

    socket.on('disconnect', () => {
      log('Disconnected from server');
      setStatus('Disconnected', 'status-err');
    });

    socket.on('auth_error', (data) => {
      log(`Auth error: ${data.error}`);
      window.location.href = '/login';
    });

    socket.on('welcome', (data) => {
      log(`Logged in as ${username}`);
      renderUserList(data.online_users, username);
    });

    socket.on('user_list', (data) => {
      renderUserList(data.online_users, username);
    });

    socket.on('identity_registered', () => {
      log('✅ Identity keys registered with server');
    });

    // Amendment 4: DEGRADED MODE confirmation from server
    socket.on('degraded_mode_confirmed', (data) => {
      if (data.degraded) {
        showDegradedBanner(data.message);
        log('⚠️ DEGRADED MODE active — server confirmed');
      }
    });

    // Handshake events
    socket.on('handshake_request', async (data) => {
      log(`Incoming handshake_request from ${data.from}`);
      await pqClient.handleHandshakeRequest(data);
    });

    socket.on('handshake_complete', async (data) => {
      log(`Handshake complete with ${data.from}`);
      await pqClient.handleHandshakeComplete(data);
    });

    // Message events
    socket.on('receive_message', async (data) => {
      await receiveMessage(data);
    });

    socket.on('message_delivered', (data) => {
      log(`Message delivered to ${data.to_user}`);
    });

    socket.on('user_offline', (data) => {
      log(`${data.username} is offline`);
      showSystemMessage(`${data.username} is offline`);
    });

    // Session reset (Amendment 3)
    socket.on('session_reset_requested', (data) => {
      log(`Session reset requested by ${data.from}: ${data.reason}`);
      showSystemMessage(`${data.from} requested a session reset. Click "Reset Session" to re-handshake.`);
    });

    socket.on('session_reset_sent', (data) => {
      log(`Session reset request sent to ${data.to_user}`);
    });

    return socket;
  }

  // ─── PQChatClient Setup ───────────────────────────────────────────────

  async function initPQClient(username, token, sock) {
    pqClient = new window.PQChatClient(sock, username, token);
    pqClient.onLog = (msg) => log(msg);

    // Fingerprint display event
    window.addEventListener('pqchat:fingerprint', (e) => {
      const { peer, fingerprint } = e.detail;
      if (peer === currentPeer) renderFingerprint(peer, fingerprint);
    });

    // Session ready event
    window.addEventListener('pqchat:session_ready', (e) => {
      const { peer } = e.detail;
      if (peer === currentPeer) {
        setSessionStatus(`Session established with ${peer}`, 'status-ok');
        el('btn-send')?.removeAttribute('disabled');
      }
    });

    // MITM warning
    window.addEventListener('pqchat:mitm_warning', (e) => {
      const { peer } = e.detail;
      showSecurityAlert(`⚠️ MITM WARNING: Signature from ${peer} is INVALID. Do not communicate.`);
    });

    // Session reset
    window.addEventListener('pqchat:session_reset', (e) => {
      const { peer } = e.detail;
      if (peer === currentPeer) {
        setSessionStatus('Session reset — re-handshake required', 'status-warn');
        el('btn-send')?.setAttribute('disabled', 'true');
      }
    });

    // DEGRADED MODE
    window.addEventListener('pqchat:degraded', (e) => {
      showDegradedBanner(`⚠️ DEGRADED MODE: ${e.detail.reason}`);
    });

    // Mark verified event
    window.addEventListener('pqchat:verified', (e) => {
      const { peer } = e.detail;
      if (peer === currentPeer) {
        el('fingerprint-status')?.classList.add('verified');
        el('btn-verify')?.textContent = '✅ VERIFIED';
      }
    });

    await pqClient.initialize();
  }

  // ─── User List ────────────────────────────────────────────────────────

  function renderUserList(users, self) {
    const list = el('user-list');
    if (!list) return;
    list.innerHTML = '';

    users.forEach(u => {
      if (u === self) return;  // don't show self
      const btn = document.createElement('button');
      btn.className = 'contact-btn';
      btn.id        = `contact-${u}`;
      btn.textContent = u;
      btn.addEventListener('click', () => selectPeer(u));
      list.appendChild(btn);
    });
  }

  async function selectPeer(peer) {
    currentPeer = peer;
    log(`Selected ${peer}`);

    // Update contact highlights
    document.querySelectorAll('.contact-btn').forEach(b => b.classList.remove('active'));
    el(`contact-${peer}`)?.classList.add('active');

    // Clear chat window
    const chatWindow = el('chat-messages');
    if (chatWindow) chatWindow.innerHTML = '';

    // Update header
    if (el('chat-peer-name')) el('chat-peer-name').textContent = peer;

    // Show fingerprint if known
    const fp = pqClient.getFingerprint(peer);
    if (fp) renderFingerprint(peer, fp.fingerprint);
    else el('fingerprint-display')?.classList.add('hidden');

    // Initiate handshake if no session
    if (!pqClient._ratchet.has(peer)) {
      setSessionStatus('Initiating handshake...', 'status-pending');
      el('btn-send')?.setAttribute('disabled', 'true');
      await pqClient.initiateHandshake(peer);
    } else {
      setSessionStatus(`Session active with ${peer}`, 'status-ok');
      el('btn-send')?.removeAttribute('disabled');
    }
  }

  // ─── Message Send / Receive ───────────────────────────────────────────

  async function sendMessage() {
    if (!currentPeer) return;
    const input   = el('message-input');
    const text    = input?.value?.trim();
    if (!text) return;

    try {
      const payload = await pqClient.encryptMessage(currentPeer, text);

      socket.emit('send_message', {
        token:       pqClient._authToken,
        target_user: currentPeer,
        ...payload,
      });

      appendMessage(pqClient.username, text, 'outgoing');
      if (input) input.value = '';

      // Update crypto terminal
      updateRatchetDisplay(currentPeer);
    } catch (err) {
      log(`Send failed: ${err.message}`);
      showSystemMessage(`Failed to send: ${err.message}`);
    }
  }

  async function receiveMessage(data) {
    const sender = data.from;
    try {
      const plaintext = await pqClient.decryptMessage(sender, data);
      appendMessage(sender, plaintext, 'incoming');
      log(`Decrypted message from ${sender} (step ${data.ratchet_step})`);
      if (sender === currentPeer) updateRatchetDisplay(sender);
    } catch (err) {
      log(`Decrypt failed from ${sender}: ${err.message}`);
      appendMessage(sender, '[⚠ Decryption failed — ratchet desynced?]', 'incoming error');
    }
  }

  function appendMessage(sender, text, direction) {
    const container = el('chat-messages');
    if (!container) return;
    const div = document.createElement('div');
    div.className = `message ${direction}`;
    div.innerHTML = `<span class="msg-sender">${sender}</span><span class="msg-text">${escapeHtml(text)}</span>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  }

  function showSystemMessage(text) {
    const container = el('chat-messages');
    if (!container) return;
    const div = document.createElement('div');
    div.className = 'message system';
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  }

  // ─── Crypto Terminal ──────────────────────────────────────────────────

  function log(msg) {
    const terminal = el('crypto-log');
    if (!terminal) return;
    const line = document.createElement('div');
    line.className = 'log-line';
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    terminal.prepend(line);
    // Keep last 50 lines
    while (terminal.children.length > 50) terminal.removeChild(terminal.lastChild);
  }

  function updateRatchetDisplay(peer) {
    const ratchet = pqClient._ratchet.get(peer);
    if (!ratchet) return;
    const { step, chainKeyPreview } = ratchet.stateSummary;
    if (el('ratchet-step'))        el('ratchet-step').textContent = step;
    if (el('chain-key-preview'))   el('chain-key-preview').textContent = chainKeyPreview;
    if (el('ratchet-algorithm'))   el('ratchet-algorithm').textContent = 'Symmetric Ratchet';
  }

  function updateAlgorithmPanel() {
    if (el('algo-kem'))  el('algo-kem').textContent  = 'Kyber768';
    if (el('algo-sig'))  el('algo-sig').textContent  = 'ML-DSA-65';
    if (el('algo-sym'))  el('algo-sym').textContent  = 'AES-256-GCM';
    if (el('algo-kdf'))  el('algo-kdf').textContent  = 'HKDF-SHA256';
    if (el('algo-ecdhe')) el('algo-ecdhe').textContent = 'ECDHE P-256';
  }

  // ─── Fingerprint Panel ────────────────────────────────────────────────

  function renderFingerprint(peer, fingerprint) {
    el('fingerprint-display')?.classList.remove('hidden');
    if (el('fingerprint-value')) el('fingerprint-value').textContent = fingerprint;
    if (el('fingerprint-peer')) el('fingerprint-peer').textContent = peer;

    // Check if already locally verified
    const verified = JSON.parse(localStorage.getItem('pqchat_verified') || '{}');
    if (verified[peer] === fingerprint) {
      el('fingerprint-status')?.classList.add('verified');
      if (el('btn-verify')) el('btn-verify').textContent = '✅ VERIFIED';
    } else {
      el('fingerprint-status')?.classList.remove('verified');
      if (el('btn-verify')) el('btn-verify').textContent = 'Mark as Verified';
    }
  }

  // ─── Session Reset (Amendment 3) ─────────────────────────────────────

  function handleSessionReset() {
    if (!currentPeer) return;
    if (!confirm(`Reset session with ${currentPeer}? Both parties must re-handshake.`)) return;
    pqClient.requestSessionReset(currentPeer, 'User clicked Reset Session button');
    showSystemMessage('Session reset initiated — waiting for peer to re-handshake');
  }

  // ─── DEGRADED MODE Banner (Amendment 4) ──────────────────────────────

  function showDegradedBanner(message) {
    let banner = el('degraded-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'degraded-banner';
      banner.className = 'degraded-banner';
      document.body.prepend(banner);
    }
    banner.textContent = message || '⚠️ DEGRADED MODE — liboqs-wasm unavailable. Post-quantum cryptography disabled.';
    banner.classList.remove('hidden');
  }

  // ─── Security Alert ───────────────────────────────────────────────────

  function showSecurityAlert(message) {
    let alert = el('security-alert');
    if (!alert) {
      alert = document.createElement('div');
      alert.id = 'security-alert';
      alert.className = 'security-alert';
      document.body.prepend(alert);
    }
    alert.textContent = message;
    alert.classList.remove('hidden');
    setTimeout(() => alert?.classList.add('hidden'), 10000);
  }

  // ─── Status Helpers ───────────────────────────────────────────────────

  function setStatus(text, cls) {
    const el_status = el('connection-status');
    if (!el_status) return;
    el_status.textContent = text;
    el_status.className = 'status-badge ' + cls;
  }

  function setSessionStatus(text, cls) {
    const el_sess = el('session-status');
    if (!el_sess) return;
    el_sess.textContent = text;
    el_sess.className = 'status-badge ' + cls;
    el_sess.classList.remove('hidden');
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ─── Entry Point ──────────────────────────────────────────────────────

  async function init(username, token) {
    const sock = initSocket(username, token);
    await initPQClient(username, token, sock);
    updateAlgorithmPanel();

    // Wire up send button and Enter key
    el('btn-send')?.addEventListener('click', sendMessage);
    el('message-input')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });

    // Wire up verify button
    el('btn-verify')?.addEventListener('click', () => {
      if (currentPeer) pqClient.markVerified(currentPeer);
    });

    // Amendment 3: Wire up session reset button
    el('btn-reset-session')?.addEventListener('click', handleSessionReset);

    // Alert on page unload if keys in memory
    window.addEventListener('beforeunload', () => {
      // Keys are cleared automatically when page unloads
    });
  }

  return { init };
})();

window.PQChatUI = PQChatUI;
