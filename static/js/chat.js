/* global io, initClientCrypto, processHandshakeResponse, encryptMessage, decryptMessage */

(() => {
	const appRoot = document.getElementById('app-root');
	if (!appRoot) {
		return;
	}

	const TOKEN = appRoot.dataset.token || '';
	const USERNAME = appRoot.dataset.username || '';

	const statusDiv = document.getElementById('connection-status');
	const terminalDiv = document.getElementById('terminal-log');
	const messageInput = document.getElementById('message-input');
	const sendButton = document.getElementById('send-btn');
	const messagesDiv = document.getElementById('messages');
	const partnerSelect = document.getElementById('chat-partner');
	const partnerButtons = Array.from(document.querySelectorAll('.contact-item'));
	const currentPartnerEl = document.getElementById('current-partner');
	const statusDot = document.getElementById('status-dot');
	const encryptionBadge = document.getElementById('encryption-badge');
	const terminalCursor = document.getElementById('terminal-cursor');

	let socket = null;
	let handshakeComplete = false;
	let chatPartner = partnerSelect ? partnerSelect.value : '';

	if (!chatPartner && partnerButtons.length > 0) {
		const fallback = USERNAME.toLowerCase() === 'alice' ? 'bob' : 'alice';
		const first = partnerButtons.find((btn) => btn.dataset.user === fallback) || partnerButtons[0];
		chatPartner = first.dataset.user;
	}

	function setConnectionState(state) {
		if (!statusDot) {
			return;
		}

		statusDot.classList.remove('online', 'error');
		if (state === 'online') {
			statusDot.classList.add('online');
		} else if (state === 'error') {
			statusDot.classList.add('error');
		}
	}

	function setChatPartner(user) {
		chatPartner = user;
		if (currentPartnerEl) {
			currentPartnerEl.textContent = user;
		}
		for (const button of partnerButtons) {
			button.classList.toggle('active', button.dataset.user === user);
		}
	}

	function setStatus(text) {
		if (statusDiv) {
			statusDiv.textContent = text;
		}
	}

	function addTerminalLine(text) {
		if (!terminalDiv) {
			return;
		}
		const row = document.createElement('div');
		row.textContent = text;
		terminalDiv.appendChild(row);
		terminalDiv.scrollTop = terminalDiv.scrollHeight;
	}

	function setInputEnabled(enabled) {
		if (messageInput) {
			messageInput.disabled = !enabled;
		}
		if (sendButton) {
			sendButton.disabled = !enabled;
		}
	}

	function addMessage(who, text, isOwn) {
		if (!messagesDiv) {
			return;
		}
		const line = document.createElement('div');
		line.className = isOwn ? 'message own' : 'message incoming';
		line.textContent = `[${who}] ${text}`;
		messagesDiv.appendChild(line);
		messagesDiv.scrollTop = messagesDiv.scrollHeight;
	}

	async function beginHandshake() {
		setConnectionState('connecting');
		setStatus('Performing handshake...');
		addTerminalLine('Initializing client cryptography...');

		const pub = await initClientCrypto();
		socket.emit('handshake_init', {
			token: TOKEN,
			client_kyber_pub_b64: pub.kyberPubB64,
			client_ecdhe_pub_b64: pub.ecdhePubB64,
		});
	}

	async function sendCurrentMessage() {
		if (!handshakeComplete || !socket || !messageInput) {
			setStatus('Securing channel...');
			addTerminalLine('Securing channel before sending.');
			return;
		}

		if (!chatPartner) {
			addTerminalLine('Select a chat partner first.');
			return;
		}

		const plaintext = messageInput.value.trim();
		if (!plaintext) {
			return;
		}

		const payload = await encryptMessage(plaintext);
		socket.emit('send_message', {
			token: TOKEN,
			to_user: chatPartner,
			encrypted_payload: payload,
		});

		addMessage(USERNAME || 'me', plaintext, true);
		messageInput.value = '';
	}

	function bindEvents() {
		if (partnerSelect) {
			partnerSelect.addEventListener('change', () => {
				setChatPartner(partnerSelect.value);
			});
		}

		for (const button of partnerButtons) {
			button.addEventListener('click', () => {
				setChatPartner(button.dataset.user);
			});
		}

		if (sendButton) {
			sendButton.addEventListener('click', () => {
				sendCurrentMessage().catch((error) => {
					addTerminalLine(`Send failed: ${error.message}`);
				});
			});
		}

		if (messageInput) {
			messageInput.addEventListener('keydown', (event) => {
				if (event.key === 'Enter') {
					event.preventDefault();
					sendCurrentMessage().catch((error) => {
						addTerminalLine(`Send failed: ${error.message}`);
					});
				}
			});
		}
	}

	function setupSocket() {
		if (!TOKEN) {
			setStatus('Missing token. Please log in again.');
			setConnectionState('error');
			addTerminalLine('No token found. Please return to login.');
			return;
		}

		if (typeof io !== 'function') {
			setStatus('Socket.IO failed to load');
			setConnectionState('error');
			addTerminalLine('Socket.IO client is unavailable.');
			return;
		}

		socket = io({ query: { token: TOKEN } });

		socket.on('connect', () => {
			addTerminalLine('Socket connected.');
			beginHandshake().catch((error) => {
				setStatus('Handshake failed');
				setConnectionState('error');
				addTerminalLine(`Handshake init error: ${error.message}`);
			});
		});

		socket.on('handshake_response', async (data) => {
			try {
				await processHandshakeResponse(data);
				handshakeComplete = true;
				setInputEnabled(true);
				setStatus('Session secured - AES-256-GCM active ✓');
				setConnectionState('online');
				if (encryptionBadge) {
					encryptionBadge.classList.add('active');
				}
				if (terminalCursor) {
					terminalCursor.classList.add('hidden');
				}
				for (const step of data.log_steps || []) {
					addTerminalLine(step);
				}
			} catch (error) {
				setStatus('Handshake failed');
				setConnectionState('error');
				addTerminalLine(`Handshake process error: ${error.message}`);
			}
		});

		socket.on('receive_message', async (data) => {
			const plaintext = await decryptMessage(data.encrypted_payload || {});
			addMessage(data.from_user || 'unknown', plaintext, false);
		});

		socket.on('message_delivered', (data) => {
			addTerminalLine(`Delivered to ${data.to_user}`);
		});

		socket.on('user_offline', (data) => {
			addTerminalLine(`${data.to_user} is offline.`);
		});

		socket.on('auth_error', (data) => {
			setStatus('Authentication error');
			setConnectionState('error');
			addTerminalLine(data.error || 'Authentication failed');
			addTerminalLine('Please re-login to continue.');
			setInputEnabled(false);
		});

		socket.on('handshake_error', (data) => {
			setStatus('Handshake error');
			setConnectionState('error');
			addTerminalLine(data.error || 'Handshake failed');
			setInputEnabled(false);
		});

		socket.on('disconnect', () => {
			handshakeComplete = false;
			setInputEnabled(false);
			setStatus('Disconnected');
			setConnectionState('error');
			if (encryptionBadge) {
				encryptionBadge.classList.remove('active');
			}
			if (terminalCursor) {
				terminalCursor.classList.remove('hidden');
			}
			addTerminalLine('Socket disconnected.');
		});

		socket.io.on('reconnect_attempt', () => {
			setStatus('Reconnecting...');
			setConnectionState('connecting');
			addTerminalLine('Attempting reconnect...');
		});

		socket.on('connect_error', (error) => {
			setStatus('Authentication error');
			setConnectionState('error');
			addTerminalLine(`Connection error: ${error.message}`);
			addTerminalLine('Please re-login to continue.');
			setInputEnabled(false);
		});
	}

	setInputEnabled(false);
	setChatPartner(chatPartner || 'alice');
	setConnectionState('connecting');
	setStatus('Connecting...');
	addTerminalLine('Loading secure chat client...');
	bindEvents();
	setupSocket();
})();
