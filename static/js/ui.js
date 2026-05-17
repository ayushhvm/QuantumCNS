import { PQChatCrypto, bufToHex, hexToBuf } from "./crypto_client.js";

// DOM Elements
const myUsernameEl = document.getElementById("myUsername");
const logoutBtn = document.getElementById("logoutBtn");
const contactsList = document.getElementById("contactsList");
const chatPeerInfo = document.getElementById("chatPeerInfo");
const currentPeerEl = document.getElementById("currentPeer");
const e2eeBadge = document.getElementById("e2eeBadge");
const chatMessages = document.getElementById("chatMessages");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");
const chatForm = document.getElementById("chatForm");

const cryptoLogs = document.getElementById("cryptoLogs");
const sessionKeyStat = document.getElementById("sessionKeyStat");
const ratchetStepStat = document.getElementById("ratchetStepStat");
const fingerprintSection = document.getElementById("fingerprintSection");
const fingerprintValue = document.getElementById("fingerprintValue");
const verifyBtn = document.getElementById("verifyBtn");
const securityAlert = document.getElementById("securityAlert");

// App State
const token = sessionStorage.getItem("pqchat_token");
const username = sessionStorage.getItem("pqchat_username");
let activePeer = null;

if (!token || !username) {
    window.location.href = "/";
}

myUsernameEl.textContent = username;

// Crypto & Socket
const crypto = new PQChatCrypto();
const socket = io();

// ── Initialisation ──────────────────────────────────────────────────────────
async function init() {
    await crypto.init(username, token);

    socket.emit("register_socket", { token });

    socket.on("registered", async (data) => {
        const keys = await crypto.getPublicKeysForRegistration();
        socket.emit("register_identity", {
            token,
            ...keys
        });
        fetchOnlineUsers();
    });

    setInterval(fetchOnlineUsers, 5000); // Poll for online users
}

init();

// ── UI Helpers ──────────────────────────────────────────────────────────────
function appendMessage(sender, text, isSystem = false) {
    const div = document.createElement("div");
    if (isSystem) {
        div.className = "system-msg";
    } else {
        div.className = `message-bubble ${sender === username ? "message-own" : "message-peer"}`;
    }
    div.textContent = text;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function appendLog(level, msg) {
    const div = document.createElement("div");
    div.className = `log-entry log-${level}`;
    div.textContent = `> ${msg}`;
    cryptoLogs.appendChild(div);
    cryptoLogs.scrollTop = cryptoLogs.scrollHeight;
}

// ── Socket Events ───────────────────────────────────────────────────────────
socket.on("handshake_request", async (data) => {
    appendLog("info", `Incoming handshake request from ${data.from}`);
    await crypto.respondToHandshake(data, socket);
});

socket.on("handshake_complete", async (data) => {
    appendLog("info", `Handshake completion received from ${data.from}`);
    await crypto.completeHandshake(data);
});

socket.on("receive_message", async (data) => {
    if (data.from !== activePeer) return; // For simplicity, only render active chat
    try {
        const plaintext = await crypto.decryptMessage(
            data.from,
            data.nonce,
            data.ciphertext,
            data.tag,
            data.ratchet_step
        );
        appendMessage(data.from, plaintext);
        updateCryptoStats();
    } catch (err) {
        appendLog("error", `Failed to decrypt message: ${err.message}`);
    }
});

socket.on("error", (data) => {
    appendLog("error", `Server error: ${data.message}`);
    if (data.message === "Unauthorized" || data.message === "Invalid or expired token") {
        sessionStorage.clear();
        window.location.href = "/";
    }
});

// ── Custom Events ───────────────────────────────────────────────────────────
window.addEventListener("pqchat:log", (e) => {
    appendLog(e.detail.level, e.detail.msg);
});

window.addEventListener("pqchat:session-established", async (e) => {
    const peer = e.detail.peer;
    if (peer === activePeer) {
        e2eeBadge.style.display = "flex";
        messageInput.disabled = false;
        sendBtn.disabled = false;
        messageInput.focus();
        appendMessage("system", "🔐 Secure post-quantum session established", true);
        
        updateCryptoStats();
        
        // Compute and show fingerprint
        const myKeys = await crypto.getPublicKeysForRegistration();
        const peerKeysResp = await fetch(`/api/keys/${peer}`);
        const peerKeys = await peerKeysResp.json();
        
        const myDilPub = hexToBuf(myKeys.dilithium_public_key);
        const peerDilPub = hexToBuf(peerKeys.dilithium_public_key);
        
        const fingerprint = await crypto.computeFingerprint(myDilPub, peerDilPub);
        fingerprintSection.style.display = "block";
        fingerprintValue.textContent = fingerprint;
        verifyBtn.textContent = "MARK AS VERIFIED";
        verifyBtn.style.color = "#0f0";
        verifyBtn.style.borderColor = "#0f0";
    }
    fetchOnlineUsers(); // Refresh contacts list to show lock icon
});

window.addEventListener("pqchat:security-alert", (e) => {
    securityAlert.textContent = e.detail.msg;
    securityAlert.style.display = "block";
    setTimeout(() => { securityAlert.style.display = "none"; }, 5000);
});

// ── Actions ─────────────────────────────────────────────────────────────────
async function fetchOnlineUsers() {
    try {
        const res = await fetch("/api/users/online");
        const data = await res.json();
        if (data.ok) {
            renderContacts(data.users);
        }
    } catch (err) {
        console.error("Failed to fetch online users", err);
    }
}

function renderContacts(users) {
    contactsList.innerHTML = "";
    users.filter(u => u !== username).forEach(user => {
        const div = document.createElement("div");
        div.className = `contact-item ${user === activePeer ? "active" : ""}`;
        
        const hasSession = crypto.hasSession(user);
        
        div.innerHTML = `
            <div>
                <span class="status-indicator online"></span>
                <span>${user}</span>
            </div>
            ${hasSession ? '<span class="lock-icon">🔐</span>' : ''}
        `;
        
        div.onclick = () => selectContact(user);
        contactsList.appendChild(div);
    });
}

function selectContact(user) {
    activePeer = user;
    chatPeerInfo.style.display = "flex";
    currentPeerEl.textContent = user;
    chatMessages.innerHTML = "";
    
    fetchOnlineUsers(); // Re-render to show active state
    
    if (crypto.hasSession(user)) {
        e2eeBadge.style.display = "flex";
        messageInput.disabled = false;
        sendBtn.disabled = false;
        appendMessage("system", `Resuming secure session with ${user}`, true);
        updateCryptoStats();
        // Trigger fingerprint display update
        window.dispatchEvent(new CustomEvent("pqchat:session-established", { detail: { peer: user } }));
    } else {
        e2eeBadge.style.display = "none";
        messageInput.disabled = true;
        sendBtn.disabled = true;
        fingerprintSection.style.display = "none";
        appendMessage("system", `Establishing secure session with ${user}...`, true);
        crypto.initiateHandshake(user, socket);
    }
}

chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !activePeer) return;
    
    messageInput.value = "";
    appendMessage(username, text);
    
    try {
        const payload = await crypto.encryptMessage(activePeer, text);
        socket.emit("send_message", {
            token,
            target_user: activePeer,
            ...payload
        });
        updateCryptoStats();
    } catch (err) {
        appendLog("error", `Failed to send message: ${err.message}`);
    }
});

logoutBtn.addEventListener("click", async () => {
    await fetch("/api/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token })
    });
    sessionStorage.clear();
    window.location.href = "/";
});

verifyBtn.addEventListener("click", () => {
    verifyBtn.textContent = "✓ VERIFIED";
    verifyBtn.style.color = "var(--text-secondary)";
    verifyBtn.style.borderColor = "var(--text-secondary)";
});

function updateCryptoStats() {
    if (!activePeer || !crypto.hasSession(activePeer)) return;
    
    const sk = bufToHex(crypto.getSessionKey(activePeer));
    sessionKeyStat.textContent = sk.slice(0, 16) + "...";
    
    const session = crypto._sessions[activePeer];
    ratchetStepStat.textContent = session ? session.step : 0;
}

const hackerModeSwitch = document.getElementById("hackerModeSwitch");
if (hackerModeSwitch) {
    hackerModeSwitch.addEventListener("change", (e) => {
        socket.emit("toggle_tampering", { token, enable: e.target.checked });
    });
}
