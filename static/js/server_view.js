const socket = io();
const terminal = document.getElementById("terminal");
const attackBtn = document.getElementById("attackBtn");
const attackPanel = document.getElementById("attackPanel");
const progressFill = document.getElementById("progressFill");
const attackStatus = document.getElementById("attackStatus");

let lastPayload = null;

// Join the 'server_intercept' room
socket.emit("join_intercept");

function appendLog(type, data) {
    const div = document.createElement("div");
    div.className = "log-entry";
    
    const time = new Date().toLocaleTimeString();
    const formattedData = JSON.stringify(data, null, 2);
    
    div.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="log-type">${type}</span>
        <div class="log-data">${formattedData}</div>
    `;
    
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
    
    lastPayload = data;
    attackBtn.disabled = false;
}

socket.on("intercept_log", (payload) => {
    appendLog(payload.type, payload.data);
});

attackBtn.addEventListener("click", () => {
    if (!lastPayload) return;
    
    attackBtn.disabled = true;
    attackPanel.style.display = "block";
    progressFill.style.width = "0%";
    
    let isHandshake = lastPayload.type === "HANDSHAKE_INIT" || lastPayload.type === "HANDSHAKE_RESPONSE";
    
    let progress = 0;
    attackStatus.textContent = "Initializing Qubits for Shor's Algorithm...";
    attackStatus.className = "attack-status";
    
    const interval = setInterval(() => {
        progress += Math.random() * 5 + 1;
        if (progress > 100) progress = 100;
        
        progressFill.style.width = `${progress}%`;
        
        if (progress > 30 && progress < 60) {
            attackStatus.textContent = "Applying Quantum Fourier Transform on ECDH P-256...";
        } else if (progress >= 60 && progress < 90) {
            attackStatus.textContent = "Extracting discrete logarithm...";
        } else if (progress >= 90 && progress < 100) {
            attackStatus.textContent = "ECDH P-256 Broken! Attempting to break ML-KEM-768...";
        } else if (progress === 100) {
            clearInterval(interval);
            
            setTimeout(() => {
                if (isHandshake) {
                    attackStatus.innerHTML = `
                        <span style="color: #ffaa00;">[!] Classical ECDH Key Recovered.</span><br>
                        <span style="color: #00ff00;">[✓] ML-KEM-768 Ciphertext Resists Shor's Algorithm.</span><br>
                        <span style="color: #ffaa00;">[X] Failed to derive final HKDF Session Key. Payload remains secure.</span>
                    `;
                } else {
                    attackStatus.innerHTML = `
                        <span style="color: #00ff00;">[✓] AES-256-GCM Payload Resists Grover's Algorithm.</span><br>
                        <span style="color: #ffaa00;">[X] Decryption Failed.</span>
                    `;
                }
                setTimeout(() => { attackBtn.disabled = false; }, 2000);
            }, 1000);
        }
    }, 100);
});
