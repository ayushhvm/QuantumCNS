/**
 * PQChat v2.0 — Quantum Attack Simulator UI
 *
 * Calls the `/api/simulate/*` Flask endpoints and animates results
 * in the simulator panel. Communicates with templates/simulator.html.
 *
 * Amendment 6: N is capped at 9999 on both client and server.
 */

'use strict';

const SimulatorUI = (() => {

  // ─── Helpers ────────────────────────────────────────────────────────────

  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function delay(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  async function animateLog(containerId, lines, delayMs = 60) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = '';
    for (const line of lines) {
      const span = document.createElement('div');
      span.className = 'sim-log-line';
      span.textContent = '> ' + line;
      el.appendChild(span);
      el.scrollTop = el.scrollHeight;
      await delay(delayMs);
    }
  }

  function setVerdict(elementId, text, isSuccess) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = text;
    el.className = 'sim-verdict ' + (isSuccess ? 'verdict-secure' : 'verdict-broken');
  }

  function renderTable(containerId, rows) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const table = document.createElement('table');
    table.className = 'sim-table';
    rows.forEach((row, i) => {
      const tr = document.createElement('tr');
      if (i === 0) tr.className = 'sim-table-head';
      row.forEach(cell => {
        const td = document.createElement(i === 0 ? 'th' : 'td');
        td.textContent = cell;
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    el.innerHTML = '';
    el.appendChild(table);
  }

  // ─── Shor's Simulation ──────────────────────────────────────────────────

  async function runShors() {
    const nInput = document.getElementById('shors-n-input');
    const useQuantum = document.getElementById('shors-use-quantum')?.checked;
    let N = parseInt(nInput?.value || '15', 10);

    // Amendment 6: client-side cap
    if (isNaN(N) || N < 4) { N = 4; nInput && (nInput.value = 4); }
    if (N > 9999) { N = 9999; nInput && (nInput.value = 9999); }

    const endpoint = useQuantum ? '/api/simulate/quantum_shors' : '/api/simulate/shors';
    setVerdict('shors-verdict', 'RUNNING...', null);
    document.getElementById('shors-log')?.classList.add('running');

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ N }),
      });
      const data = await res.json();

      if (data.error) {
        await animateLog('shors-log', [`ERROR: ${data.error}`], 30);
        setVerdict('shors-verdict', 'ERROR', false);
        return;
      }

      // Animate step log
      const lines = data.steps || [];
      if (data.mode === 'complexity_estimate') {
        lines.push(`N=${N} too large for live simulation — showing estimates`);
        lines.push(`Logical qubits needed for P-256: ${data.extrapolation?.ecdhe_p256?.logical_qubits}`);
        lines.push(`Physical qubits needed: ${data.extrapolation?.ecdhe_p256?.physical_qubits_estimate}`);
        lines.push(`Current best hardware: ${data.extrapolation?.ecdhe_p256?.current_best_hardware}`);
      }

      await animateLog('shors-log', lines, 80);

      if (data.success && data.factors) {
        const [f1, f2] = Array.isArray(data.factors) ? data.factors : [data.factors[0], data.factors[1]];
        setVerdict('shors-verdict', `✗ FACTORED: ${N} = ${f1} × ${f2} — ECDHE BROKEN`, false);
        // Then show hybrid protection
        await delay(800);
        await animateLog('shors-log', [
          ...lines,
          '',
          `⚡ ECDHE P-256 classical key exchange: BROKEN by Shor's`,
          `🛡  Kyber768 shared secret: UNKNOWN to attacker — lattice problem unaffected`,
          `🔑  PQChat Session Key = HKDF(Kyber_secret ‖ ECDHE_secret)`,
          `✅  Kyber768 secret is UNKNOWN → Session key REMAINS SECURE`,
        ], 60);
        setVerdict('shors-hybrid-verdict', '✅ HYBRID PROTECTION HOLDS — Session key secure', true);
      } else {
        setVerdict('shors-verdict', 'Factorization unsuccessful for this N/a', null);
      }

      // P-256 extrapolation panel
      const ext = data.p256_extrapolation || data.extrapolation?.ecdhe_p256;
      if (ext) {
        renderTable('shors-extrapolation-table', [
          ['Property', 'Value'],
          ['Target', ext.target || 'ECDHE P-256'],
          ['Logical qubits', ext.logical_qubits_needed || ext.logical_qubits],
          ['Physical qubits', ext.physical_qubits_needed || ext.physical_qubits_estimate],
          ['Current hardware', ext.current_best_quantum_hw || ext.current_best_hardware],
          ['Verdict', ext.verdict],
          ['PQChat protection', ext.protection_in_pqchat],
        ]);
      }

    } catch (err) {
      await animateLog('shors-log', [`Network error: ${err.message}`], 30);
      setVerdict('shors-verdict', 'ERROR', false);
    } finally {
      document.getElementById('shors-log')?.classList.remove('running');
    }
  }

  // ─── BKZ Lattice Simulation ─────────────────────────────────────────────

  async function runLattice() {
    setVerdict('lattice-verdict', 'RUNNING...', null);
    try {
      const res = await fetch('/api/simulate/lattice');
      const scenarios = await res.json();

      // Display each scenario
      const tableRows = [['Parameter Set', 'Classical Complexity', 'Quantum Complexity', 'Verdict']];
      const logLines = [];

      for (const s of scenarios) {
        tableRows.push([
          s.label,
          s.classical_complexity,
          s.quantum_complexity,
          s.secret_recovered ? '❌ BROKEN' : '✅ SECURE',
        ]);
        logLines.push(`[${s.label}]`);
        logLines.push(`  Classical: ${s.classical_complexity}`);
        logLines.push(`  Quantum:   ${s.quantum_complexity}`);
        logLines.push(`  Verdict:   ${s.verdict}`);
        if (s.elapsed != null) logLines.push(`  Time:      ${s.elapsed}s`);
        logLines.push('');
      }

      await animateLog('lattice-log', logLines, 50);
      renderTable('lattice-table', tableRows);

      const secure = scenarios.filter(s => !s.secret_recovered);
      setVerdict('lattice-verdict',
        `${secure.length}/${scenarios.length} parameter sets infeasible to attack`,
        secure.length > 2
      );
    } catch (err) {
      setVerdict('lattice-verdict', `ERROR: ${err.message}`, false);
    }
  }

  // ─── Grover's Analysis ──────────────────────────────────────────────────

  async function runGrover() {
    setVerdict('grover-verdict', 'RUNNING...', null);
    try {
      const res = await fetch('/api/simulate/grover');
      const results = await res.json();

      const tableRows = [['Algorithm', 'Key Bits', 'Classical', 'Quantum (Grover)', 'PQ Safe?']];
      const logLines = ['Analyzing Grover\'s algorithm impact on PQChat primitives...', ''];

      for (const r of results) {
        tableRows.push([
          r.algorithm,
          r.key_bits,
          r.classical_security,
          r.quantum_security_grover,
          r.post_quantum_safe ? '✅ YES' : '⚠️ NO',
        ]);
        logLines.push(`${r.algorithm}`);
        logLines.push(`  Classical: ${r.classical_security}`);
        logLines.push(`  Quantum:   ${r.quantum_security_grover}`);
        logLines.push(`  ${r.verdict}`);
        if (r.note) logLines.push(`  Note: ${r.note}`);
        logLines.push('');
      }

      await animateLog('grover-log', logLines, 50);
      renderTable('grover-table', tableRows);

      const allSafe = results.filter(r => r.used_in_project).every(r => r.post_quantum_safe);
      setVerdict('grover-verdict',
        allSafe
          ? '✅ All PQChat primitives meet NIST 128-bit quantum security minimum'
          : '⚠️ Some primitives below NIST threshold',
        allSafe
      );
    } catch (err) {
      setVerdict('grover-verdict', `ERROR: ${err.message}`, false);
    }
  }

  // ─── Full Comparison ────────────────────────────────────────────────────

  async function runFullComparison() {
    document.getElementById('full-comparison-running')?.classList.remove('hidden');
    try {
      const [extRes] = await Promise.all([
        fetch('/api/simulate/extrapolate'),
      ]);
      const ext = await extRes.json();

      const tableRows = [
        ['Algorithm', 'Attack', 'Classical Security', 'Quantum Security', 'Verdict'],
        [
          'ECDHE P-256', "Shor's + QFT", '2^128', 'BROKEN ✗',
          ext.ecdhe_p256?.verdict || '—',
        ],
        [
          'Kyber768 (ML-KEM)', 'BKZ Lattice', '2^178', '2^178 ✓',
          ext.kyber768_ml_kem?.verdict || '—',
        ],
        [
          'AES-256-GCM', "Grover's", '2^256', '2^128 ✓',
          ext.aes_256_gcm?.verdict || '—',
        ],
        [
          'ML-DSA-65', 'None (lattice)', '2^128+', '2^128 ✓',
          ext.ml_dsa_65?.verdict || '—',
        ],
      ];

      renderTable('full-comparison-table', tableRows);
    } catch (err) {
      console.error('Full comparison error:', err);
    } finally {
      document.getElementById('full-comparison-running')?.classList.add('hidden');
    }
  }

  // ─── Defense Status Panel ───────────────────────────────────────────────

  function renderDefenseStatus() {
    const statuses = {
      'status-ecdhe': { label: 'ECDHE P-256', status: '⚠️ VULNERABLE', cls: 'status-warn' },
      'status-kyber': { label: 'Kyber768', status: '✅ SECURE',     cls: 'status-ok' },
      'status-hybrid': { label: 'Hybrid',   status: '✅ PROTECTED', cls: 'status-ok' },
      'status-aes':   { label: 'AES-256',   status: '✅ SECURE',    cls: 'status-ok' },
      'status-sig':   { label: 'ML-DSA-65', status: '✅ SECURE',    cls: 'status-ok' },
    };
    for (const [id, info] of Object.entries(statuses)) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = `${info.label}: ${info.status}`;
        el.className = 'defense-item ' + info.cls;
      }
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────

  return {
    init() {
      renderDefenseStatus();
      runFullComparison();

      document.getElementById('btn-run-shors')
        ?.addEventListener('click', runShors);
      document.getElementById('btn-run-lattice')
        ?.addEventListener('click', runLattice);
      document.getElementById('btn-run-grover')
        ?.addEventListener('click', runGrover);
    },
    runShors,
    runLattice,
    runGrover,
  };
})();

document.addEventListener('DOMContentLoaded', () => SimulatorUI.init());
window.SimulatorUI = SimulatorUI;
