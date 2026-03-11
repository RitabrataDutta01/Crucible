/**
 * Crucible Interface Logic - Deep Scan Edition
 */

/* ── 1. Sidebar Toggle Logic ── */
function toggleSidebar() {
    const sb = document.getElementById('ai-sidebar');
    sb.classList.toggle('collapsed');
}

/* ── 2. The AI Analyst Bridge (MCP Connection) ── */
async function fetchAiInsight() {
    const term = document.getElementById('ai-terminal');
    const btn = document.getElementById('ai-btn');
    const sel = document.getElementById('ai-finding-select');

    // Get the specific finding ID selected by the user
    const findingId = sel ? sel.value : 'all';

    btn.disabled = true;
    btn.innerHTML = '<span class="animate-pulse">Consulting Gemini...</span>';
    term.innerHTML = '<p class="prompt">Accessing Audit Archives via MCP...</p>';

    try {
        // We pass the findingId to the Flask bridge as a query parameter
        const response = await fetch(`/get_ai_analysis?id=${findingId}`);
        const data = await response.json();

        // Inject the AI response into the terminal
        term.innerHTML = `<div class="text-[#8b949e] whitespace-pre-wrap">${data.analysis}</div>`;
        term.scrollTop = term.scrollHeight; // Auto-scroll
    } catch (err) {
        term.innerHTML = '<p class="text-red-500 font-mono">CRITICAL ERROR: AI AUDITOR UNREACHABLE</p>';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Fetch AI Insight';
    }
}

/* ── 3. Enhanced Scan Progress UI ── */
function startScan(e) {
    const urlInput = document.getElementById('target-url');
    const url = urlInput.value.trim();

    if (!url) {
        // Flash red if URL is missing
        urlInput.classList.add('border-danger');
        setTimeout(() => urlInput.classList.remove('border-danger'), 1000);
        e.preventDefault();
        return;
    }

    const btn = document.getElementById('scan-btn');
    const progressWrap = document.getElementById('scan-progress-wrap');
    const bar = document.getElementById('scan-bar');
    const pct = document.getElementById('scan-pct');
    const statusText = document.getElementById('scan-status-text');

    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Audit in Progress...';
    lucide.createIcons(); // Refresh icons for the loading state

    progressWrap.classList.remove('hidden');

    // Simulated visual phases while backend works
    const phases = [
        [15, 'Phase 1: Mapping Forms & SQLi Analysis'],
        [45, 'Phase 1.5: Crawling Hidden Endpoints...'],
        [75, 'Phase 2: Reflected XSS Detection & Payload Injection'],
        [90, 'Phase 2.5: Verifying DOM-based Vectors...'],
        [100, 'Consolidating Findings...']
    ];

    let currentPhase = 0;
    const interval = setInterval(() => {
        if (currentPhase >= phases.length) {
            clearInterval(interval);
            return;
        }
        const [progress, msg] = phases[currentPhase++];
        bar.style.width = progress + '%';
        pct.textContent = progress + '%';
        statusText.textContent = msg;
    }, 2500);

    // IMPORTANT: No e.preventDefault() here so the form reaches Flask!
}

/* ── 4. Dynamic Modal Logic ── */
function openModal(payload) {
    const overlay = document.getElementById('modal-overlay');
    const modalPayload = document.getElementById('modal-payload');

    // Set the text content of the modal to the specific payload
    modalPayload.textContent = payload;
    overlay.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
}

/* ── 5. Global Init ── */
document.addEventListener('DOMContentLoaded', () => {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
});