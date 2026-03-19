/**
 * Crucible Interface Logic - Deep Scan Edition
 */

/* ── 1. Sidebar Toggle Logic ── */
function toggleSidebar() {
    const sb = document.getElementById('ai-sidebar');
    sb.classList.toggle('collapsed');
}

/* ── 2. The AI Analyst Bridge (Typing Effect) ── */
async function fetchAiInsight() {
    const term = document.getElementById('ai-terminal');
    const btn = document.getElementById('ai-btn');
    const sel = document.getElementById('ai-finding-select');

    const findingId = sel ? sel.value : 'all';

    btn.disabled = true;
    btn.innerHTML = '<span class="animate-pulse">Consulting Gemini...</span>';
    term.innerHTML = '<p class="text-[#8b949e]">Initializing neural audit... Please wait.</p>';

    try {
        const response = await fetch(`/get_ai_analysis?id=${findingId}`);
        const data = await response.json();
        const text = data.analysis;

        term.innerHTML = ""; // Clear for typing effect
        let i = 0;
        
        function typeWriter() {
            if (i < text.length) {
                term.innerHTML += text.charAt(i) === '\n' ? '<br>' : text.charAt(i);
                i++;
                term.scrollTop = term.scrollHeight;
                setTimeout(typeWriter, 5);
            } else {
                btn.disabled = false;
                btn.textContent = 'Fetch AI Insight';
            }
        }
        typeWriter();

    } catch (err) {
        term.innerHTML = '<p class="text-red-500 font-mono">CRITICAL ERROR: AI AUDITOR UPLINK FAILED</p>';
        btn.disabled = false;
        btn.textContent = 'Retry Audit';
    }
}

/* ── 3. Enhanced Scan Progress UI ── */
function startScan(e) {
    const urlInput = document.getElementById('target-url');
    if (!urlInput.value.trim()) return;

    const btn = document.getElementById('scan-btn');
    const progressWrap = document.getElementById('scan-progress-wrap');
    const bar = document.getElementById('scan-bar');
    const pct = document.getElementById('scan-pct');
    const statusText = document.getElementById('scan-status-text');

    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Engine Active...';
    lucide.createIcons();

    progressWrap.classList.remove('hidden');

    const phases = [
        [10, 'Warming Engines...'],
        [25, 'Phase 1: Deep Crawl & Form Discovery'],
        [45, 'Phase 2: SQLi Payload Injection'],
        [65, 'Phase 3: Reflected XSS Validation'],
        [85, 'Phase 4: LFI Behavioral Analysis (500-Error Detection)'],
        [100, 'Consolidating Reports...']
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
    }, 3000);
}

/* ── 4. Dynamic Modal Logic ── */
function openModal(payload) {
    const overlay = document.getElementById('modal-overlay');
    const modalPayload = document.getElementById('modal-payload');
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