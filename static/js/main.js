function toggleSidebar() {
  document.getElementById('ai-sidebar').classList.toggle('collapsed');
  setTimeout(() => { if (typeof lucide !== 'undefined') lucide.createIcons(); }, 50);
}

function toggleReports(e) {
  e.stopPropagation();
  const menu = document.getElementById('reports-menu');
  menu.classList.toggle('hidden');
}
document.addEventListener('click', () => {
  const menu = document.getElementById('reports-menu');
  if (menu && !menu.classList.contains('hidden')) menu.classList.add('hidden');
});

async function fetchAiInsight() {
  const term = document.getElementById('ai-terminal');
  const btn = document.getElementById('ai-btn');
  const sel = document.getElementById('ai-finding-select');
  const findingId = sel ? sel.value : 'all';

  btn.disabled = true;
  btn.innerHTML = '<span class="pulse-dot inline-flex gap-0.5"><span class="w-1 h-1 rounded-full bg-white"></span><span class="w-1 h-1 rounded-full bg-white"></span><span class="w-1 h-1 rounded-full bg-white"></span></span> Consulting Gemini...';
  term.innerHTML =
    '<div class="flex items-center gap-2 text-[#8b949e] py-4"><span class="w-2 h-2 rounded-full bg-[#58a6ff] shimmer-bar" style="width:8px;height:8px;border-radius:50%;animation:pulse-dot 1s infinite"></span> Initializing neural audit...</div>';

  try {
    const response = await fetch(`/get_ai_analysis?id=${findingId}`);
    const data = await response.json();
    const text = data.analysis;
    term.innerHTML = '';
    let i = 0;

    function typeWriter() {
      if (i < text.length) {
        const ch = text.charAt(i);
        if (i === text.length - 1) {
          term.innerHTML += ch === '\n' ? '<br>' : ch;
        } else {
          term.innerHTML += ch === '\n' ? '<br>' : ch;
        }
        i++;
        term.scrollTop = term.scrollHeight;
        setTimeout(typeWriter, 3);
      } else {
        btn.disabled = false;
        btn.textContent = 'Fetch AI Insight';
      }
    }
    typeWriter();
  } catch (err) {
    term.innerHTML =
      '<div class="flex flex-col items-center gap-3 py-6"><span class="w-10 h-10 rounded-full bg-[#f851491a] flex items-center justify-center"><svg class="w-5 h-5 text-[#f85149]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></span><p class="text-[#f85149] text-[11px] font-mono text-center">AI Auditor Uplink Failed</p><p class="text-[#8b949e] text-[10px] font-mono text-center">Check your API key or network connection</p></div>';
    btn.disabled = false;
    btn.textContent = 'Retry Audit';
  }
}

function startScan(e) {
  const urlInput = document.getElementById('target-url');
  if (!urlInput.value.trim()) { e.preventDefault(); return; }

  const btn = document.getElementById('scan-btn');
  const progressWrap = document.getElementById('scan-progress-wrap');
  const statusText = document.getElementById('scan-status-text');

  btn.disabled = true;
  btn.innerHTML = '<span class="inline-flex gap-1"><span class="w-1.5 h-1.5 rounded-full bg-white pulse-dot"></span><span class="w-1.5 h-1.5 rounded-full bg-white pulse-dot"></span><span class="w-1.5 h-1.5 rounded-full bg-white pulse-dot"></span></span> Scanning...';
  if (typeof lucide !== 'undefined') lucide.createIcons();
  progressWrap.classList.remove('hidden');
  statusText.innerHTML = '<span class="w-2 h-2 rounded-full shimmer-bar inline-block mr-2" style="animation:pulse-dot 1s infinite"></span> Crawling target & injecting payloads...';
  setTimeout(() => {
    statusText.innerHTML = '<span class="w-2 h-2 rounded-full shimmer-bar inline-block mr-2" style="animation:pulse-dot 1s infinite"></span> Analyzing responses & generating findings...';
  }, 3000);
}

function openModal(btn) {
  const payload = JSON.parse(btn.dataset.payload);
  document.getElementById('modal-payload').textContent = payload;
  document.getElementById('modal-overlay').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
  document.body.style.overflow = '';
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof lucide !== 'undefined') lucide.createIcons();
  const params = new URLSearchParams(window.location.search);
  if (params.has('focus') && params.get('focus') === 'ai') {
    const sb = document.getElementById('ai-sidebar');
    if (sb) sb.classList.remove('collapsed');
  }
});
