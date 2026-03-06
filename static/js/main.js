/**
 * Crucible Interface Logic - Deep Scan Edition
 */

// 1. Handle Copying Payloads with Feedback
function copyPayload(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonElement.innerText;
        buttonElement.innerText = "Copied!";
        // Use the CSS variables for consistent styling
        buttonElement.style.borderColor = "var(--green)";
        buttonElement.style.color = "var(--green)";

        setTimeout(() => {
            buttonElement.innerText = originalText;
            buttonElement.style.borderColor = "var(--border)";
            buttonElement.style.color = "var(--text)";
        }, 1500);
    });
}

// 2. Loading State Transition (Enhanced for Deep Scan)
function showLoading() {
    const greetView = document.querySelector('.greet-view');
    const container = document.querySelector('.container');

    if (document.querySelector('.loading-view')) return;

    const loadingView = document.createElement('section');
    loadingView.className = 'view loading-view';
    
    // Updated HTML to reflect the two-phase deep scan
    loadingView.innerHTML = `
        <div class="spinner"></div>
        <h3>Deep Audit in Progress...</h3>
        <p id="phase-text">Phase 1: Mapping Forms & SQLi Analysis</p>
        <small style="color: var(--text-muted); display: block; margin-top: 10px;">
            This usually takes 45-90 seconds. Do not refresh.
        </small>
    `;

    if (greetView) {
        greetView.style.display = 'none';
        container.appendChild(loadingView);
        
        // Dynamic status switcher to make the UI feel alive
        const phaseText = document.getElementById('phase-text');
        setTimeout(() => {
            if (phaseText) phaseText.innerText = "Phase 2: Reflected XSS Detection & Payload Injection";
        }, 30000); // Switches text after 30 seconds
    }
}

// 3. UI Interactions & Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Target the NEW /deep_scan route
    const scanForm = document.querySelector('form[action="/deep_scan"]');
    
    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            // Check if the URL is valid before showing loading
            const urlInput = scanForm.querySelector('input[name="target_url"]');
            if (urlInput.value.trim() !== "") {
                showLoading();
            }
        });
    }

    // Auto-focus the URL input
    const urlInput = document.querySelector('input[name="target_url"]');
    if (urlInput) {
        urlInput.focus();
    }
});