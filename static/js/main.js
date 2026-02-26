/**
 * Crucible Interface Logic
 */

// 1. Handle Copying Payloads with Feedback
function copyPayload(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        // Change button appearance to show success using your CSS variables
        const originalText = buttonElement.innerText;
        buttonElement.innerText = "Copied!";
        buttonElement.style.borderColor = "var(--green)";
        buttonElement.style.color = "var(--green)";

        // Revert after 1.5 seconds
        setTimeout(() => {
            buttonElement.innerText = originalText;
            buttonElement.style.borderColor = "var(--border)";
            buttonElement.style.color = "var(--text)";
        }, 1500);
    });
}

// 2. Loading State Transition
function showLoading() {
    const greetView = document.querySelector('.greet-view');
    const container = document.querySelector('.container');

    // Check if the loading view already exists to prevent duplicates
    if (document.querySelector('.loading-view')) return;

    // Create the loading view structure dynamically
    const loadingView = document.createElement('section');
    loadingView.className = 'view loading-view';
    loadingView.innerHTML = `
        <div class="spinner"></div>
        <h3>Audit in Progress...</h3>
        <p>Crucible is mapping forms and injecting payloads. This usually takes 45-60 seconds.</p>
    `;

    // Swap the views
    if (greetView) {
        greetView.style.display = 'none';
        container.appendChild(loadingView);
    }
}

// 3. UI Interactions & Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Prevent multiple form submissions
    const scanForm = document.querySelector('form[action="/scan"]');
    if (scanForm) {
        scanForm.addEventListener('submit', () => {
            showLoading();
        });
    }

    // Optional: Auto-focus the URL input for better UX
    const urlInput = document.querySelector('input[name="target_url"]');
    if (urlInput) {
        urlInput.focus();
    }
});