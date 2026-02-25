/**
 * Crucible Interface Logic
 */

// 1. Handle Copying Payloads with Feedback
function copyPayload(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        // Change button appearance to show success
        const originalText = buttonElement.innerText;
        buttonElement.innerText = "Copied!";
        buttonElement.style.borderColor = "var(--green)";
        buttonElement.style.color = "var(--green)";

        // Revert after 2 seconds
        setTimeout(() => {
            buttonElement.innerText = originalText;
            buttonElement.style.borderColor = "var(--border)";
            buttonElement.style.color = "var(--text)";
        }, 2000);
    });
}

// 2. Loading State Transition
// This function hides the input form and shows the spinner immediately 
// so the user knows the 50-second scan has started.
function showLoading() {
    const greetView = document.querySelector('.greet-view');
    const loadingView = document.createElement('section');
    
    // Create the loading view structure dynamically
    loadingView.className = 'view loading-view';
    loadingView.innerHTML = `
        <div class="spinner"></div>
        <h3>Audit in Progress...</h3>
        <p>Crucible is mapping forms and injecting payloads. Please do not refresh the page.</p>
    `;

    // Swap the views
    if (greetView) {
        greetView.style.display = 'none';
        greetView.parentNode.appendChild(loadingView);
    }
}

// 3. Optional: Add an "Enter" key listener for the search box
document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.querySelector('input[name="target_url"]');
    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                showLoading();
            }
        });
    }
});