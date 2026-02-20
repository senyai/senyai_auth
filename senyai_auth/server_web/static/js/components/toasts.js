export function initToasts() {
    document.body.addEventListener("successEvent", event => {
        const messages = event.detail.message;
        messages.forEach(element => {
            showToast("success", element);
        })
        // showToast("success", event.detail.message);
    });

    document.body.addEventListener("errorEvent", event => {
        const errors = event.detail.errors;
        errors.forEach(element => {
            showToast("danger", element)
        });
    });

    const container = document.getElementById("toast-container");
    container.addEventListener("focusin", (e) => e.stopPropagation());
}


function showToast(type, message) {
    const container = document.getElementById("toast-container");

    const toastEl = document.createElement("div");
    toastEl.className = `toast align-items-center text-bg-${type} border-0`;
    toastEl.role = "alert";
    toastEl.setAttribute("aria-live", "assertive");
    toastEl.setAttribute("aria-atomic", "true");

    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close me-2 m-auto" aria-label="Close"></button>
        </div>
    `;

    const closeBtn = toastEl.querySelector(".btn-close");
    closeBtn.addEventListener("click", (e) => {
        bsToast.hide();
        toastEl.remove();
    });

    container.appendChild(toastEl);

    const bsToast = new bootstrap.Toast(toastEl, { delay: 10000 });
    bsToast.show();
}
