document.addEventListener("htmx:confirm", function(e) {
    if (!e.detail.question) return;
    e.preventDefault();

    const modal = document.getElementById("modalContent");
    modal.innerHTML = `
        <div class="modal-header">
            <h1 class="modal-title fs-5">${i18n['confirmation']}</h1>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">${e.detail.question}</div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">${i18n['close']}</button>
            <button type="button" class="btn btn-danger" data-bs-dismiss="modal">${i18n['confirm']}</button>
        </div>
    `;
    const issueRequest = e.detail.issueRequest;
    modal.querySelector(".btn-danger").addEventListener("click", e => issueRequest(true));
    getModal().show();
})
