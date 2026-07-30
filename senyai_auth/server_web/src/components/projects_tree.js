document.addEventListener("show.bs.collapse", e => {
    const icon = document.querySelector(
        `[data-bs-target="#${e.target.id}"] .folder-check`
    );
    icon?.classList.replace("bi-folder-plus", "bi-folder-minus");
});

document.addEventListener("hide.bs.collapse", e => {
    const icon = document.querySelector(
        `[data-bs-target="#${e.target.id}"] .folder-check`
    );
    icon?.classList.replace("bi-folder-minus", "bi-folder-plus");
});
