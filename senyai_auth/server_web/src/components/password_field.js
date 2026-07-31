/*
Show and hide password in password fields
*/
document.body.addEventListener("click", event => {
    const button = event.target.closest("[data-password-show]")
    if (!button) return;
    const root = button.closest("[data-password-root]");
    const password = root.querySelector("input");

    password.type = password.type === "password" ? "text" : "password";
    const icon = button.querySelector("i");
    if (icon) {
        icon.classList.toggle("bi-eye");
        icon.classList.toggle("bi-eye-slash");
    }
});