export function initPasswordField() {
    document.body.addEventListener("click", handleChange);
}



function handleChange(event) {
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

}
