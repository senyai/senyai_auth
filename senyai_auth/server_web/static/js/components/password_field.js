export function initPasswordField() {
    document.body.addEventListener("click", handleChange);

    document.body.addEventListener("htmx:configRequest", event => {
        const form = event.target.closest("[data-password-form]");
        if (!form) return;

        const valid = validatePasswordForm(form);

        if (!valid || !form.checkValidity()) {
            event.preventDefault();
            form.classList.add("was-validated");
        }
    });
}



function handleChange(event) {
    const button = event.target.closest("[data-password-show]")
    if (!button) return;
    // const button = event.target;
    // alert(button);
    const root = button.closest("[data-password-root]");
    const password = root.querySelector("input");

    password.type = password.type === "password" ? "text" : "password";
    const icon = button.querySelector("i");
    if (icon) {
        icon.classList.toggle("bi-eye");
        icon.classList.toggle("bi-eye-slash");
    }

}

function validatePasswordForm(form) {

    const newPassword = form.querySelector("[data-password-new]");
    const confirmPassword = form.querySelector("[data-password-confirm]");

    if (!newPassword || !confirmPassword) return;

    const match = newPassword.value === confirmPassword.value;

    if (!match) {
        confirmPassword.setCustomValidity("Passwords do not match!");
        confirmPassword.classList.add("is-invalid");
        return false;
    }

    confirmPassword.setCustomValidity("");
    confirmPassword.classList.remove("is-invalid");
    return true;
}