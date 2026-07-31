import { initRoleEditor } from "./components/role_editor.js";
import { initToasts } from "./components/toasts.js";
import "./components/password_field.js"
import "./components/switch_theme.js"
import "./components/confirm_dialog.js"
import "./components/projects_tree.js"
import "./components/tabs.js"


initRoleEditor();
initToasts();

const modalEl = document.getElementById("baseModal");
export function getModal() {
    return bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
}
document.body.addEventListener("closeModal", () => {
    bootstrap.Modal.getInstance(modalEl)?.hide();
});
modalEl.addEventListener('hidden.bs.modal', () => {
    document.getElementById('modalContent').innerHTML = '';
});
modalEl.addEventListener('shown.bs.modal', () => {
    document.getElementById('modalContent').querySelector("[autofocus]")?.focus();
});
