const state = {
    initial: new Set(),
    current: new Set()
}

export function getRolePayload() {
    return getRoleDiff();
}

export function initRoleEditor() {

    document.body.addEventListener("change", handleChange);

    document.body.addEventListener("htmx:configRequest", event => {
        if (!event.target.closest("[data-role-editor-root]")) return;

        const diff = getRoleDiff();
        // event.detail.parameters.added = diff.added;
        // event.detail.parameters.removed = diff.removed;
        event.detail.parameters.roles = diff;
        clearState();
    })


    document.body.addEventListener("htmx:load", event => {
        const root = event.target.querySelector("[data-role-editor-root]");
        if (!root) return;

        collectInitialState(root);
        syncSubmitButton(root);
    })

    const root = document.querySelector("[data-role-editor-root]")
    if (root) {
        collectInitialState(root);
        syncSubmitButton(root);
    }

    document.body.addEventListener("htmx:configRequest", e => {
        if (e.detail.elt.matches("[data-roles-request]")) {

        }
    });
}

export function getRoleDiff() {
    const added = [...state.current].filter(
        r => !state.initial.has(r)
    );

    const removed = [...state.initial].filter(
        r => !state.current.has(r)
    );
    return { added, removed };
}

export function hasChanged() {
    const diff = getRoleDiff();
    return diff.added.length > 0 || diff.removed.length > 0;
}

function clearState() {
    state.initial.clear();
    state.current.clear();
}

function collectInitialState() {
    clearState();
    document.querySelectorAll("[data-role-checkbox]").forEach(cb => {
        const roleId = cb.dataset.roleId;

        if (cb.checked) {
            state.initial.add(roleId);
            state.current.add(roleId);
        }
    });
}

function handleChange(event) {
    if (!event.target.matches("[data-role-checkbox]")) return;

    const checkbox = event.target;
    const roleId = checkbox.dataset.roleId;

    if (checkbox.checked) {
        state.current.add(roleId);
    } else {
        state.current.delete(roleId);
    }

    highlightChange(checkbox, roleId);

    const root = checkbox.closest("[data-role-editor-root]");
    syncSubmitButton(root);

}

function highlightChange(checkbox, roleId) {
    const container = checkbox.closest("div");

    container.classList.remove("role-changed");

    const wasInitially = state.initial.has(roleId);
    const isNow = state.current.has(roleId);

    if (wasInitially != isNow) {
        container.classList.add("role-changed");
    }
}

function hasChanges() {
    return state.initial.size != state.current.size || [...state.current].some(r => !state.initial.has(r));
}

function syncSubmitButton(root) {
    const button = document.querySelector("[data-role-submit]");
    if (!button) return;
    button.disabled = !hasChanges();
}