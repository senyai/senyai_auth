document.addEventListener('shown.bs.tab', event => {
    // when a tab is shown and it is .stale, issue `updateStale` event
    if (event.target.classList.contains("stale")) {
        event.target.classList.remove("stale");
        htmx.trigger(
            event.target.getAttribute("data-bs-target"),
            "updateStale",
            {}
        );
    }
})

document.addEventListener('htmx:afterSettle', event => {
    // after tab data was updated, switch to current tab
    let target = event.target;
    if (target.id != "tabs-container" && target.getAttribute("hx-trigger") != "updateProjectInfo from:body") return;
    target = htmx.find("#tabs-container");
    let paneId = target.querySelector("ul[role='tablist']>li>button.active")
        ?.getAttribute("aria-controls") || "members-tab-pane"
    let currentPane = document.getElementById(paneId);
    htmx.toggleClass(currentPane, "show");
    htmx.toggleClass(currentPane, "active");
    target.querySelectorAll("ul[role='tablist']>li>button").forEach(trigger => {
        bootstrap.Tab.getInstance(trigger)?.dispose();
        new bootstrap.Tab(trigger);
    });
    if (paneId == "invites-tab-pane") {
        htmx.trigger(document.body, "updateInvitesTab", {});
    } else {
        htmx.find('#invites-tab')?.classList.add('stale');
    }
});