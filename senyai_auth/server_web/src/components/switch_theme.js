document.addEventListener("DOMContentLoaded", () => {
    const themeToggleButton = document.getElementById("themeToggle");
    const body = document.body;

    // Проверяем сохраненную тему в localStorage
    if (localStorage.getItem("theme") === "dark") {
        switchTheme("dark");
    } else {
        switchTheme("light");
    }

    function switchTheme(theme) {
        document.documentElement.setAttribute("data-bs-theme", theme);
    }

    // Обработчик смены темы
    themeToggleButton.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-bs-theme");
        const newTheme = currentTheme === "light" ? "dark" : "light"
        switchTheme(newTheme);
        themeToggle.innerHTML = currentTheme === "light" ? '<i class="bi bi-sun-fill"></i>' : '<i class="bi bi-moon-stars-fill"></i>';
        localStorage.setItem("theme", newTheme);
    });
});