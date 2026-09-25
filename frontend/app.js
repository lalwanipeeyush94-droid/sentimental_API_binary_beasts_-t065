document.addEventListener("DOMContentLoaded", () => {

    const menuButton = document.querySelector(".mobile-menu");
    const sidebar = document.querySelector(".sidebar");

    if (menuButton && sidebar) {
        menuButton.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }

    const current = window.location.pathname.split("/").pop() || "index.html";

    document.querySelectorAll(".nav a").forEach(link => {
        const href = link.getAttribute("href");

        if (href === current) {
            link.classList.add("active");
        }
    });
});

function escapeHTML(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatDate(value) {
    if (!value) return "—";

    try {
        return new Date(value).toLocaleString();
    } catch {
        return value;
    }
}

function getArray(data) {
    if (Array.isArray(data)) return data;

    if (Array.isArray(data.items)) return data.items;
    if (Array.isArray(data.results)) return data.results;
    if (Array.isArray(data.data)) return data.data;

    return [];
}