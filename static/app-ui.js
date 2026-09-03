document.querySelectorAll('[data-loading-form]').forEach((form) => {
    form.addEventListener('submit', () => {
        const button = form.querySelector('button[type="submit"]');
        if (!button || !form.checkValidity()) return;
        button.disabled = true;
        button.dataset.originalText = button.innerHTML;
        button.textContent = button.dataset.loadingText || 'Working…';
    });
});

const sidebar = document.getElementById('adminSidebar');
const backdrop = document.getElementById('sidebarBackdrop');
const toggle = document.getElementById('sidebarToggle');
if (sidebar && backdrop && toggle) {
    const closeSidebar = () => {
        sidebar.classList.remove('open');
        backdrop.classList.remove('show');
    };
    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        backdrop.classList.toggle('show');
    });
    backdrop.addEventListener('click', closeSidebar);
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeSidebar();
    });
}
