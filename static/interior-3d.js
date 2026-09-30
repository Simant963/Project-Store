(() => {
    const sidebar = document.querySelector('#adminSidebar');
    const menu = document.querySelector('#sidebarToggle');
    if (sidebar && menu) {
        const mobile = matchMedia('(max-width: 991.98px)');
        const main = document.querySelector('.admin-main');
        menu.setAttribute('aria-controls', sidebar.id);
        const syncMenu = () => {
            const open = sidebar.classList.contains('open');
            menu.setAttribute('aria-expanded', String(open));
            sidebar.inert = mobile.matches && !open;
            if (main) main.inert = mobile.matches && open;
            if (mobile.matches && !open && sidebar.contains(document.activeElement)) menu.focus();
            if (mobile.matches && open && !sidebar.contains(document.activeElement)) {
                sidebar.querySelector('a,button')?.focus();
            }
        };
        new MutationObserver(syncMenu).observe(sidebar, { attributes: true, attributeFilter: ['class'] });
        mobile.addEventListener('change', syncMenu);
        document.addEventListener('keydown', event => {
            if (!mobile.matches || !sidebar.classList.contains('open')) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                menu.click();
                syncMenu();
                menu.focus();
            } else if (event.key === 'Tab') {
                const links = [...sidebar.querySelectorAll('a[href],button:not(:disabled)')].filter(el => el.getClientRects().length);
                const first = links[0], last = links[links.length - 1];
                if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
                else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
            }
        });
        syncMenu();
    }
    const choices = [
        ['.marketplace-hero .container', 'THE APP UNIVERSE', 'Find something out of the ordinary.'],
        ['.public-app-hero .container', 'INDEPENDENT IDEAS', 'Discover the people behind the pixels.'],
        ['.login-aside-copy', 'WELCOME TO YOUR ORBIT', 'Your next chapter starts here.'],
        ['.admin-main', 'MISSION CONTROL', 'A trusted universe starts with you.'],
        ['.member-dashboard main', 'YOUR APP UNIVERSE', 'Make room for what comes next.'],
        ['.submission-shell', 'CREATOR STUDIO', 'Give your idea a new dimension.'],
        ['.register-form-wrap', 'JOIN THE UNIVERSE', 'Big ideas start small.'],
    ];
    const choice = choices.find(([selector]) => document.querySelector(selector));
    if (!choice) return;
    const host = document.querySelector(choice[0]);
    const banner = document.createElement('section');
    banner.className = 'dimension-banner';
    const caption = document.createElement('div');
    caption.className = 'dimension-caption';
    const label = document.createElement('small');
    label.textContent = choice[1];
    const title = document.createElement('p');
    title.textContent = choice[2];
    caption.append(label, title);
    const art = document.createElement('div');
    art.className = 'dimension-art';
    art.setAttribute('aria-hidden', 'true');
    const cube = document.createElement('div');
    cube.className = 'dimension-cube';
    for (let index = 0; index < 6; index++) {
        const face = document.createElement('span');
        face.className = 'dimension-face';
        face.textContent = '+';
        cube.append(face);
    }
    art.append(cube);
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'dimension-toggle';
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    let paused = false;
    const update = () => {
        banner.classList.toggle('dimension-paused', paused || reduced.matches || document.hidden);
        toggle.textContent = reduced.matches ? 'Motion reduced' : paused ? 'Resume motion' : 'Pause motion';
        toggle.disabled = reduced.matches;
        toggle.setAttribute('aria-pressed', String(paused || reduced.matches));
    };
    toggle.addEventListener('click', () => { paused = !paused; update(); });
    document.addEventListener('visibilitychange', update);
    reduced.addEventListener('change', update);
    banner.append(caption, art, toggle);
    host.prepend(banner);
    if ('IntersectionObserver' in window) new IntersectionObserver(([entry]) => {
        banner.classList.toggle('dimension-offscreen', !entry.isIntersecting);
    }).observe(banner);
    update();
})();
