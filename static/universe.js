(() => {
    const scene = document.querySelector('.scene');
    const sculpture = document.querySelector('.sculpture');
    const toggle = document.querySelector('#motionToggle');
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    let paused = reduced.matches;
    let frame;
    const update = () => {
        document.body.classList.toggle('motion-paused', paused || reduced.matches || document.hidden);
        toggle.textContent = reduced.matches ? 'Reduced motion enabled' : paused ? 'Resume motion' : 'Pause motion';
        toggle.setAttribute('aria-pressed', String(paused || reduced.matches));
        toggle.disabled = reduced.matches;
    };
    toggle.addEventListener('click', () => { paused = !paused; update(); });
    reduced.addEventListener('change', update);
    document.addEventListener('visibilitychange', update);
    new IntersectionObserver(([entry]) => scene.classList.toggle('scene-offscreen', !entry.isIntersecting)).observe(scene);
    scene.addEventListener('pointermove', event => {
        if (paused || reduced.matches || event.pointerType === 'touch') return;
        cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => {
            const rect = scene.getBoundingClientRect();
            sculpture.style.setProperty('--ry', `${(event.clientX - rect.left - rect.width / 2) / rect.width * 16}deg`);
            sculpture.style.setProperty('--rx', `${-(event.clientY - rect.top - rect.height / 2) / rect.height * 12}deg`);
        });
    });
    scene.addEventListener('pointerleave', () => {
        cancelAnimationFrame(frame);
        sculpture.style.setProperty('--rx', '0deg');
        sculpture.style.setProperty('--ry', '0deg');
    });
    update();
})();
