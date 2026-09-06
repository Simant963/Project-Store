const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

if (!reducedMotion.matches) {
    document.querySelectorAll('[data-tilt]').forEach((element) => {
        let frame;
        const strength = Number(element.dataset.tiltStrength || 6);
        element.addEventListener('pointermove', (event) => {
            if (event.pointerType === 'touch') return;
            cancelAnimationFrame(frame);
            frame = requestAnimationFrame(() => {
                const box = element.getBoundingClientRect();
                element.style.setProperty('--tilt-x', `${(.5 - (event.clientY - box.top) / box.height) * strength}deg`);
                element.style.setProperty('--tilt-y', `${((event.clientX - box.left) / box.width - .5) * strength}deg`);
            });
        });
        element.addEventListener('pointerleave', () => {
            element.style.setProperty('--tilt-x', '0deg');
            element.style.setProperty('--tilt-y', '0deg');
        });
    });

    const reveal = new IntersectionObserver((entries) => entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        reveal.unobserve(entry.target);
    }), { threshold: .12 });
    document.querySelectorAll('.section-space, .category-strip').forEach((section) => {
        section.classList.add('motion-reveal');
        reveal.observe(section);
    });
}
