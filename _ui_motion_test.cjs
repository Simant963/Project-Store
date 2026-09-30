// Run with node _ui_motion_test.cjs. No browser or extra packages required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function element() {
    const classes = new Set();
    return {
        children: [], attributes: {}, events: {},
        style: { setProperty() {} },
        classList: { toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }, contains(name) { return classes.has(name); } },
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener(name, callback) { this.events[name] = callback; },
        append(...children) { this.children.push(...children); },
        prepend(child) { this.children.unshift(child); },
    };
}
for (const file of ['interior-3d.js', 'universe.js']) {
    const host = element(), body = element(), button = element();
    const media = { matches: true, addEventListener(name, callback) { this.change = callback; } };
    const document = {
        body, hidden: false, events: {}, createElement: element,
        addEventListener(name, callback) { this.events[name] = callback; },
        querySelector(selector) {
            if (selector === '#motionToggle') return button;
            if (['.scene', '.sculpture', '.marketplace-hero .container'].includes(selector)) return host;
            return null;
        },
    };
    const context = { document, matchMedia: () => media, window: {}, IntersectionObserver: class { observe() {} } };
    vm.runInNewContext(fs.readFileSync(`${__dirname}/static/${file}`, 'utf8'), context);
    const control = file === 'universe.js' ? button : host.children[0].children[2];
    assert.equal(control.disabled, true, `${file}: reduced motion disables animation control`);
    assert.equal(control.attributes['aria-pressed'], 'true');
    media.matches = false;
    media.change();
    assert.equal(control.disabled, false);
    const previous = control.attributes['aria-pressed'];
    control.events.click();
    assert.notEqual(control.attributes['aria-pressed'], previous, `${file}: pause toggles`);
    document.hidden = true;
    document.events.visibilitychange();
    const target = file === 'universe.js' ? body : host.children[0];
    assert(target.classList.contains(file === 'universe.js' ? 'motion-paused' : 'dimension-paused'));
}
console.log('ui-motion-tests-passed');
