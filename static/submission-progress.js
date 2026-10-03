(() => {
    const root = document.querySelector('[data-submission-live]');
    if (!root) return;
    let fetching = false, actionBusy = false;
    const connection = document.querySelector('[data-submission-connection]');
    const announce = (text) => { if (connection) connection.textContent = text; };
    const localDates = () => document.querySelectorAll('time[data-local-time]').forEach((time) => {
        const raw = time.dateTime.replace(/Z$/, '');
        const date = new Date(/[+-]\d{2}:\d{2}$/.test(raw) ? raw : raw + 'Z');
        if (!Number.isNaN(date.getTime())) time.textContent = date.toLocaleString(undefined, { dateStyle:'medium', timeStyle:'short' });
    });
    async function refresh() {
        if (fetching || actionBusy || document.hidden || document.querySelector('.submission-confirm[open]')) return;
        if (document.activeElement?.closest('.submission-actions')) return;
        const nodes = [...document.querySelectorAll('[data-submission-progress]')];
        const ids = [...new Set(nodes.map(node => node.dataset.submissionProgress))];
        if (!ids.length) return;
        fetching = true;
        try {
            for (let offset=0; offset<ids.length; offset+=50) {
                const url = new URL(root.dataset.submissionLive, location.origin);
                url.searchParams.set('ids', ids.slice(offset,offset+50).join(','));
                if (root.dataset.submissionDetails) url.searchParams.set('details','1');
                const response = await fetch(url, { credentials:'same-origin', headers:{Accept:'application/json'} });
                if (!response.ok) throw new Error('Status updates unavailable');
                const data = await response.json();
                data.items.forEach(item => {
                    const panel = document.querySelector(`[data-submission-panel="${item.id}"]`);
                    const node = document.querySelector(`[data-submission-progress="${item.id}"]`);
                    const changed = node && node.dataset.revision !== String(item.revision);
                    if (panel && item.panel && (panel.dataset.revision !== String(item.revision) || panel.dataset.scanRunning !== (item.scan_running ? '1' : '0'))) panel.outerHTML = item.panel;
                    else if (node && node.dataset.revision !== String(item.revision)) node.outerHTML = item.html;
                    const actions = document.querySelector(`[data-submission-developer-actions="${item.id}"]`);
                    if (changed && actions && item.actions) actions.innerHTML = item.actions;
                    ['label','security','admin','publishing'].forEach(field => document.querySelectorAll(`[data-submission-${field}="${item.id}"]`).forEach(label => { label.textContent = item[field]; }));
                });
            }
            localDates(); announce('Live status updates · checked just now');
        } catch (_) { announce('Connection interrupted. Retrying automatically; your saved status is unchanged.'); }
        finally { fetching = false; }
    }
    const dialog = document.createElement('dialog');
    dialog.className = 'submission-confirm';
    dialog.setAttribute('aria-labelledby','submission-confirm-title');
    dialog.innerHTML = '<h2 id="submission-confirm-title">Confirm submission action</h2><p></p><form method="dialog"><button class="btn btn-outline-light" value="cancel">Cancel</button><button class="btn btn-primary" value="confirm">Confirm</button></form>';
    document.body.append(dialog);
    let activeForm = null, previousFocus = null;
    document.addEventListener('submit', event => {
        const form = event.target.closest('[data-submission-action]');
        if (!form) return;
        event.preventDefault();
        if (actionBusy) return;
        activeForm = form; previousFocus = document.activeElement;
        dialog.querySelector('p').textContent = form.dataset.confirm;
        dialog.returnValue = ''; dialog.showModal(); dialog.querySelector('[value="cancel"]').focus();
    });
    dialog.addEventListener('close', async () => {
        previousFocus?.focus();
        const form = activeForm; activeForm = null;
        if (dialog.returnValue !== 'confirm' || !form) return;
        const button = form.querySelector('button[type="submit"]');
        const original = button.textContent; button.disabled = true; button.textContent = 'Processing…'; actionBusy = true;
        announce('Updating submission…');
        let failureMessage = null;
        try {
            const response = await fetch(form.action, { method:'POST', body:new FormData(form), credentials:'same-origin', headers:{'X-Requested-With':'fetch'} });
            if (!response.ok) {
                let message = 'The action failed or this submission changed. Refresh its status and try again.';
                if (response.headers.get('content-type')?.includes('application/json')) message = (await response.json()).message || message;
                throw new Error(message);
            }
            // Scanning has an existing server-rendered report; navigate after completion.
            if (form.action.endsWith('/scan')) { location.assign(response.url); return; }
            announce('Submission updated successfully.');
            if (form.hasAttribute('data-reload-after')) { location.reload(); return; }
        } catch (error) { failureMessage = error.message; }
        finally { actionBusy = false; button.disabled = false; button.textContent = original; }
        document.activeElement?.blur();
        await refresh();
        if (failureMessage) announce(failureMessage + ' Latest saved status has been checked; retry if needed.');
    });
    if (root.dataset.submissionEvents && window.EventSource) {
        const events = new EventSource(root.dataset.submissionEvents);
        events.addEventListener('account-change', refresh);
        events.addEventListener('open', refresh);
        events.addEventListener('error', () => announce('Reconnecting · periodic updates remain enabled'));
    }
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
    setInterval(refresh, 15000); localDates(); refresh();
})();
