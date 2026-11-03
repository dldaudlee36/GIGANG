// Only the top frame polls; background coalesces ticks from multiple tabs.
(() => {
    if (window.top !== window) return;
    let pending = false;
    async function tick() {
        if (pending) return;
        pending = true;
        try { await chrome.runtime.sendMessage({type:'GIGANG_POLICY_TICK'}); }
        catch {} finally { pending = false; }
    }
    void tick();
    setInterval(tick, 1000);
    window.addEventListener('pageshow', tick);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) void tick(); });
})();
