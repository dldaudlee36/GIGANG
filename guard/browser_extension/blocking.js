// Navigation aid, not a guarantee that an earlier paste/upload was prevented.
const GIGANGBlocking = (() => {
    const policyKey = 'gigangBlockPolicy';
    function domains(value) {
        return Array.isArray(value) ? value.filter(x => typeof x === 'string' &&
            /^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/i.test(x)).map(x => x.toLowerCase()) : [];
    }
    function matches(host, list) {
        return list.some(domain => host === domain || host.endsWith('.' + domain));
    }
    async function refresh() {
        try {
            const response = await fetch('http://127.0.0.1:8765/blocklist', {
                credentials:'omit', redirect:'error', signal:AbortSignal.timeout(2500)});
            if (!response.ok) throw new Error('POLICY_UNAVAILABLE');
            const body = await response.json();
            if (!Array.isArray(body.blocked_domains)) throw new Error('INVALID_POLICY');
            const list = domains(body.blocked_domains);
            await chrome.storage.local.set({[policyKey]:list});
            return list;
        } catch {
            return domains((await chrome.storage.local.get(policyKey))[policyKey]);
        }
    }
    async function show(tabId, host, reason, eventType='') {
        if(reason==='policy') {
            void fetch('http://127.0.0.1:8765/site-blocked',{method:'POST',headers:{'Content-Type':'application/json'},
                body:JSON.stringify({target:host}),credentials:'omit',redirect:'error',signal:AbortSignal.timeout(10000)}).catch(()=>{});
        }
        if(await GIGANGMode.paused()) return;
        const params = new URLSearchParams({site:host, reason, event:eventType});
        await chrome.tabs.update(tabId, {url:chrome.runtime.getURL('blocked.html')+'?'+params});
    }
    chrome.webNavigation.onBeforeNavigate.addListener(details => {
        if (details.frameId !== 0 || details.tabId < 0) return;
        void (async () => {
            const url = new URL(details.url);
            if (!['http:','https:'].includes(url.protocol)) return;
            if(await GIGANGMode.paused()) return;
            const list = await refresh();
            if (!matches(url.hostname, list) || await permission(url.hostname)) return;
            const tab = await chrome.tabs.get(details.tabId);
            // Avoid overwriting an unrelated navigation while fetching policy.
            if ((tab.pendingUrl || tab.url) !== details.url) return;
            await show(details.tabId, url.hostname, 'policy');
        })().catch(() => {});
    });
    // 이미 열려 있는 탭도 정책에 걸리면 차단 화면으로 보낸다(탐색 이벤트만으로는 못 막는 구멍).
    async function sweep(list) {
        if (!list.length || await GIGANGMode.paused()) return;
        const tabs = await chrome.tabs.query({url:['http://*/*','https://*/*']});
        for (const tab of tabs) {
            try {
                const host = new URL(tab.url).hostname;
                if (!matches(host, list) || await permission(host)) continue;
                await show(tab.id, host, 'policy');
            } catch {}
        }
    }
    async function refreshAndSweep() { await sweep(await refresh()); }
    chrome.alarms.onAlarm.addListener(alarm => {
        if (alarm.name === 'gigang-policy') void refreshAndSweep();
    });
    chrome.runtime.onInstalled.addListener(() => {
        void chrome.alarms.create('gigang-policy', {periodInMinutes:0.5});
        void refreshAndSweep();
    });
    chrome.runtime.onStartup.addListener(() => {
        void chrome.alarms.create('gigang-policy', {periodInMinutes:0.5});
        void refreshAndSweep();
    });
    async function permission(host) {
        try {
            const response=await fetch('http://127.0.0.1:8765/site-permission?domain='+encodeURIComponent(host),
                {credentials:'omit',redirect:'error',signal:AbortSignal.timeout(8000)});
            const body=await response.json();
            return response.ok && body.allowed && Date.parse(body.authorization?.expires_at)>Date.now() ? body.authorization : null;
        } catch { return null; }
    }
    return {show, refresh, sweep, matches, permission};
})();
