importScripts('lifecycle.js', 'blocking.js');
importScripts('matching.js');
importScripts('image_match.js', 'image_background.js');
const AGENT = 'http://127.0.0.1:8765';

function eventMetadata(message, sender) {
    const site = new URL(sender.url);
    if (!['http:', 'https:'].includes(site.protocol)) throw new Error('INVALID_SITE');
    const input = message.metadata;
    if (!input || typeof input !== 'object') throw new Error('INVALID_METADATA');
    const stamp = new Date(input.timestamp);
    if (typeof input.timestamp !== 'string' || !Number.isFinite(stamp.getTime())) throw new Error('INVALID_METADATA');

    const data = {target: site.hostname, timestamp: stamp.toISOString()};
    for (const key of ['pattern_hits','text_length','inspectable','reason','file_kind']) {
        if(input[key] !== undefined) data[key] = input[key];
    }
    if (message.event_type === 'COPY_ATTEMPT') {
        if (site.origin !== 'https://desktop-oli.tail2bbbea.ts.net' || site.pathname !== '/db' ||
            input.detection_scope !== 'customer_table') throw new Error('INVALID_SITE');
        Object.assign(data, {source_path: '/db', detection_scope: 'customer_table'});
        return {path: '/copy-event', data, key: 'lastCopy'};
    }
    if (['DOWNLOAD_STARTED', 'DOWNLOAD_COMPLETED', 'DOWNLOAD_INTERRUPTED'].includes(message.event_type)) {
        if (site.origin !== 'https://desktop-oli.tail2bbbea.ts.net' || site.pathname !== '/db/download') throw new Error('INVALID_SITE');
        if (!Number.isSafeInteger(input.download_id) || input.download_id < 0) throw new Error('INVALID_METADATA');
        Object.assign(data, {source_path: '/db/download', download_id: input.download_id,
            download_state: input.download_state, file_name: input.file_name || ''});
        if (Number.isSafeInteger(input.file_size) && input.file_size >= 0) data.file_size = input.file_size;
        return {path: '/download-event', data, key: 'lastDownload'};
    }
    if (message.event_type === 'PASTE_ATTEMPT') {
        if (!Number.isSafeInteger(input.text_length) || input.text_length < 0 || input.text_length > 100000000) {
            throw new Error('INVALID_METADATA');
        }
        data.text_length = input.text_length;
        if (input.image_count !== undefined) {
            if (!Number.isSafeInteger(input.image_count) || input.image_count <= 0 || input.image_count > 1000 ||
                !Number.isSafeInteger(input.image_bytes) || input.image_bytes < 0) throw new Error('INVALID_METADATA');
            data.image_count = input.image_count;
            data.image_bytes = input.image_bytes;
        }
        if (data.text_length === 0 && !data.image_count) throw new Error('INVALID_METADATA');
        return {path: '/paste-event', data, key: 'lastPaste'};
    }
    if (message.event_type === 'FILE_UPLOAD_ATTEMPT') {
        if (typeof input.file_name !== 'string' || input.file_name.length > 1024 ||
            !Number.isSafeInteger(input.file_size) || input.file_size < 0) {
            throw new Error('INVALID_METADATA');
        }
        data.file_name = input.file_name;
        data.file_size = input.file_size;
        if (input.method !== undefined) {
            if (input.method !== 'drop') throw new Error('INVALID_METADATA');
            data.method = input.method;
        }
        return {path: '/upload-event', data, key: 'lastUpload'};
    }
    throw new Error('INVALID_EVENT');
}

async function saveStatus(key, value) {
    try {
        const previous = (await chrome.storage.local.get(key))[key];
        if (!previous || previous.timestamp <= value.timestamp) {
            await chrome.storage.local.set({[key]: value});
        }
    } catch {}
}

async function deliver(message, sender) {
    if(await GIGANGMode.paused()) return {status:'paused'};
    let parsed;
    try {
        parsed = eventMetadata(message, sender);
    } catch (error) {
        return {status: 'failed', error: error.message};
    }

    const observed = Date.now();
    const trace = message.trace_id || crypto.randomUUID();
    parsed.data.trace_id = trace;
    const kind = message.event_type === 'PASTE_ATTEMPT' ? 'text' : 'file';
    if (['PASTE_ATTEMPT','FILE_UPLOAD_ATTEMPT'].includes(message.event_type)) {
        Object.assign(parsed.data, await MatchStore.match(kind, message.fingerprint, parsed.data.target, observed));
        if(parsed.data.source_inspection) {
            for(const key of ["pattern_hits","inspectable","reason","file_kind"])
                if(parsed.data.source_inspection[key]!==undefined) parsed.data[key]=parsed.data.source_inspection[key];
            delete parsed.data.source_inspection;
        }
    } else {
        parsed.data.match_status = MatchStore.isDigest(message.fingerprint) ? 'source_recorded' : 'not_checked';
    }
    if (['PASTE_ATTEMPT','FILE_UPLOAD_ATTEMPT'].includes(message.event_type)) {
        const grant=await GIGANGBlocking.permission(parsed.data.target);
        if(grant) parsed.data.authorization=grant;
    }
    if (parsed.data.match_status === 'matched' && sender.tab && !parsed.data.authorization) {
        await GIGANGBlocking.show(sender.tab.id, parsed.data.target, 'matched', message.event_type).catch(() => {});
    }
    const record = {event_type: message.event_type, ...parsed.data};
    try {
        const response = await fetch(AGENT + parsed.path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({...parsed.data, event_type: message.event_type}),
            signal: AbortSignal.timeout(12000),
            credentials: 'omit',
            redirect: 'error'
        });
        if (!response.ok) throw new Error(`HTTP_${response.status}`);
        const result = await response.json();
        if (result.status !== 'saved' || result.event_type !== message.event_type) {
            throw new Error('INVALID_AGENT_RESPONSE');
        }
        await saveStatus(parsed.key, {...record, status: 'saved'});
        if (['COPY_ATTEMPT','DOWNLOAD_COMPLETED'].includes(message.event_type)) {
            await MatchStore.remember({kind:message.event_type==='COPY_ATTEMPT'?'text':'file',
                digest:message.fingerprint,trace_id:trace,timestamp:parsed.data.timestamp,observed,inspection:Object.fromEntries(
                    ["pattern_hits","text_length","inspectable","reason","file_kind"].filter(k=>parsed.data[k]!==undefined).map(k=>[k,parsed.data[k]]))});
        }
        return {status: 'saved', event_type: message.event_type, match_status: parsed.data.match_status};
    } catch (error) {
        const code = error.name === 'TimeoutError' || error.name === 'AbortError' ? 'TIMEOUT' :
            /^HTTP_|^INVALID_AGENT_RESPONSE$/.test(error.message) ? error.message : 'AGENT_UNREACHABLE';
        await saveStatus(parsed.key, {...record, status: 'failed', error: code});
        return {status: 'failed', error: code};
    }
}

async function diagnostics() {
    const result = {
        version: chrome.runtime.getManifest().version,
        agent: {ok: false},
        mode: 'sensor-with-block-screen'
    };
    try {
        const response = await fetch(AGENT + '/health', {
            signal: AbortSignal.timeout(3000),
            credentials: 'omit',
            redirect: 'error'
        });
        const health = await response.json();
        result.agent = {
            ok: response.ok && health.service === 'GIGANGAgent',
            version: health.version || '?',
            windowsBlockingOk: health.windows_blocking_ok,
            blockedCount: health.blocked_count || 0
        };
    } catch {}
    Object.assign(result, await chrome.storage.local.get(['lastCopy', 'lastPaste', 'lastUpload', 'lastDownload', 'lastImage']));
    return result;
}

let eventWork = Promise.resolve();
chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return false;
    if (message?.type === 'GIGANG_INSPECT_PORTAL') {
        try {
            const site=new URL(sender.url);
            if(site.origin!=='https://desktop-oli.tail2bbbea.ts.net'||site.pathname!=='/db') throw new Error('INVALID_SOURCE');
            fetch(AGENT+'/inspect-content',{method:'POST',headers:{'Content-Type':'application/json'},
                body:JSON.stringify(message.payload),credentials:'omit',redirect:'error',signal:AbortSignal.timeout(30000)})
                .then(r=>r.json()).then(respond,()=>respond({status:'failed'}));
            return true;
        } catch {respond({status:'failed'});return false;}
    }
    if (message?.type === 'GIGANG_MATCH_SEED'  && sender.tab) {
        MatchStore.seed().then(seed=>respond({seed}),()=>respond({error:'SEED_FAILED'}));return true;
    }
    if (message?.type === 'GIGANG_DOWNLOAD_PREPARED') {
        try {
            const url=new URL(sender.url);
            if(url.origin!=='https://desktop-oli.tail2bbbea.ts.net'||url.pathname!=='/db'||!sender.tab ||
                typeof message.blob_url!=='string'||message.blob_url.length>500||
                typeof message.file_name!=='string'||message.file_name.length>1024||
                !Number.isSafeInteger(message.file_size)||message.file_size<0||message.file_size>50*1024*1024)
                throw new Error('INVALID_DOWNLOAD');
            MatchStore.prepare({blob_url:message.blob_url,digest:message.digest,
                file_name:message.file_name,file_size:message.file_size,tab_id:sender.tab.id,inspection:message.inspection})
                .then(()=>respond({status:'ready'}),()=>respond({error:'INVALID_DOWNLOAD'}));
            return true;
        } catch {respond({error:'INVALID_DOWNLOAD'});return false;}
    }
    if (message?.type === 'GIGANG_EVENT') {
        if (!['COPY_ATTEMPT','PASTE_ATTEMPT','FILE_UPLOAD_ATTEMPT'].includes(message.event_type)) {
            respond({status:'failed',error:'INVALID_EVENT'}); return false;
        }
        const next=eventWork.then(()=>deliver(message,sender));eventWork=next.catch(()=>{});
        next.then(respond, () => respond({status: 'failed', error: 'EXTENSION_ERROR'}));
        return true;
    }
    if (message?.type === 'GIGANG_STATUS' && sender.url?.startsWith(chrome.runtime.getURL(''))) {
        diagnostics().then(respond, () => respond({error: 'EXTENSION_ERROR'}));
        return true;
    }
    return false;
});


// Download URL is checked exactly; referrers and query strings are not transmitted.
function isPortalDownload(item) {
    try {
        const url = new URL(item.url);
        return url.origin === 'https://desktop-oli.tail2bbbea.ts.net' && url.pathname === '/db/download';
    } catch { return false; }
}
let downloadWork = Promise.resolve();
function scheduleDownload(work) {
    downloadWork = downloadWork.then(work).catch(error => console.warn('[GIGANG] Download event failed', error.name));
}
async function downloadSource(item) {
    const captured=await MatchStore.prepared(item.url);
    if(captured) return captured;
    return isPortalDownload(item) ? {file_name:(item.filename||'').split(/[\\/]/).pop()} : null;
}
async function reportDownload(item, eventType, stamp) {
    const source=await downloadSource(item); if(!source)return;
    const key = `downloadReported:${item.id}:${eventType}`;
    if ((await chrome.storage.session.get(key))[key]) return;
    const result = await deliver({event_type:eventType,
        fingerprint:eventType==='DOWNLOAD_COMPLETED'?source.digest:null,
        metadata: {
            ...(source.inspection||{}),
            timestamp: stamp || new Date().toISOString(), download_id: item.id,
            download_state: eventType === 'DOWNLOAD_STARTED' ? 'in_progress' : item.state,
            file_name:source.file_name || (item.filename||'').split(/[\\/]/).pop(),
            file_size:source.file_size ?? item.fileSize
        }}, {url:'https://desktop-oli.tail2bbbea.ts.net/db/download'});
    if (result.status === 'saved') await chrome.storage.session.set({[key]: true});
}
async function reportTerminal(item) {
    if (item.state === 'complete') await reportDownload(item, 'DOWNLOAD_COMPLETED', item.endTime);
    if (item.state === 'interrupted') await reportDownload(item, 'DOWNLOAD_INTERRUPTED', item.endTime);
}
chrome.downloads.onCreated.addListener(item => {
    scheduleDownload(async () => {
        if(!await downloadSource(item))return;
        await reportDownload(item,'DOWNLOAD_STARTED',item.startTime);
        const [latest]=await chrome.downloads.search({id:item.id});
        if(latest)await reportTerminal(latest);
    });
});
chrome.downloads.onChanged.addListener(delta => {
    if(!['complete','interrupted'].includes(delta.state?.current))return;
    scheduleDownload(async()=>{
        const [item]=await chrome.downloads.search({id:delta.id});
        if(!item||!await downloadSource(item))return;
        await reportDownload(item,'DOWNLOAD_STARTED',item.startTime);
        await reportTerminal(item);
    });
});


// 맨 앞 탭 주소를 Agent에 알려준다. Agent는 기밀 DB 화면인지만 판단해 스크린샷 감지에 쓰고 주소는 버린다.
let reportedTab = null;
async function reportActiveTab() {
    let url = '';
    try {
        const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true});
        const page = tab?.url ? new URL(tab.url) : null;
        if (page && ['http:', 'https:'].includes(page.protocol)) url = page.origin + page.pathname;
    } catch {}
    if (url === reportedTab) return;
    reportedTab = url;
    try {
        await fetch(AGENT + '/active-tab', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}),
            signal: AbortSignal.timeout(3000), credentials: 'omit', redirect: 'error'
        });
    } catch {
        reportedTab = null;
    }
}

chrome.tabs.onActivated.addListener(() => void reportActiveTab());
chrome.tabs.onUpdated.addListener((tabId, change, tab) => { if (change.url && tab.active) void reportActiveTab(); });
chrome.windows.onFocusChanged.addListener(() => void reportActiveTab());

function pageOf(address) {
    try {
        const page = new URL(address.startsWith('blob:') ? address.slice(5) : address);
        return ['http:', 'https:'].includes(page.protocol) ? page.origin + page.pathname : '';
    } catch { return ''; }
}

chrome.downloads.onChanged.addListener(async change => {
    if (change.state?.current !== 'complete') return;
    try {
        const [item] = await chrome.downloads.search({id: change.id});
        if (!item?.filename) return;
        await fetch(AGENT + '/download-event', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                url: pageOf(item.url || ''), final_url: pageOf(item.finalUrl || ''), referrer: pageOf(item.referrer || ''),
                file_path: item.filename, timestamp: new Date(item.endTime || Date.now()).toISOString()
            }),
            signal: AbortSignal.timeout(30000), credentials: 'omit', redirect: 'error'
        });
    } catch {}
});
