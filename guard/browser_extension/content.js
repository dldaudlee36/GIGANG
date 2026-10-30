// GIGANG 3.6.0: exact-content links, without exporting text or file fingerprints.
(() => {
    if (globalThis.__gigangSensor360Installed) return;
    globalThis.__gigangSensor360Installed = true;
    const PORTAL = 'https://desktop-oli.tail2bbbea.ts.net';
    const LIMIT = 50 * 1024 * 1024;
    let pending = Promise.resolve();
    const enqueue = task => { pending = pending.then(task).catch(e => console.warn('[GIGANG]', e.name)); };
    async function inspectPortal(payload) {
        try {
            const result = await chrome.runtime.sendMessage({type:'GIGANG_INSPECT_PORTAL', payload});
            if (result?.status === 'ok') {
                const {status, ...metadata} = result;
                return metadata;
            }
        } catch {}
        return {inspectable:false, reason:'LOCAL_INSPECTION_FAILED'};
    }
    async function inspectPortalFile(blob, name) {
        if (blob.size > 20*1024*1024) return {inspectable:false,reason:'FILE_TOO_LARGE'};
        const bytes = new Uint8Array(await blob.arrayBuffer());
        let binary = '';
        for(let i=0;i<bytes.length;i+=32768) binary += String.fromCharCode(...bytes.subarray(i,i+32768));
        return inspectPortal({file_base64:btoa(binary),file_name:name});
    }
    async function hashBytes(buffer) {
        return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)), b => b.toString(16).padStart(2, '0')).join('');
    }
    async function hashText(text) {
        try {
        if (!crypto.subtle || text.length > 1000000) return null;
        const {seed} = await chrome.runtime.sendMessage({type:'GIGANG_MATCH_SEED'});
        if (!seed) return null;
        return hashBytes(new TextEncoder().encode(seed + '\0' + text.replace(/\r\n?/g, '\n')));
        } catch { return null; }
    }
    async function report(kind, metadata, digest) {
        const result = await chrome.runtime.sendMessage({type:'GIGANG_EVENT', event_type:kind,
            metadata:{timestamp:new Date().toISOString(), ...metadata}, fingerprint:digest});
        console.log('[GIGANG]',kind,result?.status,result?.match_status || '',result?.error || '');
    }
    document.addEventListener('copy', event => {
        if(globalThis.GIGANGPaused?.())return;
        if (!event.isTrusted || location.origin !== PORTAL || location.pathname !== '/db') return;
        const target = event.composedPath?.()[0] || event.target;
        if (target?.closest?.('input, textarea, [contenteditable="true"]')) return;
        const table = document.getElementById('customerTable'), selection = window.getSelection();
        if (!table || !selection || selection.isCollapsed) return;
        let selected = false;
        for (let i=0;i<selection.rangeCount;i++) {
            if (Array.from(table.rows).slice(1).some(row => selection.getRangeAt(i).intersectsNode(row))) selected = true;
        }
        if (!selected) return;
        // Snapshot at the actual copy event. Do not read the clipboard or persist plaintext.
        let text = selection.toString();
        const timestamp = new Date().toISOString();
        enqueue(async () => {
            const digest = !event.defaultPrevented && text ? await hashText(text) : null;
            const inspection = !event.defaultPrevented ? await inspectPortal({text}) : {inspectable:false,reason:'COPY_CANCELLED'};
            text = null;
            await report('COPY_ATTEMPT',{timestamp,source_path:'/db',detection_scope:'customer_table',...inspection},digest);
        });
    },true);
    document.addEventListener('paste', event => {
        if(globalThis.GIGANGPaused?.())return;
        if (!event.isTrusted || !event.clipboardData) return;
        const target = event.composedPath?.()[0] || event.target;
        if (target?.closest?.('input[type="password"]')) return;
        let text = event.clipboardData.getData('text/plain') || '';
        const images = Array.from(event.clipboardData.files || []).filter(file => file.type.startsWith('image/'));
        if (!text && images.length === 0) return;
        const length = Array.from(text).length, timestamp = new Date().toISOString();
        const meta = {timestamp, text_length: length};
        if (images.length) {
            meta.image_count = images.length;
            meta.image_bytes = images.reduce((total, file) => total + file.size, 0);
        }
        enqueue(async () => {
            const digest = text ? await hashText(text) : null; text = null;
            await report('PASTE_ATTEMPT', meta, digest);
        });
    },true);
    document.addEventListener('change', event => {
        if(globalThis.GIGANGPaused?.())return;
        const target = event.composedPath?.()[0] || event.target;
        if (!event.isTrusted || target?.tagName !== 'INPUT' || target.type !== 'file') return;
        for (const file of Array.from(target.files || [])) {
            const timestamp = new Date().toISOString();
            enqueue(async () => {
                let digest = null;
                try { if (crypto.subtle && file.size <= LIMIT) digest = await hashBytes(await file.arrayBuffer()); } catch {}
                await report('FILE_UPLOAD_ATTEMPT',{timestamp,file_name:file.name,file_size:file.size},digest);
            });
        }
    },true);

    document.addEventListener('drop', function (event) {
        if (globalThis.GIGANGPaused?.()) return;
        if (!event.isTrusted || !event.dataTransfer) return;
        for (const file of Array.from(event.dataTransfer.files || [])) {
            const timestamp = new Date().toISOString();
            enqueue(async () => {
                let digest = null;
                try { if (crypto.subtle && file.size <= LIMIT) digest = await hashBytes(await file.arrayBuffer()); } catch {}
                await report('FILE_UPLOAD_ATTEMPT', {timestamp, file_name: file.name, file_size: file.size, method: 'drop'}, digest);
            });
        }
    }, true);
    function fileName(header) {
        const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header || '');
        const plain = /filename="?([^";]+)/i.exec(header || '');
        let name = 'gigang_customer_data.xlsx';
        try { name = encoded ? decodeURIComponent(encoded[1]) : plain ? plain[1] : name; } catch {}
        return name.split(/[\\/]/).pop().replace(/[\x00-\x1f]/g,'_');
    }
    function notice(text) {
        const id='gigang-download-status';
        let box=document.getElementById(id);
        if (!box) { box=document.createElement('div');box.id=id;box.setAttribute('role','status');
            box.style.cssText='position:fixed;bottom:20px;right:20px;z-index:2147483647;max-width:400px;padding:16px;background:#15293b;color:white;border-radius:8px;font:14px sans-serif';
            document.body.appendChild(box); }
        box.textContent=text;
    }
    let downloading=false;
    document.addEventListener('click',event => {
        if(globalThis.GIGANGPaused?.())return;
        if (!event.isTrusted || event.button!==0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey ||
            location.origin!==PORTAL || location.pathname!=='/db') return;
        const link=event.target.closest?.('a[href]');
        if (!link) return;
        const url=new URL(link.href,location.href);
        if (url.origin!==PORTAL || url.pathname!=='/db/download') return;
        event.preventDefault();
        if (downloading) return;
        downloading=true;
        void (async () => {
            notice('엑셀 파일을 준비하고 있습니다…');
            let response;
            try {
                response=await fetch(url.href,{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(60000)});
                if (!response.ok || new URL(response.url).pathname!=='/db/download') throw new Error('LOGIN_OR_DOWNLOAD_FAILED');
                const type=response.headers.get('Content-Type') || '';
                if (/text\/html|application\/json/i.test(type)) throw new Error('NOT_A_FILE');
                if (Number(response.headers.get('Content-Length'))>LIMIT) throw new Error('FILE_TOO_LARGE');
                const reader=response.body.getReader(),chunks=[];let size=0;
                while (true) {
                    const {done,value}=await reader.read();if(done)break;
                    size+=value.byteLength;
                    if(size>LIMIT){await reader.cancel();throw new Error('FILE_TOO_LARGE');}
                    chunks.push(value);
                }
                const blob=new Blob(chunks,{type:type||'application/octet-stream'});
                const digest=await hashBytes(await blob.arrayBuffer());
                const blobUrl=URL.createObjectURL(blob), name=fileName(response.headers.get('Content-Disposition'));
                const inspection=await inspectPortalFile(blob,name);
                const result=await chrome.runtime.sendMessage({type:'GIGANG_DOWNLOAD_PREPARED',
                    blob_url:blobUrl,digest,file_name:name,file_size:blob.size,inspection});
                if(result?.status!=='ready'){URL.revokeObjectURL(blobUrl);throw new Error('SENSOR_NOT_READY');}
                const anchor=document.createElement('a');anchor.href=blobUrl;anchor.download=name;
                document.body.appendChild(anchor);anchor.click();anchor.remove();
                // Keep the source Blob alive long enough for Chrome to consume it.
                setTimeout(()=>URL.revokeObjectURL(blobUrl),600000);
                notice('파일 저장을 시작했습니다. 완료 후 같은 파일의 업로드 시도를 연결합니다.');
            } catch(error) {
                notice('비교 준비 실패: '+error.message+' · Ctrl+클릭으로 원래 다운로드를 사용할 수 있습니다(파일 일치 비교 제외).');
            } finally {downloading=false;}
        })();
    },true);
    console.log('[GIGANG] 3.6.0 복사→붙여넣기 / 다운로드→업로드 비교 준비');
})();
