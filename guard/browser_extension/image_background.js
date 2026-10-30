const ImageGuardBackground = (() => {
    const PORTAL='https://desktop-oli.tail2bbbea.ts.net';
    const API='http://127.0.0.1:8765';
    let snapshotWork=Promise.resolve();
    let inspecting=false;
    function siteOf(sender) {
        if (!sender.tab || sender.id!==chrome.runtime.id) throw new Error('INVALID_SENDER');
        const site=new URL(sender.url);
        if(!['https:','http:'].includes(site.protocol)) throw new Error('INVALID_SENDER');
        return site;
    }
    async function saveSnapshot(message,sender) {
        if(await GIGANGMode.paused()) return {status:'paused'};
        const site=siteOf(sender);
        if(site.origin!==PORTAL || site.pathname!=='/db' || sender.frameId!==0) throw new Error('INVALID_SOURCE');
        const seed=await MatchStore.seed();
        const rows=await ImageMatch.snapshot(message.rows,seed);
        const saved=(await chrome.storage.session.get('imageDB')).imageDB || {};
        const combined=[...ImageMatch.validRows(saved.rows),...rows];
        const unique=new Map(combined.map(r=>[r.tokens.map(t=>t.hash).sort().join(':'),r]));
        await chrome.storage.session.set({imageDB:{rows:[...unique.values()].slice(-500)}});
        // Only hashed DB cells and a session seed are passed to the local Agent.
        await fetch(API+'/image-baseline',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({seed,rows:[...unique.values()].slice(-500)}),
            credentials:'omit',redirect:'error',signal:AbortSignal.timeout(3000)}).catch(()=>{});
        return {status:'ready',rows:rows.length};
    }
    async function logResult(message,site,result) {
        const data={...(result.inspection||{}),target:site.hostname,timestamp:new Date().toISOString(),trace_id:crypto.randomUUID(),
            file_name:message.file_name,file_size:message.file_size,event_type:'FILE_UPLOAD_ATTEMPT',
            image_guard:{outcome:result.status==='blocked'?'blocked_match':result.status==='allow'?'no_match':'held_error',
                channel:message.channel,error:result.error || null,cache_hit:!!result.cache_hit},
            match_status:result.status==='blocked'?'matched':'not_checked',match:result.evidence,authorization:result.authorization};
        let saved=false;
        try {
            const response=await fetch(API+'/image-event',{method:'POST',headers:{'Content-Type':'application/json'},
                body:JSON.stringify(data),credentials:'omit',redirect:'error',signal:AbortSignal.timeout(10000)});
            const reply=await response.json();saved=response.ok && reply.status==='saved';
        } catch {}
        await chrome.storage.local.set({lastImage:{timestamp:data.timestamp,target:site.hostname,
            outcome:data.image_guard.outcome,channel:message.channel,cache_hit:!!result.cache_hit,log_saved:saved,error:result.error||null}});
        return {...result,log_saved:saved};
    }
    async function inspect(message,sender) {
        if(await GIGANGMode.paused()) return {status:'allow',paused:true};
        const site=siteOf(sender);
        if(!ImageMatch.isAI(site.hostname)) throw new Error('NOT_MONITORED_AI');
        if(!['paste','file','drop'].includes(message.channel) || typeof message.file_name!=='string' || message.file_name.length>1024 ||
            !Number.isSafeInteger(message.file_size) || message.file_size<1 || message.file_size>8*1024*1024 ||
            typeof message.image_base64!=='string' || message.image_base64.length>11184812) throw new Error('INVALID_IMAGE');
        const grant=await GIGANGBlocking.permission(site.hostname);
        if(grant) return logResult(message,site,{status:'allow',authorization:grant});
        if(inspecting) return {status:'hold',error:'OCR_BUSY'};
        inspecting=true;
        let result;
        try {
            const bytes=Uint8Array.from(atob(message.image_base64),c=>c.charCodeAt(0));
            if(bytes.length!==message.file_size) throw new Error('INVALID_IMAGE');
            const fileHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
            const saved=await chrome.storage.session.get(['imageDB','imageBlockedCache']);
            const rows=ImageMatch.validRows(saved.imageDB?.rows);
            const cache=(saved.imageBlockedCache||[]).filter(x=>Date.now()-x.observed<ImageMatch.TTL);
            const cached=cache.find(x=>x.hash===fileHash && Date.now()-new Date(x.evidence.source_time).getTime()<ImageMatch.TTL);
            if(cached) result={status:'blocked',inspection:cached.inspection,evidence:{...cached.evidence,
                age_seconds:Math.floor((Date.now()-new Date(cached.evidence.source_time).getTime())/1000)},cache_hit:true};
            else if(!rows.length) result={status:'hold',error:'DB_BASELINE_MISSING'};
            else {
                const response=await fetch(API+'/image-ocr',{method:'POST',headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({image_base64:message.image_base64}),credentials:'omit',redirect:'error',signal:AbortSignal.timeout(30000)});
                const ocr=await response.json();
                if(!response.ok || ocr.status!=='ok') result={status:'hold',error:ocr.error||'OCR_FAILED'};
                else { result=await ImageMatch.match(ocr.lines,rows,await MatchStore.seed());result.inspection=ocr.inspection; }
                if(result.status==='blocked') await chrome.storage.session.set({imageBlockedCache:[...cache,
                    {hash:fileHash,evidence:result.evidence,inspection:result.inspection,observed:Date.now()}].slice(-100)});
            }
        } catch { result={status:'hold',error:'LOCAL_INSPECTION_FAILED'}; }
        finally { inspecting=false; }
        if(await GIGANGMode.paused()) return {status:'allow',paused:true};
        if(result.status==='blocked') {
            try {
                const tab=await chrome.tabs.get(sender.tab.id);
                // Do not replace a different page visited while inspection was running.
                if((tab.pendingUrl||tab.url)===(sender.tab.url||sender.url)) {
                    await GIGANGBlocking.show(sender.tab.id,site.hostname,'image_blocked',message.channel);
                }
            } catch { /* The content script still keeps the attachment blocked. */ }
        }
        return logResult(message,site,result);
    }
    chrome.runtime.onMessage.addListener((message,sender,respond)=>{
        if(!['GIGANG_IMAGE_DB','GIGANG_IMAGE_CHECK'].includes(message?.type)) return false;
        let task;
        if(message.type==='GIGANG_IMAGE_DB') {
            task=snapshotWork.then(()=>saveSnapshot(message,sender));snapshotWork=task.catch(()=>{});
        } else task=snapshotWork.then(()=>inspect(message,sender));
        task.then(respond,()=>respond({status:'hold',error:'IMAGE_GUARD_ERROR'}));
        return true;
    });
})();
