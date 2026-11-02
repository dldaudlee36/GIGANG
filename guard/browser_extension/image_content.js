// Intercept supported DOM transfer events synchronously, before asynchronous OCR.
(() => {
    if(globalThis.__gigangImageGuard370) return;
    globalThis.__gigangImageGuard370=true;
    const PORTAL='https://desktop-oli.tail2bbbea.ts.net';
    const replayEvents=new WeakSet(), pendingInputs=new WeakSet();
    let busy=false;
    function notice(text,bad=false,pending=false) {
        let host=document.getElementById('gigang-image-guard');
        if(!host) {
            host=document.createElement('div');host.id='gigang-image-guard';
            host.style.cssText='position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;background:#101725eF;padding:24px;box-sizing:border-box';
            const root=host.attachShadow({mode:'open'}),box=document.createElement('div');
            box.setAttribute('role','dialog');box.setAttribute('aria-modal','true');box.setAttribute('aria-label','GIGANG 보안 안내');
            box.style.cssText='width:min(660px,100%);box-sizing:border-box;padding:44px;border:1px solid #33445b;border-radius:20px;background:#182438;color:#eaf0fa;font:17px/1.7 system-ui';
            const brand=document.createElement('small'),title=document.createElement('h1'),message=document.createElement('p'),button=document.createElement('button');
            brand.textContent='GIGANG SECURITY';brand.style.cssText='color:#82b7ff;letter-spacing:3px';
            title.style.cssText='font-size:32px;margin:20px 0';message.style.whiteSpace='pre-wrap';message.setAttribute('role','status');
            button.textContent='확인';button.style.cssText='padding:12px 24px;border:0;border-radius:8px;font:inherit;cursor:pointer;background:#80b5ff;color:#101725';
            button.addEventListener('click',()=>host.remove());
            box.appendChild(brand);box.appendChild(title);box.appendChild(message);box.appendChild(button);
            root.appendChild(box);(document.body||document.documentElement).appendChild(host);
        }
        const box=host.shadowRoot.firstChild;
        box.children[1].textContent=pending?'보안 확인 중':'보안 정책 안내';
        box.children[2].textContent=text;
        box.children[3].hidden=pending;
    }
    if(location.origin===PORTAL && location.pathname==='/db' && window===window.top) {
        let timer,last='';
        async function snapshot() {
            if(globalThis.GIGANGPaused?.())return;
            if(document.visibilityState!=='visible') return;
            const table=document.getElementById('customerTable');
            if(!table || table.getClientRects().length===0) return;
            const rows=Array.from(table.rows).filter(r=>r.querySelector('td') && r.getClientRects().length)
                .slice(0,500).map(r=>Array.from(r.cells).slice(0,30).map(c=>(c.innerText||'').trim().slice(0,256)));
            const signature=JSON.stringify(rows);
            if(signature===last) return;
            try {
                const reply=await chrome.runtime.sendMessage({type:'GIGANG_IMAGE_DB',rows});
                if(reply?.status==='ready') {last=signature;console.info('[GIGANG] 이미지 비교 기준 등록:',reply.rows,'행');}
            } catch {}
        }
        function schedule() {clearTimeout(timer);timer=setTimeout(()=>void snapshot(),400);}
        new MutationObserver(schedule).observe(document,{childList:true,subtree:true,characterData:true});
        document.addEventListener('visibilitychange',()=>{last='';schedule();});
        // Renew only the DB data visible in this tab, not old unseen pages.
        setInterval(()=>{last='';void snapshot();},60000);
        schedule();
    }
    if(!ImageMatch.isAI(location.hostname)) return;
    const isImage=f=>/^image\//i.test(f.type)||/\.(png|jpe?g|webp|gif|bmp|tiff?|heic|avif|svg)$/i.test(f.name);
    function stop(event) {event.preventDefault();event.stopImmediatePropagation();}
    function replay(target,event) {replayEvents.add(event);target.dispatchEvent(event);}
    function transfer(files) {const d=new DataTransfer();for(const f of files)d.items.add(f);return d;}
    function encoded(file) {return new Promise((resolve,reject)=>{
        const reader=new FileReader();reader.onerror=()=>reject(new Error('READ_FAILED'));
        reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.readAsDataURL(file);
    });}
    async function inspect(files,channel) {
        if(globalThis.GIGANGPaused?.())return true;
        if(busy) {notice('이미지 검사 중입니다. 완료 후 다시 시도해 주세요.',true);return false;}
        busy=true;
        try {
            const images=files.filter(isImage);
            if(images.length>10) {notice('한 번에 이미지 10개 이하로 검사해 주세요.',true);return false;}
            for(let i=0;i<images.length;i++) {
                const f=images[i];notice('이미지 첨부에 대한 보안 확인 중입니다.\n잠시만 기다려 주세요.',false,true);
                if(f.size>8*1024*1024 || !f.size) throw new Error('IMAGE_TOO_LARGE');
                const reply=await chrome.runtime.sendMessage({type:'GIGANG_IMAGE_CHECK',channel,
                    file_name:f.name,file_size:f.size,image_base64:await encoded(f)});
                if(reply?.status==='blocked') {
                    notice('보안 정책에 따라 이미지 붙여넣기 또는 업로드가 차단되었습니다.\n업무상 이용이 필요하면 관리자에게 문의하세요.',true);
                    return false;
                }
                if(reply?.status!=='allow') throw new Error(reply?.error||'LOCAL_INSPECTION_FAILED');
            }
            return true;
        } catch(e) {
            notice('보안 확인을 완료하지 못해 이미지 첨부를 보류했습니다.\n잠시 후 다시 시도하거나 관리자에게 문의하세요.',true);
            return false;
        } finally {busy=false;}
    }
    async function auditOtherFiles(files) {
        for(const f of files.filter(f=>!isImage(f))) {
            let fingerprint=null;
            if(f.size<=50*1024*1024) {
                const b=await crypto.subtle.digest('SHA-256',await f.arrayBuffer());
                fingerprint=Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
            }
            const reply=await chrome.runtime.sendMessage({type:'GIGANG_EVENT',event_type:'FILE_UPLOAD_ATTEMPT',fingerprint,preflight:true,
                metadata:{timestamp:new Date().toISOString(),file_name:f.name,file_size:f.size}});
            if(reply?.status!=='saved' || reply.decision!=='allow') throw new Error('FILE_NOT_ALLOWED');
        }
    }
    function attachNotice() {document.getElementById('gigang-image-guard')?.remove();}
    window.addEventListener('paste',event=>{
        if(globalThis.GIGANGPaused?.()||replayEvents.has(event)||!event.isTrusted||!event.clipboardData) return;
        const files=Array.from(event.clipboardData.files||[]);
        if(!files.some(isImage)) return;
        stop(event);
        const target=event.composedPath()[0];
        void (async()=>{
            if(!await inspect(files,'paste')) return;
            if(!target?.isConnected) {notice('입력창이 바뀌었습니다. 다시 붙여넣어 주세요.',true);return;}
            // Replay only files; HTML/text from a mixed clipboard is not forwarded unchecked.
            await auditOtherFiles(files);
            replay(target,new ClipboardEvent('paste',{clipboardData:transfer(files),bubbles:true,cancelable:true,composed:true}));
            attachNotice();
        })().catch(()=>notice('첨부를 재개하지 못했습니다. 입력창에서 다시 시도해 주세요.',true));
    },true);
    function fileEvent(event) {
        if(globalThis.GIGANGPaused?.()||replayEvents.has(event)||!event.isTrusted) return;
        const target=event.composedPath()[0];
        if(target?.tagName!=='INPUT'||target.type!=='file') return;
        if(pendingInputs.has(target)) {stop(event);target.value='';return;}
        const files=Array.from(target.files||[]);
        if(!files.some(isImage)) return;
        stop(event);target.value='';pendingInputs.add(target);
        void(async()=>{
            try {
                if(!await inspect(files,'file')) return;
                if(!target.isConnected) {notice('파일 입력창이 바뀌었습니다. 다시 선택해 주세요.',true);return;}
                await auditOtherFiles(files);
                target.files=transfer(files).files;
                replay(target,new Event('input',{bubbles:true,composed:true}));
                replay(target,new Event('change',{bubbles:true,composed:true}));
                attachNotice();
            } finally {pendingInputs.delete(target);}
        })().catch(()=>notice('파일 첨부를 재개하지 못했습니다. 다시 선택해 주세요.',true));
    }
    window.addEventListener('input',fileEvent,true);
    window.addEventListener('change',fileEvent,true);
    window.addEventListener('drop',event=>{
        if(globalThis.GIGANGPaused?.()||replayEvents.has(event)||!event.isTrusted||!event.dataTransfer) return;
        const files=Array.from(event.dataTransfer.files||[]);
        if(!files.some(isImage)) return;
        stop(event);const target=event.composedPath()[0];
        const {clientX,clientY}=event;
        void(async()=>{
            if(!await inspect(files,'drop')) return;
            if(!target?.isConnected) {notice('첨부 영역이 바뀌었습니다. 다시 시도해 주세요.',true);return;}
            await auditOtherFiles(files);
            replay(target,new DragEvent('drop',{dataTransfer:transfer(files),bubbles:true,cancelable:true,composed:true,clientX,clientY}));
            attachNotice();
        })().catch(()=>notice('드래그 첨부를 재개하지 못했습니다. 다시 시도해 주세요.',true));
    },true);
})();
