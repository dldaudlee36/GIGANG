// Hold supported DOM transfers before the page sees them. Replay only after an explicit allow.
(() => {
    if (globalThis.__gigangTransferGuard384) return;
    globalThis.__gigangTransferGuard384 = true;
    const replayed = new WeakSet();
    let busy = false;
    function stop(e) { e.preventDefault(); e.stopImmediatePropagation(); }
    function notice(text,pending=false) {
        let host=document.getElementById('gigang-transfer-status');
        if(!host) {
            host=document.createElement('div');host.id='gigang-transfer-status';
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
    const clearNotice=()=>document.getElementById('gigang-transfer-status')?.remove();
    async function digest(buffer) {
        return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',buffer)),b=>b.toString(16).padStart(2,'0')).join('');
    }
    async function textDigest(text) {
        if (!crypto.subtle || text.length>1000000) throw new Error('검사할 수 없는 텍스트 크기입니다.');
        const result=await chrome.runtime.sendMessage({type:'GIGANG_MATCH_SEED'});
        if (!result?.seed) throw new Error('검사 기준을 읽지 못했습니다.');
        return digest(new TextEncoder().encode(result.seed+'\0'+text.replace(/\r\n?/g,'\n')));
    }
    async function check(kind,metadata,fingerprint) {
        const reply=await chrome.runtime.sendMessage({type:'GIGANG_EVENT',event_type:kind,preflight:true,
            metadata:{timestamp:new Date().toISOString(),...metadata},fingerprint});
        if (reply?.status==='saved' && reply.decision==='block') return false;
        if (reply?.status==='saved' && reply.decision==='allow') return true;
        // Old background code, stopped Agent, timeouts and malformed replies must never resume input.
        throw new Error('보안 검사를 완료하지 못했습니다. 센서 연결과 확장 버전을 확인해 주세요.');
    }
    function captureEditor(target) {
        const editor=target?.closest?.('textarea,input,[contenteditable="true"],[contenteditable="plaintext-only"]');
        if (!editor || editor.disabled || editor.readOnly) return null;
        if (editor.tagName==='INPUT' && !['text','search','email','url','tel','number',''].includes(editor.type)) return null;
        if (editor.tagName==='INPUT' || editor.tagName==='TEXTAREA') {
            if (typeof editor.selectionStart!=='number') return null;
            return {editor,value:editor.value,start:editor.selectionStart,end:editor.selectionEnd};
        }
        const selection=window.getSelection();
        if (!selection?.rangeCount || !editor.contains(selection.getRangeAt(0).commonAncestorContainer)) return null;
        return {editor,html:editor.innerHTML,range:selection.getRangeAt(0).cloneRange()};
    }
    function insertText(snapshot,text) {
        const {editor}=snapshot;
        if (!editor.isConnected || (document.activeElement!==editor && !editor.contains(document.activeElement))) throw new Error('입력창이 바뀌었습니다. 다시 붙여넣어 주세요.');
        if ('value' in snapshot) {
            if (editor.value!==snapshot.value || editor.selectionStart!==snapshot.start || editor.selectionEnd!==snapshot.end) throw new Error('입력 내용이나 커서 위치가 바뀌었습니다. 다시 시도해 주세요.');
            editor.setRangeText(text,snapshot.start,snapshot.end,'end');
            editor.dispatchEvent(new InputEvent('input',{bubbles:true,composed:true,inputType:'insertFromPaste',data:text}));
        } else {
            if (editor.innerHTML!==snapshot.html) throw new Error('입력 내용이 바뀌었습니다. 다시 시도해 주세요.');
            const selection=window.getSelection();selection.removeAllRanges();selection.addRange(snapshot.range);
            if (!document.execCommand('insertText',false,text)) throw new Error('이 입력창에서 자동 재개를 지원하지 않습니다.');
        }
    }
    async function guarded(task) {
        if (busy) {notice('보안 검사 중입니다. 완료 후 다시 시도해 주세요.',true);return;}
        busy=true;notice('보안 확인 중입니다. 확인 전에는 입력·첨부하지 않습니다.',true);
        try {
            if (await task()) clearNotice();
            else notice('회사 자료와 일치하여 붙여넣기·첨부를 차단했습니다.\n확인을 눌러도 내용은 입력되지 않습니다.');
        } catch (error) {notice(error.message || '보안 검사를 완료하지 못해 입력·첨부를 보류했습니다.');}
        finally {busy=false;}
    }
    function transfer(files) {const data=new DataTransfer();for(const file of files)data.items.add(file);return data;}
    function replay(target,event) {replayed.add(event);target.dispatchEvent(event);}
    async function checkFiles(files,method) {
        if (files.length>10) throw new Error('한 번에 파일 10개 이하로 검사해 주세요.');
        for (const file of files) {
            if (file.size>50*1024*1024) throw new Error('50MB를 넘는 파일은 검사를 완료할 수 없어 첨부를 보류했습니다.');
            if (!await check('FILE_UPLOAD_ATTEMPT',{file_name:file.name,file_size:file.size,...(method==='drop'?{method}: {})},await digest(await file.arrayBuffer()))) return false;
        }
        return true;
    }
    function pasteOrDrop(e,channel) {
        if (globalThis.GIGANGPaused?.() || replayed.has(e) || !e.isTrusted) return;
        const data=channel==='paste'?e.clipboardData:e.dataTransfer;
        if (!data) return;
        const target=e.composedPath?.()[0] || e.target;
        // Do not collect password paste metadata.
        if (target?.closest?.('input[type="password"]')) return;
        const files=Array.from(data.files || []),text=data.getData('text/plain') || '';
        if (!files.length && !text) return;
        stop(e); // synchronous: the page cannot start sending the original transfer
        const editor=captureEditor(target);
        void guarded(async()=>{
            if (files.length) {
                if (text) throw new Error('텍스트와 파일이 함께 있는 붙여넣기는 나누어서 시도해 주세요.');
                if (!await checkFiles(files,channel)) return false;
                if (!target?.isConnected) throw new Error('첨부 영역이 바뀌었습니다. 다시 선택해 주세요.');
                replay(target,channel==='paste' ? new ClipboardEvent('paste',{clipboardData:transfer(files),bubbles:true,cancelable:true,composed:true}) :
                    new DragEvent('drop',{dataTransfer:transfer(files),clientX:e.clientX,clientY:e.clientY,bubbles:true,cancelable:true,composed:true}));
            } else {
                if (!editor) throw new Error('이 입력 영역에서는 검사 후 붙여넣기를 지원하지 않습니다.');
                if (!await check('PASTE_ATTEMPT',{text_length:Array.from(text).length},await textDigest(text))) return false;
                insertText(editor,text);
            }
            return true;
        });
    }
    window.addEventListener('paste',e=>pasteOrDrop(e,'paste'),true);
    window.addEventListener('drop',e=>pasteOrDrop(e,'drop'),true);
    function selectedFile(e) {
        if (globalThis.GIGANGPaused?.() || replayed.has(e) || !e.isTrusted) return;
        const input=e.composedPath?.()[0] || e.target;
        if (input?.tagName!=='INPUT' || input.type!=='file') return;
        const files=Array.from(input.files || []);
        if (!files.length) return;
        stop(e);input.value=''; // clear FileList before the website receives input/change
        void guarded(async()=>{
            if (!await checkFiles(files,'file')) return false;
            if (!input.isConnected) throw new Error('파일 입력창이 바뀌었습니다. 다시 선택해 주세요.');
            input.files=transfer(files).files;
            replay(input,new Event('input',{bubbles:true,composed:true}));
            replay(input,new Event('change',{bubbles:true,composed:true}));
            return true;
        });
    }
    window.addEventListener('input',selectedFile,true);
    window.addEventListener('change',selectedFile,true);
})();
