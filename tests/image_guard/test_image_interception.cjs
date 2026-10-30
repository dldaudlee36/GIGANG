// Event-handler unit test. This does not claim to replace a real Chrome integration test.
const vm=require('vm'),fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const code=fs.readFileSync(path.join(__dirname,'../../guard/browser_extension/image_content.js'),'utf8');
function setup(){
    const listeners={},nodes=new Map(),calls=[],replayed=[];let resolve;
    class Element{
        constructor(){this.style={};this.isConnected=true;this.children=[];this.files=[];this.tagName='INPUT';this.type='file';}
        setAttribute(){} addEventListener(){} remove(){nodes.delete(this.id)} attachShadow(){return this.shadowRoot=new Element()}
        appendChild(x){this.children.push(x);this.firstChild||=x;if(x.id)nodes.set(x.id,x);}
        set value(x){if(x==='')this.files=[];} dispatchEvent(e){replayed.push(e);return true;}
    }
    class DataTransfer{constructor(){this.files=[];this.items={add:f=>this.files.push(f)}}}
    class E{constructor(type,opts){this.type=type;Object.assign(this,opts);this.isTrusted=false}}
    class Reader{readAsDataURL(){this.result='data:image/png;base64,AAAA';queueMicrotask(()=>this.onload())}}
    const context={console,URL,location:{origin:'https://chatgpt.com',hostname:'chatgpt.com',pathname:'/'},
        ImageMatch:{isAI:()=>true},window:{addEventListener:(type,fn)=>listeners[type]=fn},
        document:{getElementById:id=>nodes.get(id),createElement:()=>new Element(),body:new Element()},
        chrome:{runtime:{sendMessage:message=>{calls.push(message);return new Promise(r=>resolve=r)}}},
        DataTransfer,ClipboardEvent:E,DragEvent:E,Event:E,FileReader:Reader,setTimeout,clearTimeout};
    vm.createContext(context);vm.runInContext(code,context);
    const image={name:'shot.png',type:'image/png',size:3};
    function event(type){const target=new Element();target.files=[image];return {
        type,isTrusted:true,clipboardData:{files:[image]},dataTransfer:{files:[image]},target,
        composedPath:()=>[target],preventDefault(){this.prevented=true},stopImmediatePropagation(){this.stopped=true}}}
    return {listeners,event,replayed,calls,resolve:r=>resolve(r),nodes};
}
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{
    for(const type of ['input','change','paste','drop']){
        const s=setup(),e=s.event(type);s.listeners[type](e);
        assert(e.prevented&&e.stopped);assert.equal(s.replayed.length,0);
        if(['input','change'].includes(type))assert.equal(e.target.files.length,0);
        await tick();assert.equal(s.calls[0].type,'GIGANG_IMAGE_CHECK');
        s.resolve({status:'blocked',log_saved:true});await tick();
        assert.equal(s.replayed.length,0);console.log('PASS '+type+': synchronous hold, matching image never replayed');
    }
    for(const type of ['input','paste','drop']){
        const s=setup(),e=s.event(type);s.listeners[type](e);await tick();
        s.resolve({status:'allow',log_saved:true});await tick();
        assert.equal(s.replayed.length,type==='input'?2:1);console.log('PASS '+type+': resumed only after allow result');
    }
    for(const error of ['OCR_FAILED','DB_BASELINE_MISSING','OCR_BUSY']){
        const s=setup(),e=s.event('input');s.listeners.input(e);await tick();
        s.resolve({status:'hold',error});await tick();assert.equal(s.replayed.length,0);
    }
    const s=setup(),e=s.event('input');s.listeners.input(e);await tick();
    e.target.files=[{name:'second.png',type:'image/png',size:3}];s.listeners.change(e);
    assert.equal(e.target.files.length,0);s.resolve({status:'blocked'});await tick();
    console.log('PASS inspection failures and pending-input replacement: held');
})().catch(e=>{console.error(e);process.exitCode=1});
