const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const code=fs.readFileSync(__dirname+'/../guard/browser_extension/transfer_guard.js','utf8');
const settle=()=>new Promise(resolve=>setTimeout(resolve,35));
function harness(verdict) {
  const listeners={},sent=[],notices=[];let panel=null;
  const element=()=>({style:{},children:[],setAttribute(){},addEventListener(){},attachShadow(){this.shadowRoot={appendChild(x){this.firstChild=x}};return this.shadowRoot},appendChild(x){this.children.push(x)},remove(){panel=null},querySelector(){return this.children[0]}});
  const document={activeElement:null,getElementById(){return panel},createElement:element,documentElement:{appendChild(x){panel=x;notices.push(x)}}};
  class Transfer {constructor(){this.files=[];this.items={add:f=>this.files.push(f)}}}
  class Event {constructor(type,opts){this.type=type;Object.assign(this,opts)}}
  const ctx=vm.createContext({document,window:{addEventListener(type,fn){listeners[type]=fn}},crypto:webcrypto,TextEncoder,Date,WeakSet,DataTransfer:Transfer,Event,ClipboardEvent:Event,DragEvent:Event,InputEvent:Event,
    chrome:{runtime:{async sendMessage(message){sent.push(message);if(message.type==='GIGANG_MATCH_SEED')return {seed:'test-seed'};return typeof verdict==='function'?verdict(message):verdict}}}});
  vm.runInContext(code,ctx);
  const input={tagName:'TEXTAREA',isConnected:true,disabled:false,readOnly:false,value:'hello ',selectionStart:6,selectionEnd:6,
    closest(q){return q.includes('password')?null:this},setRangeText(text){this.value+=text;this.selectionStart=this.selectionEnd=this.value.length},dispatchEvent(e){this.events=(this.events||[]).concat(e.type)}};
  document.activeElement=input;
  function paste(text='secret') {
    const event={isTrusted:true,clipboardData:{files:[],getData:()=>text},composedPath:()=>[input],preventDefault(){this.prevented=true},stopImmediatePropagation(){this.stopped=true}};
    listeners.paste(event);return event;
  }
  return {listeners,input,paste,sent,document};
}
(async()=>{
  const blocked=harness({status:'saved',decision:'block'}),event=blocked.paste();
  assert.ok(event.prevented&&event.stopped);assert.equal(blocked.input.value,'hello ');
  await settle();assert.equal(blocked.input.value,'hello ');assert.equal(blocked.input.events,undefined);
  const allowed=harness({status:'saved',decision:'allow'});allowed.paste();assert.equal(allowed.input.value,'hello ');
  await settle();assert.equal(allowed.input.value,'hello secret');assert.deepEqual(allowed.input.events,['input']);
  assert.equal(allowed.sent.at(-1).preflight,true);assert.equal(allowed.sent.at(-1).metadata.text,undefined);
  for(const verdict of [{status:'failed'},{status:'saved'},null]) {
    const h=harness(verdict);h.paste();await settle();assert.equal(h.input.value,'hello ');
  }
  const edit=harness({status:'saved',decision:'allow'});edit.paste();edit.input.value='changed';await settle();assert.equal(edit.input.value,'changed');
  const file=harness({status:'saved',decision:'block'});file.input.tagName='INPUT';file.input.type='file';file.input.files=[{name:'a.txt',size:6,arrayBuffer:async()=>new TextEncoder().encode('secret').buffer}];
  const change={isTrusted:true,composedPath:()=>[file.input],preventDefault(){this.prevented=true},stopImmediatePropagation(){this.stopped=true}};
  file.listeners.change(change);assert.ok(change.prevented&&change.stopped);assert.equal(file.input.value,'');await settle();assert.equal(file.input.events,undefined);
  console.log('PASS: synchronous stop; block/no reply/old worker/error never insert; allow inserts once; changed editor held; file cleared before website receives it.');
})().catch(e=>{console.error(e);process.exitCode=1});
