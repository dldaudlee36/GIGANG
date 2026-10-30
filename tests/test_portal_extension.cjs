const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
const base=path.resolve(__dirname,'../guard/browser_extension');
const session={},local={},calls=[];
const event=()=>({addListener(){}});
const storage=obj=>({async get(k){if(typeof k==='string')return {[k]:structuredClone(obj[k])};return structuredClone(obj);},async set(x){Object.assign(obj,structuredClone(x));}});
const ctx=vm.createContext({console,URL,Date,AbortSignal,crypto:webcrypto,
 GIGANGMode:{paused:async()=>false},GIGANGBlocking:{permission:async()=>null,show:async()=>{}},
 chrome:{runtime:{id:'x',onMessage:event(),getURL:()=>''},storage:{session:storage(session),local:storage(local)},
 downloads:{onCreated:event(),onChanged:event()},tabs:{onActivated:event(),onUpdated:event()},windows:{onFocusChanged:event()}},
 fetch:async(url,opts)=>{const data=JSON.parse(opts.body);calls.push({url,data});return {ok:true,json:async()=>({status:'saved',event_type:data.event_type})};}
});
ctx.importScripts=(...names)=>{for(const n of names)if(n==='matching.js')vm.runInContext(fs.readFileSync(path.join(base,n),'utf8'),ctx);};
vm.runInContext(fs.readFileSync(path.join(base,'background.js'),'utf8'),ctx);
(async()=>{
 const stamp=new Date().toISOString(),digest='a'.repeat(64);
 const copy={event_type:'COPY_ATTEMPT',fingerprint:digest,metadata:{timestamp:stamp,source_path:'/db',detection_scope:'customer_table',inspectable:true,text_length:100,pattern_hits:{rrn_high:3}}};
 const result=await vm.runInContext('deliver',ctx)(copy,{url:'https://desktop-oli.tail2bbbea.ts.net/db'});
 assert.equal(result.status,'saved');
 const pasted=await vm.runInContext('deliver',ctx)({event_type:'PASTE_ATTEMPT',fingerprint:digest,metadata:{timestamp:stamp,text_length:100}},{url:'https://chatgpt.com/',tab:{id:1}});
 assert.equal(pasted.match_status,'matched');
 const data=calls.at(-1).data;
 assert.equal(data.pattern_hits.rrn_high,3);
 assert.equal(data.inspectable,true);
 assert.ok(!JSON.stringify(data).includes(digest));
 assert.equal(data.text,undefined);
 // Download preparation records file counts, completion is required before matching uploads.
 const store=vm.runInContext('MatchStore',ctx);
 await store.prepare({blob_url:'blob:https://desktop-oli.tail2bbbea.ts.net/test',digest:'b'.repeat(64),file_name:'a.csv',file_size:5,inspection:{inspectable:true,pattern_hits:{email:2}}});
 await vm.runInContext('reportDownload',ctx)({url:'blob:https://desktop-oli.tail2bbbea.ts.net/test',filename:'a.csv',fileSize:5,id:1,state:'complete'},'DOWNLOAD_STARTED',stamp);
 const started=calls.at(-1).data;
 assert.equal(started.pattern_hits.email,2);
 await vm.runInContext('reportDownload',ctx)({url:'blob:https://desktop-oli.tail2bbbea.ts.net/test',filename:'a.csv',fileSize:5,id:1,state:'complete'},'DOWNLOAD_COMPLETED',stamp);
 await vm.runInContext('deliver',ctx)({event_type:'FILE_UPLOAD_ATTEMPT',fingerprint:'b'.repeat(64),metadata:{timestamp:stamp,file_name:'a.csv',file_size:5}},{url:'https://chatgpt.com/',tab:{id:1}});
 assert.equal(calls.at(-1).data.pattern_hits.email,2);
 assert.equal(calls.at(-1).data.match_status,'matched');
 console.log('PASS: portal copy/download -> saved fingerprints -> matched paste/upload preserves counts; event payload contains no plaintext or digest.');
})().catch(e=>{console.error(e);process.exitCode=1});
