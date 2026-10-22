import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const api='http://127.0.0.1:17080/capture-0123456789abcdef0123456789abcdef/api/app/';
const source=fs.readFileSync(new URL('./minvoice-capture-hook.js',import.meta.url),'utf8').replaceAll('__CAPTURE_API__',api).replaceAll('__CAPTURE_PAGE_ORIGIN__','https://fixture.minvoice.net');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const good=()=>({ok:true,json:async()=>({ready:true,expires_utc:new Date(Date.now()+4*60*60*1000).toISOString()})});
async function setup({page='https://fixture.minvoice.net/#/hoa-don',fetcher=async()=>good()}={}) {
  const sent=[],logs=[],healthCalls=[];
  class Socket {
    static OPEN=1;
    constructor(){this.url='ws://localhost:16080/signalr/connect';this.handlers={};this.readyState=1;this.closed=false;}
    send(value){sent.push(value);}
    close(){this.closed=true;this.readyState=3;}
    addEventListener(key,fn){this.handlers[key]=fn;}
    removeEventListener(key,fn){if(this.handlers[key]===fn)delete this.handlers[key];}
  }
  class XHR {
    constructor(){this.responseType='';this.responseText='';this.handlers={};this.aborted=false;}
    open(method,url){this.url=url;}
    send(value){sent.push(value);}
    abort(){this.aborted=true;this.handlers.abort?.();}
    addEventListener(key,fn){this.handlers[key]=fn;}
    removeEventListener(key,fn){if(this.handlers[key]===fn)delete this.handlers[key];}
  }
  const original={ws:Socket.prototype.send,open:XHR.prototype.open,xhr:XHR.prototype.send};
  const pageURL=new URL(page);
  const context={WebSocket:Socket,XMLHttpRequest:XHR,URL,URLSearchParams,AbortController,WeakMap,WeakSet,
    location:{protocol:pageURL.protocol,origin:pageURL.origin,href:pageURL.href},
    fetch:async(url,options)=>{healthCalls.push({url,options});return fetcher(healthCalls.length);},
    console:{info:(...args)=>logs.push(JSON.stringify(args)),error:(...args)=>logs.push(JSON.stringify(args))},setTimeout:()=>1,clearTimeout:()=>{}};
  context.window=context;vm.runInNewContext(source,context);await flush();
  return {Socket,XHR,sent,logs,context,healthCalls,original};
}
const command=(overrides={})=>JSON.stringify({BrowserInfo:{LinkApi:'https://api-hddt.minvoice.com.vn/api/app/',Cookie:'NEVER_LOG_COOKIE',Pass:'NEVER_LOG_PASSWORD'},PlugCommand:{CommandName:'SignInvoices',InvoiceIdArray:['12345678-90ab-cdef-1234-567890abcdef']},...overrides});
const frame=value=>JSON.stringify({H:'handlerHub',M:'processMessage',A:[value],I:'17'});
const callback=JSON.stringify({M:[{H:'handlerHub',M:'reponseResult',A:[JSON.stringify({code:1,message:'NEVER_LOG_MESSAGE',data:{command:'SignInvoices',status:true}})]}]});
const restored=t=>{assert.equal(t.Socket.prototype.send,t.original.ws);assert.equal(t.XHR.prototype.open,t.original.open);assert.equal(t.XHR.prototype.send,t.original.xhr);};
{
  const t=await setup(),socket=new t.Socket();
  assert.equal(socket.send(frame(command())),undefined);assert.equal(t.sent.length,0);await flush();
  const received=JSON.parse(t.sent[0]),body=JSON.parse(received.A[0]);
  assert.equal(received.I,'17');assert.equal(body.BrowserInfo.LinkApi,api);assert.equal(body.BrowserInfo.Pass,'NEVER_LOG_PASSWORD');
  assert.equal(t.healthCalls.length,2);
  for(const {url,options} of t.healthCalls){assert.equal(url,api.replace('api/app/','status'));assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert(options.signal);}
  socket.handlers.message({data:callback});
  assert.equal(t.context.TokenSignerCapture.status().rewritten,1);assert.equal(t.context.TokenSignerCapture.status().callbacks,1);restored(t);
  assert(!t.logs.join('\n').includes('NEVER_LOG'));
}
{
  const t=await setup(),xhr=new t.XHR();xhr.open('POST','http://localhost:16080/signalr/send?transport=longPolling');
  assert.equal(xhr.send(new URLSearchParams({data:frame(command()),preserved:'yes'}).toString()),undefined);
  assert.equal(t.sent.length,0);await flush();
  const form=new URLSearchParams(t.sent[0]);assert.equal(form.get('preserved'),'yes');assert.equal(JSON.parse(JSON.parse(form.get('data')).A[0]).BrowserInfo.LinkApi,api);
  xhr.responseText=callback;xhr.handlers.load();restored(t);assert(!t.logs.join('\n').includes('NEVER_LOG'));
}
for(const fetcher of [async()=>{throw new Error('NEVER_LOG_FETCH');},async()=>({ok:false}),async()=>({ok:true,json:async()=>({ready:false})}),async()=>({ok:true,json:async()=>({ready:true,expires_utc:new Date(Date.now()+30000).toISOString()})})]){
  const t=await setup({fetcher});assert.equal(t.context.TokenSignerCapture,undefined);assert.equal(t.context.TokenSignerCapturePending,undefined);assert(t.logs.join().includes('NOT armed'));restored(t);assert.equal(t.sent.length,0);assert(!t.logs.join().includes('NEVER_LOG'));
}
for(const transport of ['ws','xhr']){
  const t=await setup({fetcher:async count=>{if(count===1)return good();throw new Error('NEVER_LOG_FETCH');}});
  const socket=new t.Socket(),xhr=new t.XHR();
  if(transport==='ws')socket.send(frame(command()));else{xhr.open('POST','http://localhost:16080/signalr/send');xhr.send(new URLSearchParams({data:frame(command())}).toString());}
  await flush();assert.equal(t.sent.length,0);assert(transport==='ws'?socket.closed:xhr.aborted);assert(t.logs.join().includes('command NOT sent'));assert(!t.logs.join().includes('NEVER_LOG'));restored(t);
}
{
  const t=await setup({fetcher:async count=>count===1?good():({ok:true,json:async()=>({ready:false,expires_utc:new Date(Date.now()+3600000).toISOString()})})}),socket=new t.Socket();
  socket.send(frame(command()));await flush();assert.equal(t.sent.length,0);assert(socket.closed);restored(t);
}
for(const bad of [command({BrowserInfo:{LinkApi:'https://evil.example/'}}),command({PlugCommand:{CommandName:'SignInvoices',InvoiceIdArray:['a','b']}})]){
  const t=await setup(),socket=new t.Socket();socket.send(frame(bad));await flush();assert.equal(t.sent.length,0);assert(socket.closed);assert.equal(t.healthCalls.length,1);restored(t);
}
{
  let release;const t=await setup({fetcher:async count=>count===1?good():new Promise(resolve=>{release=resolve;})}),socket=new t.Socket();
  socket.send(frame(command()));socket.send(frame(command()));assert.equal(t.sent.length,0);release(good());await flush();assert.equal(t.sent.length,0);assert(socket.closed);restored(t);
}
{
  let release;const t=await setup({fetcher:async count=>count===1?good():new Promise(resolve=>{release=resolve;})}),xhr=new t.XHR();
  xhr.open('POST','http://localhost:16080/signalr/send');xhr.send(new URLSearchParams({data:frame(command())}).toString());xhr.abort();release(good());await flush();assert.equal(t.sent.length,0);restored(t);
}
{
  let release;const t=await setup({fetcher:async count=>count===1?good():new Promise(resolve=>{release=resolve;})}),socket=new t.Socket();
  socket.send(frame(command()));t.context.TokenSignerCapture.restore();release(good());await flush();assert.equal(t.sent.length,0);restored(t);
}
{
  const t=await setup(),socket=new t.Socket();socket.url='wss://other.example/signalr/connect';const original=frame(command());socket.send(original);assert.equal(t.sent[0],original);
  socket.url='ws://localhost:16080/signalr/connect';socket.send('unrelated-heartbeat');assert.equal(t.sent[1],'unrelated-heartbeat');socket.send(frame(command({PlugCommand:{CommandName:'GetCertificates'}})));assert.equal(t.sent.length,3);assert.equal(t.healthCalls.length,1);t.context.TokenSignerCapture.restore();restored(t);
}
for(const page of ['https://other.minvoice.net/','https://fixture.minvoice.net.evil.example/','https://hddt.minvoice.com.vn/','http://fixture.minvoice.net/']){
  const t=await setup({page});assert.equal(t.context.TokenSignerCapture,undefined);assert.equal(t.healthCalls.length,0);restored(t);
}
console.log('PASS: setup/send-time readiness; WebSocket/XHR one-invoice routing; expired/unavailable relay blocks sends; duplicate reservation and abort block sends; exact tenant/API; callbacks restore; credential redaction; unrelated traffic preserved.');
