import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto, createHash} from 'node:crypto';

const source = fs.readFileSync(new URL('./esigner-prolog-diagnostic.js', import.meta.url), 'utf8');
const portal = 'https://dichvucong.gdt.gov.vn';
const local = 'http://127.0.0.1:32001/api/hubclient/signxml';
const xml = '<?xml version="1.0" encoding="UTF-8"?><HSoThueDTu><HSoKhaiThue>PRIVATE_XML_Thử</HSoKhaiThue></HSoThueDTu>';
const b64 = value => Buffer.from(value).toString('base64');
const sha = value => createHash('sha256').update(value).digest('hex');
// Test browser boundaries/retention, not a replacement XML validator. The live
// script uses browser DOMParser; actual Foundation/signing fixtures run in Swift.
class Parser {
  parseFromString(text) {
    return {documentElement: {localName: text.includes('<HSoThueDTu') ? 'HSoThueDTu' : 'other'},
      getElementsByTagName: () => [], getElementsByTagNameNS: () => []};
  }
}
function setup({url = portal, responder = () => new Response(JSON.stringify({status:200, data:b64(xml)}))} = {}) {
  const calls = [];
  class Events {
    handlers = new Map();
    addEventListener(key, fn) { if (!this.handlers.has(key)) this.handlers.set(key, new Set()); this.handlers.get(key).add(fn); }
    removeEventListener(key, fn) { this.handlers.get(key)?.delete(fn); }
    emit(key, event) { for (const fn of this.handlers.get(key) ?? []) fn(event); }
  }
  class XHR extends Events {
    responseType = ''; status = 200;
    open(...args) { this.openArgs = args; return 'open-return'; }
    send(...args) { calls.push({type:'xhr', receiver:this, args}); return 'xhr-return'; }
  }
  class WS extends Events {
    constructor(url) { super(); this.url = url; }
    send(...args) { calls.push({type:'ws', receiver:this, args}); return 'ws-return'; }
  }
  const location = new URL(url);
  const fetch = function (...args) { calls.push({type:'fetch', receiver:this, args}); return Promise.resolve(responder(...args)); };
  const original = {fetch, open:XHR.prototype.open, xhr:XHR.prototype.send, ws:WS.prototype.send};
  let timeout;
  const context = {fetch, XMLHttpRequest:XHR, WebSocket:WS, location, URL, URLSearchParams, TextEncoder, TextDecoder,
    crypto:webcrypto, DOMParser:Parser, atob, Blob, FormData, ArrayBuffer, Uint8Array,
    setTimeout:fn => {timeout=fn; return 1;}, clearTimeout:() => {}};
  context.window = context;
  const install = () => vm.runInNewContext(source, context);
  return {context, calls, XHR, WS, install, original, expire:() => timeout()};
}
async function settle(t) { await new Promise(r=>setTimeout(r,20)); await t.context.TokenSignerProlog.settled(); }
function restored(t) {
  assert.equal(t.context.fetch,t.original.fetch); assert.equal(t.XHR.prototype.open,t.original.open);
  assert.equal(t.XHR.prototype.send,t.original.xhr); assert.equal(t.WS.prototype.send,t.original.ws);
}
{
  const t=setup(); t.install();
  const body=JSON.stringify({dataFile:b64(xml),PIN_CODE:'PRIVATE_PIN',cookie:'PRIVATE_COOKIE'});
  const init={method:'POST',body,headers:{Authorization:'PRIVATE_AUTH'}};
  const promise=t.context.fetch(local,init);
  // Observer neither awaits digest work nor changes input/options or return.
  assert.equal(t.calls.length,1); assert.equal(t.calls[0].args[1],init);
  const response=await promise; assert.equal(response.status,200); await settle(t);
  const capture=t.context.TokenSignerProlog.snapshot();
  assert.equal(capture.records[0].parts[0].decodedOnce.kind,'xml');
  assert.equal(capture.records[0].parts[0].decodedOnce.sha256,sha(xml));
  assert.equal(capture.records[1].parts[0].decodedOnce.sha256,sha(xml));
  assert(!JSON.stringify(capture).includes('PRIVATE_')); assert(!JSON.stringify(capture).includes('Authorization'));
  assert(!JSON.stringify(capture).includes(local));
  // Returned snapshot is detached from retained state.
  capture.records.length=0; assert(t.context.TokenSignerProlog.snapshot().records.length>0);
  t.context.TokenSignerProlog.restore(); restored(t);
}
{
  const t=setup({responder:()=>new Response(JSON.stringify({status:200,data:b64(b64(xml))}))});t.install();
  await t.context.fetch(local,{method:'POST',body:JSON.stringify({dataFile:b64(xml)})}); await settle(t);
  assert.equal(t.context.TokenSignerProlog.snapshot().records[1].parts[0].decodedOnce.kind,'base64-text');
  t.expire(); restored(t);
}
{
  const t=setup();t.install();
  // Traffic before signing and other origins never appears in diagnostics.
  await t.context.fetch(portal+'/unrelated',{method:'POST',body:'PRIVATE_FORM'});
  await t.context.fetch('https://other.example/upload',{method:'POST',body:xml});
  assert.equal(t.context.TokenSignerProlog.snapshot().records.length,0);
  const xhr=new t.XHR(); assert.equal(xhr.open('POST',local,true),'open-return');
  const command=JSON.stringify({dataFile:b64(xml)}); assert.equal(xhr.send(command),'xhr-return');
  xhr.responseText=JSON.stringify({status:200,data:b64(xml)});xhr.emit('load');await settle(t);
  assert.equal(t.calls.at(-1).args[0],command);
  const form=new FormData(); form.set('uploadfile',new Blob([xml]),'PRIVATE_FILENAME.xml');form.set('cookievalue','PRIVATE_COOKIE');
  assert.equal(xhr.open('POST',portal+'/PRIVATE_PATH?token=PRIVATE_TOKEN',true),'open-return');
  xhr.send(form); xhr.responseText='<html><body>Content is not allowed in prolog. PRIVATE_ERROR</body></html>';xhr.emit('load');
  await settle(t);
  const snap=t.context.TokenSignerProlog.snapshot();
  const parts=snap.records.find(r=>r.container==='multipart').parts;
  assert.equal(parts.length,1);assert.equal(parts[0].wire.sha256,sha(xml));
  assert(snap.records.some(r=>r.payload?.wire.prologError===true));
  assert(!JSON.stringify(snap).includes('PRIVATE_'));
  // Reusing the XHR must not attribute a response to the previous request.
  assert.equal(snap.records.filter(r=>r.stage==='ctsign-response').length,1);
  t.context.TokenSignerProlog.restore();restored(t);
}
{
  const t=setup();t.install();
  const socket=new t.WS('ws://localhost:8768/plugin/sign');
  const prepared=JSON.stringify({CODE:'CER_001',BASE64_VALUE:b64(xml),PIN_CODE:'PRIVATE_PIN'});
  assert.equal(socket.send(prepared),'ws-return'); assert.equal(t.calls.at(-1).args[0],prepared);
  socket.emit('message',{data:JSON.stringify({CODE:'CER_001',SUCCESS:'TRUE',SIGNED_CONTENT:b64('signature bytes'),CERT:'PRIVATE_CERT'})});
  await settle(t);
  assert.equal(t.context.TokenSignerProlog.snapshot().records[0].command,'CER_001');
  assert.equal(t.context.TokenSignerProlog.snapshot().records[1].success,true);
  assert(!JSON.stringify(t.context.TokenSignerProlog.snapshot()).includes('PRIVATE_'));
  t.context.TokenSignerProlog.restore();restored(t);assert.equal(socket.handlers.get('message').size,0);
}
{
  const t=setup({responder:()=>{throw new Error('PRIVATE_NETWORK_ERROR');}});t.install();
  assert.throws(()=>t.context.fetch(local,{method:'POST',body:'bad'}),/PRIVATE_NETWORK_ERROR/);
  t.context.TokenSignerProlog.restore();restored(t);
}
{
  const raw=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(xml)]);
  const t=setup({responder:()=>new Response(raw)});t.install();
  await t.context.fetch(local,{method:'POST',body:JSON.stringify({dataFile:b64(xml)})});await settle(t);
  const response=t.context.TokenSignerProlog.snapshot().records[1];
  assert.equal(response.bodyBytes.bom,'utf8');assert.equal(response.bodyBytes.sha256,sha(raw));
  t.context.TokenSignerProlog.restore();restored(t);
}
{
  const t=setup({responder:()=>Promise.reject(new Error('PRIVATE_NETWORK_ERROR'))});t.install();
  await assert.rejects(t.context.fetch(local,{method:'POST',body:JSON.stringify({dataFile:b64(xml)})}),/PRIVATE_NETWORK_ERROR/);
  await settle(t);assert(t.context.TokenSignerProlog.snapshot().records.some(r=>r.failed));
  assert(!JSON.stringify(t.context.TokenSignerProlog.snapshot()).includes('PRIVATE_'));
  t.context.TokenSignerProlog.restore();restored(t);
}
{
  const t=setup();t.install();let cloned=false;
  const request={url:local,method:'POST',clone(){cloned=true;throw new Error('Do not read request');}};
  await t.context.fetch(request);await settle(t);
  assert.equal(cloned,false);assert.equal(t.calls[0].args[0],request);
  assert.equal(t.context.TokenSignerProlog.snapshot().records[0].container,'request-body-unobserved');
  t.context.TokenSignerProlog.restore();restored(t);
}
for(const url of ['http://dichvucong.gdt.gov.vn','https://dichvucong.gdt.gov.vn.evil.example','https://example.com']) {
  const t=setup({url});assert.throws(t.install,/exact GDT/);restored(t);assert.equal(t.calls.length,0);
}
{
  const t=setup();t.install();assert.throws(t.install,/already installed/);
  const ws=new t.WS('ws://127.0.0.1:8769/plugin/sign');
  for(let i=0;i<60;i++) ws.send(JSON.stringify({CODE:'OFFLINE_XML_SIGN_002',URL_FILE_NAME:'PRIVATE_PATH'}));
  await settle(t);assert.equal(t.calls.length,60);assert.equal(t.context.TokenSignerProlog.snapshot().records.length,48);
  t.context.TokenSignerProlog.restore();restored(t);
}
console.log('PASS: passive fetch/XHR/WS; single and double base64; multipart byte digest; prolog marker; no raw XML/credentials/URLs/filenames; exact portal; record cap; expiry/restoration; reused XHR correlation.');
