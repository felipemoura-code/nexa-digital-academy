'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {configured,testProvider}=require('../provider-api');
const keys=['KIWIFY_CLIENT_ID','KIWIFY_CLIENT_SECRET','KIWIFY_ACCOUNT_ID','EDUZZ_APP_ACCESS_TOKEN'];
const old={};for(const key of keys)old[key]=process.env[key];
const originalFetch=global.fetch;
test.after(()=>{for(const key of keys){if(old[key]===undefined)delete process.env[key];else process.env[key]=old[key];}global.fetch=originalFetch;});
test('recusa provedores desconhecidos e sem configuracao',async()=>{
 for(const key of keys)delete process.env[key];
 assert.equal(configured().kiwify,false);assert.equal(configured().eduzz,false);
 assert.deepEqual(await testProvider('outro'),{ok:false,code:'invalid_provider'});
 assert.deepEqual(await testProvider('kiwify'),{ok:false,code:'missing_credentials'});
 assert.deepEqual(await testProvider('eduzz'),{ok:false,code:'missing_credentials'});
});
test('Kiwify valida token, produtos e vendas sem executar alteracoes',async()=>{
 process.env.KIWIFY_CLIENT_ID='fake-id';process.env.KIWIFY_CLIENT_SECRET='fake-secret';process.env.KIWIFY_ACCOUNT_ID='fake-account';
 const calls=[];
 global.fetch=async(url,options)=>{
  calls.push({url:String(url),options});
  if(String(url).endsWith('/oauth/token'))return new Response(JSON.stringify({access_token:'temporary-test-token'}),{status:200});
  return new Response('{}',{status:200});
 };
 const result=await testProvider('kiwify');
 assert.equal(result.ok,true);assert.equal(calls.length,3);
 assert.equal(calls[0].options.method,'POST');
 assert.ok(calls[1].url.includes('/v1/products'));
 assert.ok(calls[2].url.includes('/v1/sales'));
 assert.equal(calls[1].options.headers.Authorization,'Bearer temporary-test-token');
 assert.equal(calls[1].options.headers['x-kiwify-account-id'],'fake-account');
 assert.ok(calls.slice(1).every(x=>x.options.method==='GET'));
 assert.ok(calls.every(x=>x.options.redirect==='error'));
});
test('Eduzz reprova chave sem autorizacao para leitura de vendas',async()=>{
 process.env.EDUZZ_APP_ACCESS_TOKEN='fake-eduzz-token';
 const calls=[];
 global.fetch=async(url,options)=>{
  calls.push({url:String(url),options});
  return new Response('{}',{status:String(url).includes('/sales?')?403:200});
 };
 const result=await testProvider('eduzz');
 assert.deepEqual(result,{ok:false,code:'missing_permission',scope:'sales'});
 assert.equal(calls.length,2);
 assert.ok(calls.every(x=>x.options.method==='GET'));
 assert.ok(calls.every(x=>x.options.headers.Authorization==='Bearer fake-eduzz-token'));
});
test('Eduzz confirma somente leitura quando produtos e vendas sao autorizados',async()=>{
 process.env.EDUZZ_APP_ACCESS_TOKEN='fake-eduzz-token';
 let count=0;
 global.fetch=async()=>{count++;return new Response('{}',{status:200});};
 const result=await testProvider('eduzz');
 assert.equal(result.ok,true);
 assert.deepEqual(result.scopes_verified,['products','sales']);
 assert.equal(count,2);
});
