'use strict';
// Verificacao somente leitura, com destinos HTTPS fixos e sem expor credenciais ou dados de clientes.
const NAMES=['kiwify','eduzz'];
function configured(){
 return {
  kiwify:!!(process.env.KIWIFY_CLIENT_ID&&process.env.KIWIFY_CLIENT_SECRET&&process.env.KIWIFY_ACCOUNT_ID),
  eduzz:!!process.env.EDUZZ_APP_ACCESS_TOKEN
 };
}
async function request(url,options={}){
 return fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(9000)});
}
function fail(code){return {ok:false,code};}
async function checkRead(url,headers){
 const r=await request(url,{method:'GET',headers:{Accept:'application/json',...headers}});
 const status=r.status;
 if(r.body)await r.body.cancel().catch(()=>{});
 if(status===401)return fail('invalid_credentials');
 if(status===403)return fail('missing_permission');
 if(status===429)return fail('rate_limited');
 if(status<200||status>=300)return fail('provider_error');
 return {ok:true};
}
async function testProvider(provider){
 if(!NAMES.includes(provider))return fail('invalid_provider');
 if(!configured()[provider])return fail('missing_credentials');
 try{
  if(provider==='kiwify'){
   const body=new URLSearchParams({client_id:process.env.KIWIFY_CLIENT_ID,client_secret:process.env.KIWIFY_CLIENT_SECRET});
   const tokenResponse=await request('https://public-api.kiwify.com/v1/oauth/token',{
    method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body
   });
   if(!tokenResponse.ok){
    if(tokenResponse.body)await tokenResponse.body.cancel().catch(()=>{});
    return fail(tokenResponse.status===429?'rate_limited':tokenResponse.status<500?'invalid_credentials':'provider_error');
   }
   const tokenData=await tokenResponse.json();
   if(typeof tokenData.access_token!=='string'||!tokenData.access_token)return fail('invalid_response');
   const headers={Authorization:'Bearer '+tokenData.access_token,'x-kiwify-account-id':process.env.KIWIFY_ACCOUNT_ID};
   const products=await checkRead('https://public-api.kiwify.com/v1/products?page_size=1&page_number=1',headers);
   if(!products.ok)return {...products,scope:'products'};
   const sales=await checkRead('https://public-api.kiwify.com/v1/sales?page_size=1&page_number=1',headers);
   if(!sales.ok)return {...sales,scope:'sales'};
  }else{
   const headers={Authorization:'Bearer '+process.env.EDUZZ_APP_ACCESS_TOKEN};
   const products=await checkRead('https://api.eduzz.com/myeduzz/v1/products?page=1&itemsPerPage=1',headers);
   if(!products.ok)return {...products,scope:'products'};
   const now=new Date(),before=new Date(now.getTime()-86400000);
   const search=new URLSearchParams({startDate:before.toISOString(),endDate:now.toISOString(),page:'1',itemsPerPage:'1'});
   const sales=await checkRead('https://api.eduzz.com/myeduzz/v1/sales?'+search.toString(),headers);
   if(!sales.ok)return {...sales,scope:'sales'};
  }
  return {ok:true,scopes_verified:['products','sales']};
 }catch{
  return fail('provider_unreachable');
 }
}
module.exports={configured,testProvider};
