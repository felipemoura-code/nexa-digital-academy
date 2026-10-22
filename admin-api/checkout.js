'use strict';
// Allow only known first-party checkout hosts, with no redirects, credentials or query parameters.
const ED=['chk.eduzz.com','sun.eduzz.com'];
function checkoutProvider(value){
 if(typeof value!=='string')return null;
 try{
   const u=new URL(value);
   if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash)return null;
   if(u.hostname==='pay.kiwify.com.br'&&/^\/[a-zA-Z0-9_-]{5,80}\/?$/.test(u.pathname))return 'kiwify';
   if(ED.includes(u.hostname)&&/^\/[a-zA-Z0-9_-]{2,128}\/?$/.test(u.pathname))return 'eduzz';
 }catch{}
 return null;
}
module.exports={checkoutProvider};
