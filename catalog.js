'use strict';
(function(){
 const API='https://nexa-admin-pro-api.onrender.com/api/public-catalog';
 const products=[['dinheiro-no-controle','financas'],['ia-na-pratica','ia']];
 const valid=(p)=>p&&typeof p.name==='string'&&typeof p.description==='string'&&Number.isInteger(p.price_cents)&&p.price_cents>=0&&p.price_cents<=100000000&&typeof p.checkout_url==='string'&&p.published===true;
 function checkout(url){
   try{const u=new URL(url);return u.protocol==='https:'&&u.hostname==='pay.kiwify.com.br'&&!u.username&&!u.password&&!u.search&&!u.hash&&/^\/[a-zA-Z0-9_-]{5,80}\/?$/.test(u.pathname);}catch{return false;}
 }
 function text(selector,node,value){const el=node.querySelector(selector);if(el)el.textContent=value;}
 function render(data){
   if(!data||!Array.isArray(data.products)||data.products.length!==2)return;
   const byId=new Map(data.products.map(p=>[p.id,p]));
   if(byId.size!==2)return;
   for(const [pid] of products){const p=byId.get(pid);if(!valid(p)||!checkout(p.checkout_url)||p.image_url)return;}
   // Validate all before making any changes; the page is fully usable without API access.
   for(const [pid,anchor] of products){
     const p=byId.get(pid),card=document.getElementById(anchor);
     if(!card||!card.classList.contains('card'))continue;
     text('.card-title h3',card,(p.name.split(/\s+[—–]\s+/)[0]||p.name).trim());
     text('.card-body > p',card,p.description.trim());
     const price=card.querySelector('.price');
     if(price&&price.firstChild&&price.firstChild.nodeType===Node.TEXT_NODE)price.firstChild.nodeValue='R$ '+(p.price_cents/100).toFixed(2).replace('.',',');
     const buy=card.querySelector('a.js-buy');
     if(buy){buy.href=p.checkout_url;buy.rel='noopener noreferrer';}
   }
   const costs=[...byId.values()].map(p=>p.price_cents);
   const fact=document.querySelector('.facts li:last-child');
   if(fact){for(const node of fact.childNodes){if(node.nodeType===Node.TEXT_NODE){node.nodeValue=costs[0]===costs[1]?'R$ '+(costs[0]/100).toFixed(2).replace('.',',')+' cada':'Confira os preços abaixo';break;}}}
 }
 const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),6000);
 fetch(API,{method:'GET',mode:'cors',credentials:'omit',cache:'no-store',signal:abort.signal})
   .then(r=>r.ok?r.json():Promise.reject(Error('unavailable'))).then(render).catch(()=>{})
   .finally(()=>clearTimeout(timeout));
})();