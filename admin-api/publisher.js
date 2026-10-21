'use strict';
const crypto=require('node:crypto');
const REPO='felipemoura-code/nexa-digital-academy';
const FILE='index.html';
const BRANCH='main';
const known=[
  {id:'dinheiro-no-controle',anchor:'<article class="card card-fin" id="financas">',key:'financas'},
  {id:'ia-na-pratica',anchor:'<article class="card card-ia" id="ia">',key:'ia'}
];
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const brl=n=>'R$ '+(n/100).toFixed(2).replace('.',',');
function assertCatalog(products){
  if(!Array.isArray(products)||products.length!==2)throw Error('only_two_original_products_supported');
  const ids=products.map(p=>p.id).sort().join(',');
  if(ids!==known.map(x=>x.id).sort().join(','))throw Error('only_two_original_products_supported');
  for(const p of products){
    if(p.published!==true)throw Error('hidden_products_not_supported');
    if(p.image_url)throw Error('image_upload_not_supported');
    if(typeof p.name!=='string'||!p.name.trim()||p.name.length>160)throw Error('invalid_catalog');
    if(typeof p.description!=='string'||p.description.length>4000)throw Error('invalid_catalog');
    if(!Number.isSafeInteger(p.price_cents)||p.price_cents<0)throw Error('invalid_catalog');
    const url=new URL(p.checkout_url);
    if(url.protocol!=='https:'||url.hostname!=='pay.kiwify.com.br'||url.username||url.password||url.search||url.hash||!/^\/[a-zA-Z0-9_-]{5,80}\/?$/.test(url.pathname))throw Error('invalid_checkout');
  }
}
function changeOne(html,spec,p){
  const start=html.indexOf(spec.anchor);
  if(start<0||html.indexOf(spec.anchor,start+1)>=0)throw Error('site_template_changed');
  const end=html.indexOf('</article>',start);
  if(end<0)throw Error('site_template_changed');
  const original=html.slice(start,end+10);
  const title=(p.name.split(/\s+[—–]\s+/)[0]||p.name).trim();
  let next=original;
  let n=0;
  next=next.replace(/(<div class="card-title">[\s\S]*?<h3>)[\s\S]*?(<\/h3>)/,(_,a,b)=>{n++;return a+esc(title)+b;});
  next=next.replace(/(<div class="card-body">\s*<p>)[\s\S]*?(<\/p>)/,(_,a,b)=>{n++;return a+esc(p.description.trim())+b;});
  next=next.replace(/(<div class="price">)[^<]*(<span>)/,(_,a,b)=>{n++;return a+esc(brl(p.price_cents))+b;});
  const re=new RegExp('(<a class="btn btn-primary js-buy" data-key="'+spec.key+'" href=")[^"]+(")');
  next=next.replace(re,(_,a,b)=>{n++;return a+esc(p.checkout_url)+b;});
  if(n!==4)throw Error('site_template_changed');
  return {html:html.slice(0,start)+next+html.slice(end+10),changes:{product:p.id,title,price:brl(p.price_cents),checkout:p.checkout_url,description:p.description.trim()}};
}
function renderSite(html,products){
  assertCatalog(products);
  if(!html.startsWith('<!doctype html>')||html.length<25000||!html.includes('id="ebooks"'))throw Error('site_template_changed');
  let next=html,changes=[];
  for(const spec of known){const p=products.find(p=>p.id===spec.id);const result=changeOne(next,spec,p);next=result.html;changes.push(result.changes);}
  const prices=new Set(products.map(p=>p.price_cents));
  // The hero currently mentions one common price. Replace it if catalog prices diverge.
  if(prices.size!==1)next=next.replace(/R\$ 29,90 cada/,'Confira os preços abaixo');
  else next=next.replace(/R\$ 29,90 cada/,brl(products[0].price_cents)+' cada');
  return {html:next,changes,changed:next!==html};
}
function digest(products){return crypto.createHash('sha256').update(JSON.stringify([...products].sort((a,b)=>a.id.localeCompare(b.id)))).digest('hex');}
async function githubRequest(url,token,opts={}){
 const headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'NexaAdmin-Publisher',...(token?{'Authorization':'Bearer '+token}:{}),'Content-Type':'application/json'};
 const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),9000);
 try{const response=await fetch(url,{...opts,headers,signal:controller.signal});
   const data=await response.json().catch(()=>({}));
   if(!response.ok){const e=Error('github_'+response.status);e.status=response.status;throw e;}
   return data;
 }finally{clearTimeout(timer);}
}
async function getStore(token){
 const u='https://api.github.com/repos/'+REPO+'/contents/'+FILE+'?ref='+BRANCH;
 const data=await githubRequest(u,token);
 if(data.encoding!=='base64'||!data.sha||!data.content)throw Error('github_invalid_response');
 return {sha:data.sha,html:Buffer.from(data.content.replace(/\s/g,''),'base64').toString('utf8')};
}
async function updateStore(token,currentSha,html){
 if(!token)throw Error('publisher_not_configured');
 const url='https://api.github.com/repos/'+REPO+'/contents/'+FILE;
 const result=await githubRequest(url,token,{method:'PUT',body:JSON.stringify({message:'Publicar catalogo Nexa Admin (revisao autorizada)',branch:BRANCH,sha:currentSha,content:Buffer.from(html,'utf8').toString('base64')})});
 return {commit:result.commit?.sha||null,blob:result.content?.sha||null};
}
module.exports={renderSite,digest,getStore,updateStore};
