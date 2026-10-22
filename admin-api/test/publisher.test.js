'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {renderSite,digest}=require('../publisher');

const catalog=()=>[
 {id:'dinheiro-no-controle',name:'Dinheiro no Controle — Guia Prático de Finanças Pessoais',description:'Um guia de finanças.',price_cents:2990,checkout_url:'https://pay.kiwify.com.br/RBsy9xi',image_url:'',published:true},
 {id:'ia-na-pratica',name:'IA na Prática — 50 Tarefas com Inteligência Artificial',description:'Aprenda a utilizar IA.',price_cents:2990,checkout_url:'https://pay.kiwify.com.br/smxRgiT',image_url:'',published:true}
];
const card=(id,cls,key,name,description,url)=>'<article class="card '+cls+'" id="'+id+'">'+
 '<div class="card-title"><span class="tag">E-book</span><h3>'+name+'</h3></div>'+
 '<div class="card-body"><p>'+description+'</p><div class="buy">'+
 '<div class="price">R$ 29,90<span>E-book digital</span></div>'+
 '<a class="btn btn-primary js-buy" data-key="'+key+'" href="'+url+'" rel="noopener noreferrer">Comprar agora</a>'+
 '</div></div></article>';
const fixture=()=>{
 const x=catalog();
 return '<!doctype html><html lang="pt-BR"><body><ul class="facts"><li><svg></svg>R$ 29,90 cada</li></ul>'+
 '<section id="ebooks">'+
 card('financas','card-fin','financas','Dinheiro no Controle',x[0].description,x[0].checkout_url)+
 card('ia','card-ia','ia','IA na Prática',x[1].description,x[1].checkout_url)+
 '</section>'+'.'.repeat(26000)+'</body></html>';
};

test('can update titles, descriptions, display prices and Kiwify links',()=>{
 const c=catalog();c[0].description='Organize suas contas & metas';c[0].price_cents=3590;
 const output=renderSite(fixture(),c);
 assert.equal(output.changes.length,2);
 assert.match(output.html,/Organize suas contas &amp; metas/);
 assert.match(output.html,/R\$ 35,90/);
 assert.match(output.html,/Confira os preços abaixo/);
 assert.match(output.html,/https:\/\/pay.kiwify.com.br\/RBsy9xi/);
 assert.equal(output.changed,true);
});
test('successive updates keep hero price consistent',()=>{
 const c=catalog();c[0].price_cents=3990;c[1].price_cents=3990;
 const first=renderSite(fixture(),c);
 assert.match(first.html,/R\$ 39,90 cada/);
 c[0].price_cents=4990;c[1].price_cents=4990;
 const second=renderSite(first.html,c);
 assert.match(second.html,/R\$ 49,90 cada/);
 c[1].price_cents=6990;
 const third=renderSite(second.html,c);
 assert.match(third.html,/Confira os preços abaixo/);
});
test('unchanged source stays unchanged',()=>{
 const original=fixture();
 const result=renderSite(original,catalog());
 assert.equal(result.changed,false);
 assert.equal(result.html,original);
});
test('rejects external or spoofed checkout hosts',()=>{
 for(const url of ['http://pay.kiwify.com.br/xBAD12','https://pay.kiwify.com.br.evil.com/a12345','https://evil.com/a12345']){
   const c=catalog();c[0].checkout_url=url;
   assert.throws(()=>renderSite(fixture(),c),/invalid_checkout/);
 }
});
test('blocks unsupported product additions, hidden products and image uploads',()=>{
 const c=catalog();
 c.push({...c[0],id:'terceiro'});
 assert.throws(()=>renderSite(fixture(),c),/only_two_original_products_supported/);
 c.pop();c[0].published=false;
 assert.throws(()=>renderSite(fixture(),c),/hidden_products_not_supported/);
 c[0].published=true;c[0].image_url='https://example.com/cover.png';
 assert.throws(()=>renderSite(fixture(),c),/image_upload_not_supported/);
});
test('escapes user HTML instead of injecting markup',()=>{
 const c=catalog();c[0].description='<img src=x onerror=alert(1)>';
 const out=renderSite(fixture(),c);
 assert.match(out.html,/&lt;img src=x onerror=alert\(1\)&gt;/);
 assert.doesNotMatch(out.html,/<img src=x onerror=alert\(1\)>/);
});
test('halts safely when the storefront markup changes',()=>{
 assert.throws(()=>renderSite(fixture().replace('data-key="ia"','data-key="new"'),catalog()),/site_template_changed/);
});
test('draft digest independent of product order',()=>{
 const c=catalog();
 assert.equal(digest(c),digest([...c].reverse()));
});

test('digest uses canonical fields even when JSONB returns properties in another order',()=>{
 const c=catalog();
 const asJsonb=c.map(p=>({
   published:p.published,checkout_url:p.checkout_url,price_cents:p.price_cents,
   description:p.description,id:p.id,image_url:p.image_url,name:p.name
 }));
 assert.equal(digest(c),digest(asJsonb));
});

test('publishes an Eduzz checkout URL for selected product without changing other Kiwify checkout',()=>{
 const c=catalog();
 c[0].checkout_url='https://chk.eduzz.com/797ZQ5P80E';
 const out=renderSite(fixture(),c);
 assert.match(out.html,/href="https:\/\/chk\.eduzz\.com\/797ZQ5P80E"/);
 assert.match(out.html,/href="https:\/\/pay\.kiwify\.com\.br\/smxRgiT"/);
});
test('rejects phishing lookalike and unsafe Eduzz checkout URLs',()=>{
 for(const link of [
   'https://chk.eduzz.com.evil.example/797ZQ5P80E',
   'https://chk.eduzz.com/797ZQ5P80E?redirect=https://evil.example',
   'http://chk.eduzz.com/797ZQ5P80E',
   'https://sun.eduzz.com/123456#fragment'
 ]){
   const c=catalog();c[0].checkout_url=link;
   assert.throws(()=>renderSite(fixture(),c),/invalid_checkout/);
 }
});
