'use strict';
const fs=require('node:fs');
const publisher=require('./publisher');
const {checkoutProvider}=require('./checkout');
const providerApi=require('./provider-api');
const providerTestTimes=new Map();
const http=require('node:http'),crypto=require('node:crypto'),{Pool}=require('pg');
const db=process.env.DATABASE_URL||'',secret=process.env.SESSION_SECRET||'',port=Number(process.env.PORT||3000);
// O proprietario pode configurar ADMIN_PASSWORD diretamente como segredo no Render.
// A senha e derivada em memoria com scrypt no inicio do processo, sem usar texto puro para comparacao.
// ADMIN_PASSWORD_SCRYPT permanece disponivel para instalacoes com hash previamente criado.
const hash=(()=>{
  const prehash=process.env.ADMIN_PASSWORD_SCRYPT||'';
  if(/^scrypt:[a-f0-9]{32}:[a-f0-9]{128}$/.test(prehash))return prehash;
  const password=process.env.ADMIN_PASSWORD||'';
  if(password.length<16||password.length>128)return '';
  const salt=crypto.randomBytes(16).toString('hex');
  const derived=crypto.scryptSync(password,salt,64).toString('hex');
  delete process.env.ADMIN_PASSWORD;
  return 'scrypt:'+salt+':'+derived;
})();
const ready=!!db&&secret.length>=32&&/^scrypt:[a-f0-9]{32}:[a-f0-9]{128}$/.test(hash);
const pool=db?new Pool({connectionString:db,ssl:{rejectUnauthorized:true},max:3,connectionTimeoutMillis:6000}):null;
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const json=(res,s,data,extra={})=>{res.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...extra});res.end(JSON.stringify(data));};
function pass(password){if(typeof password!=='string'||password.length>512)return false;try{const [,salt,expected]=hash.split(':');const got=crypto.scryptSync(password,salt,64);return crypto.timingSafeEqual(got,Buffer.from(expected,'hex'));}catch{return false;}}
async function parse(req,limit=250000){let size=0,arr=[];for await(const c of req){size+=c.length;if(size>limit)throw Error('too_large');arr.push(c);}return JSON.parse(Buffer.concat(arr).toString('utf8'));}
async function session(req){const c=(req.headers.cookie||'').match(/(?:^|;\s*)nexa_session=([a-f0-9]{64})\.([a-f0-9]{64})(?:;|$)/);if(!c||!ready)return null;const mac=crypto.createHmac('sha256',secret).update(c[1]).digest('hex');if(!crypto.timingSafeEqual(Buffer.from(c[2],'hex'),Buffer.from(mac,'hex')))return null;const r=await pool.query('SELECT token_hash,csrf_token FROM admin_sessions WHERE token_hash=$1 AND expires_at>now()',[sha(c[1])]);return r.rows[0]||null;}
async function requireAuth(req,res,mutation=false){const s=await session(req);if(!s){json(res,401,{error:'unauthorized'});return null;}if(mutation&&req.headers['x-csrf-token']!==s.csrf_token){json(res,403,{error:'csrf'});return null;}return s;}
function valid(p){if(!p||typeof p.id!=='string'||!/^[a-z0-9_-]{1,64}$/.test(p.id)||typeof p.name!=='string'||!p.name.trim()||p.name.length>160||typeof p.description!=='string'||p.description.length>4000||!Number.isInteger(p.price_cents)||p.price_cents<0||p.price_cents>100000000||typeof p.published!=='boolean'||typeof p.checkout_url!=='string'||typeof p.image_url!=='string')return false;try{if(!checkoutProvider(p.checkout_url))return false;if(p.image_url){const x=new URL(p.image_url);if(x.protocol!=='https:'||x.username||x.password||x.hash||p.image_url.length>1500)return false;}}catch{return false;}return true;}
const css="*{box-sizing:border-box}html{color-scheme:dark}body{margin:0;min-height:100vh;background:#0c0d0e;color:#f4f5f5;font:14px/1.6 Inter,system-ui,-apple-system,\"Segoe UI\",sans-serif}header{height:76px;display:flex;align-items:center;justify-content:space-between;padding:0 6%;border-bottom:1px solid #292b2d;background:#101112}header strong{font-size:13px;letter-spacing:.055em}header small{font-size:12px;color:#9da4a5}main{min-height:calc(100vh - 76px);padding:8vh 20px}.panel{max-width:445px;margin:auto;background:#181a1b;border:1px solid #303336;border-radius:16px;padding:40px;box-shadow:0 24px 90px #0006}.panel h1{font-weight:680;font-size:29px;letter-spacing:-.04em;margin:0 0 8px}.panel p{color:#999fa1;font-size:13px;margin:8px 0 23px}form label{display:block;color:#d6dadb;font-weight:600;margin:18px 0 9px}input{width:100%;padding:14px;background:#212324;color:#f4f5f5;border:1px solid #414548;border-radius:9px;font:inherit}input:focus-visible{outline:2px solid #acc9b4;outline-offset:2px}button{border:0;border-radius:9px;background:#e4f2e7;color:#1f2922;font-weight:720;padding:13px 28px;cursor:pointer}button:hover{background:white}button:disabled{opacity:.6;cursor:wait}#status{color:#cfd9d1;min-height:20px}@media(max-width:520px){main{padding:40px 18px}.panel{padding:30px 24px}header{padding:0 22px}header strong{font-size:11px}}";
const commonHead=(nonce,title)=>'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+'</title><style nonce="'+nonce+'">'+css+'</style></head>';
const loginScript="document.querySelector('form').onsubmit=async e=>{e.preventDefault();let b=document.querySelector('button');b.disabled=true;try{let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.querySelector('input').value})});document.getElementById('status').textContent=r.ok?'Acesso autorizado':'Acesso indisponível ou senha incorreta';if(r.ok)location.href='/admin';}catch{document.getElementById('status').textContent='Sem conexão';}finally{b.disabled=false;}}";
function html(res,body,script,title){const nonce=crypto.randomBytes(16).toString('base64');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(commonHead(nonce,title)+body+'<script nonce="'+nonce+'">'+script+'</script></html>');}
const adminTemplate=fs.readFileSync(require('node:path').join(__dirname,'dashboard-dark.html'),'utf8');
function serveDashboard(res){const nonce=crypto.randomBytes(16).toString('base64');res.setHeader('Content-Security-Policy',"default-src 'none';script-src 'nonce-"+nonce+"';style-src 'nonce-"+nonce+"';connect-src 'self';form-action 'self';base-uri 'none';frame-ancestors 'none'");res.setHeader('X-Robots-Tag','noindex, nofollow');res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(adminTemplate.replaceAll('%%NEXA_NONCE%%',nonce));}
const server=http.createServer(async(req,res)=>{res.setHeader('X-Frame-Options','DENY');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Strict-Transport-Security','max-age=31536000');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Content-Security-Policy',"default-src 'none';frame-ancestors 'none'");const route=new URL(req.url,'http://localhost').pathname;try{
 if(route==='/health'&&req.method==='GET')return json(res,200,{status:'ok',configured:ready});
 if(route==='/'&&req.method==='GET'){res.writeHead(302,{Location:'/login'});return res.end();}
 if(route==='/login'&&req.method==='GET')return html(res,'<header><strong>NEXA DIGITAL ACADEMY</strong><small>Área administrativa</small></header><main><section class="panel"><h1>Acessar painel</h1><p>Entre com a senha administrativa.</p><form><label>Senha</label><input type="password" required autocomplete="current-password"><p><button type="submit">Entrar</button></p></form><p id="status" role="status"></p></section></main>',loginScript,'Nexa Admin — Entrar');
 if(!ready)return json(res,503,{error:'setup_required'});
 if(route==='/admin'&&req.method==='GET'){if(!await session(req)){res.writeHead(302,{Location:'/login'});return res.end();}return serveDashboard(res);}
 if(['POST','PUT','DELETE'].includes(req.method)&&req.headers.origin&&req.headers.origin!=='https://'+req.headers.host&&req.headers.origin!=='http://localhost:'+port&&req.headers.origin!=='http://127.0.0.1:'+port)return json(res,403,{error:'invalid_origin'});
 if(route==='/api/login'&&req.method==='POST'){const ip=crypto.createHmac('sha256',secret).update(req.socket.remoteAddress||'').digest('hex');const count=await pool.query("SELECT count(*)::int n FROM admin_login_attempts WHERE ip_hash=$1 AND attempted_at>now()-interval '15 minutes'",[ip]);if(count.rows[0].n>=7)return json(res,429,{error:'rate_limited'});const b=await parse(req,4096);if(!pass(b.password)){await pool.query('INSERT INTO admin_login_attempts(ip_hash) VALUES($1)',[ip]);return json(res,401,{error:'invalid_credentials'});}await pool.query('DELETE FROM admin_login_attempts WHERE ip_hash=$1',[ip]);const token=crypto.randomBytes(32).toString('hex'),csrf=crypto.randomBytes(24).toString('hex');await pool.query("INSERT INTO admin_sessions(token_hash,csrf_token,expires_at) VALUES($1,$2,now()+interval '8 hours')",[sha(token),csrf]);const mac=crypto.createHmac('sha256',secret).update(token).digest('hex');return json(res,200,{ok:true},{'Set-Cookie':'nexa_session='+token+'.'+mac+'; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'});}
 if(route==='/api/session'&&req.method==='GET'){const s=await requireAuth(req,res);if(!s)return;return json(res,200,{csrf:s.csrf_token});}
 if(route==='/api/logout'&&req.method==='POST'){const s=await requireAuth(req,res,true);if(!s)return;await pool.query('DELETE FROM admin_sessions WHERE token_hash=$1',[s.token_hash]);return json(res,200,{ok:true},{'Set-Cookie':'nexa_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'});}
 // Consultar snapshot histórico para restaurar somente o rascunho, mediante confirmação no painel.
 if(route.startsWith('/api/revisions/')&&req.method==='GET'){
   if(!await requireAuth(req,res))return;
   const match=route.match(/^\/api\/revisions\/([1-9][0-9]{0,15})$/);
   if(!match)return json(res,404,{error:'not_found'});
   const r=await pool.query('SELECT id,action,catalog,created_at FROM catalog_revisions WHERE id=$1',[match[1]]);
   if(!r.rows.length)return json(res,404,{error:'revision_not_found'});
   const snapshot=r.rows[0];
   if(!Array.isArray(snapshot.catalog)||snapshot.catalog.length>100||!snapshot.catalog.every(valid)||
      new Set(snapshot.catalog.map(x=>x.id)).size!==snapshot.catalog.length)return json(res,409,{error:'revision_invalid'});
   return json(res,200,{revision:{id:snapshot.id,action:snapshot.action,created_at:snapshot.created_at},products:snapshot.catalog,site_changed:false});
 }
 if(route==='/api/activity'&&req.method==='GET'){if(!await requireAuth(req,res))return;const r=await pool.query('SELECT id,action,created_at FROM catalog_revisions ORDER BY id DESC LIMIT 20');return json(res,200,{events:r.rows});}
 // Provider checkout links, not account/API connectivity. No secrets are handled here.
 if(route==='/api/providers'&&req.method==='GET'){
   if(!await requireAuth(req,res))return;
   const checkouts=await pool.query('SELECT product_id,provider,checkout_url,updated_at FROM product_checkout_links ORDER BY product_id,provider');
   const states=await pool.query('SELECT provider,connection_status,linked_at FROM provider_connections ORDER BY provider');
   const env=providerApi.configured();
   const connections=states.rows.map(x=>({...x,credentials_configured:!!env[x.provider],api_verified:!!env[x.provider]&&x.connection_status==='connected'}));
   return json(res,200,{checkouts:checkouts.rows,connections,checkout_note:'Os testes validam acesso de leitura a produtos e vendas, sem importar dados ou alterar contas.'});
 }
 if(route==='/api/providers/test'&&req.method==='POST'){
   if(!await requireAuth(req,res,true))return;
   const body=await parse(req,512);
   if(!body||!['kiwify','eduzz'].includes(body.provider))return json(res,400,{error:'invalid_provider'});
   const provider=body.provider,now=Date.now();
   if(now-(providerTestTimes.get(provider)||0)<30000)return json(res,429,{error:'wait_before_retest'});
   providerTestTimes.set(provider,now);
   const result=await providerApi.testProvider(provider);
   if(result.code!=='missing_credentials'){
     await pool.query("UPDATE provider_connections SET connection_status=$2,linked_at=CASE WHEN $2='connected' THEN now() ELSE NULL END,updated_at=now() WHERE provider=$1",[
       provider,result.ok?'connected':'error'
     ]);
     await pool.query('INSERT INTO admin_audit(event,detail) VALUES($1,$2)',[
       'provider_api_test',JSON.stringify({provider,success:result.ok,code:result.code||'ok',scopes_verified:result.scopes_verified||[]})
     ]);
   }
   return json(res,result.ok?200:422,{...result,provider,credentials_exposed:false,site_changed:false,sales_imported:false});
 }
 if(route==='/api/providers/eduzz-checkout'&&req.method==='PUT'){
   if(!await requireAuth(req,res,true))return;
   const b=await parse(req,4096);
   if(!b||typeof b.product_id!=='string'||!/^[a-z0-9_-]{1,64}$/.test(b.product_id)||typeof b.checkout_url!=='string'||b.checkout_url.length>1800)return json(res,400,{error:'invalid_eduzz_checkout'});
   const url=b.checkout_url.trim();
   if(url&&checkoutProvider(url)!=='eduzz')return json(res,400,{error:'invalid_eduzz_checkout'});
   const exists=await pool.query('SELECT 1 FROM products WHERE id=$1',[b.product_id]);
   if(exists.rowCount!==1)return json(res,404,{error:'product_not_found'});
   const client=await pool.connect();
   try{
     await client.query('BEGIN');
     const locked=(await client.query('SELECT checkout_url FROM products WHERE id=$1 FOR UPDATE',[b.product_id])).rows[0];
     if(!locked){await client.query('ROLLBACK');return json(res,404,{error:'product_not_found'});}
     const selectedEduzz=checkoutProvider(locked.checkout_url)==='eduzz';
     if(!url&&selectedEduzz){await client.query('ROLLBACK');return json(res,409,{error:'cannot_remove_checkout_selected_for_draft'});}
     if(url)await client.query(`INSERT INTO product_checkout_links(product_id,provider,checkout_url) VALUES($1,'eduzz',$2) ON CONFLICT (product_id,provider) DO UPDATE SET checkout_url=excluded.checkout_url,updated_at=now()`,[b.product_id,url]);
     if(url&&selectedEduzz&&locked.checkout_url!==url){
       await client.query('UPDATE products SET checkout_url=$2,updated_at=now() WHERE id=$1',[b.product_id,url]);
       const snapshot=(await client.query('SELECT id,name,description,price_cents,checkout_url,image_url,published FROM products ORDER BY id')).rows;
       await client.query('INSERT INTO catalog_revisions(catalog,action) VALUES($1,$2)',[JSON.stringify(snapshot),'draft_save']);
     }
     else await client.query("DELETE FROM product_checkout_links WHERE product_id=$1 AND provider='eduzz'",[b.product_id]);
     await client.query('INSERT INTO admin_audit(event,detail) VALUES($1,$2)',[
       'eduzz_checkout_configured',JSON.stringify({product_id:b.product_id,configured:!!url})]);
     await client.query('COMMIT');
     return json(res,200,{ok:true,configured:!!url,saved_to_database:true,site_changed:false,draft_checkout_updated:!!(url&&selectedEduzz&&locked.checkout_url!==url),sales_api_connected:false});
   }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 }
 if(route==='/api/products'&&req.method==='GET'){if(!await requireAuth(req,res))return;const r=await pool.query('SELECT id,name,description,price_cents,checkout_url,image_url,published FROM products ORDER BY id');return json(res,200,{products:r.rows});}
 if(route==='/api/products'&&req.method==='PUT'){if(!await requireAuth(req,res,true))return;const b=await parse(req);if(!Array.isArray(b.products)||b.products.length>100||!b.products.every(valid)||new Set(b.products.map(x=>x.id)).size!==b.products.length)return json(res,400,{error:'invalid_catalog'});const cx=await pool.connect();try{await cx.query('BEGIN');await cx.query('DELETE FROM products WHERE NOT(id=ANY($1::text[]))',[b.products.map(p=>p.id)]);for(const p of b.products){
   await cx.query('INSERT INTO products(id,name,description,price_cents,checkout_url,image_url,published) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET name=excluded.name,description=excluded.description,price_cents=excluded.price_cents,checkout_url=excluded.checkout_url,image_url=excluded.image_url,published=excluded.published,updated_at=now()',[p.id,p.name,p.description,p.price_cents,p.checkout_url,p.image_url,p.published]);
   await cx.query('INSERT INTO product_checkout_links(product_id,provider,checkout_url) VALUES($1,$2,$3) ON CONFLICT (product_id,provider) DO UPDATE SET checkout_url=excluded.checkout_url,updated_at=now()',[p.id,checkoutProvider(p.checkout_url),p.checkout_url]);
 }await cx.query('INSERT INTO catalog_revisions(catalog,action) VALUES($1,$2)',[JSON.stringify(b.products),'draft_save']);await cx.query('INSERT INTO admin_audit(event,detail) VALUES($1,$2)',['draft_save',JSON.stringify({count:b.products.length})]);await cx.query('COMMIT');return json(res,200,{saved:b.products.length,published_to_site:false});}catch(e){await cx.query('ROLLBACK');throw e;}finally{cx.release();}}
 // Preview compares the exact database draft with the current GitHub storefront.

 if(route==='/api/public-catalog'&&req.method==='GET'){
   const r=await pool.query('SELECT catalog,version,published_at FROM published_catalog WHERE id=1');
   if(!r.rows.length)return json(res,503,{error:'not_published'});
   const origin=req.headers.origin;
   const allowed=origin==='https://nexa-digital-academy.onrender.com';
   return json(res,200,{products:r.rows[0].catalog,version:r.rows[0].version,published_at:r.rows[0].published_at},{
     ...(allowed?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{}),
     'Cache-Control':'public,max-age=30'
   });
 }
 if(route==='/api/publish/preview'&&req.method==='GET'){
   if(!await requireAuth(req,res))return;
   const draft=(await pool.query('SELECT id,name,description,price_cents,checkout_url,image_url,published FROM products ORDER BY id')).rows;
   try{
     publisher.assertCatalog(draft);
     const pub=(await pool.query('SELECT catalog,version FROM published_catalog WHERE id=1')).rows[0];
     const current=pub?.catalog||[];
     const changed=publisher.digest(draft)!==publisher.digest(current);
     return json(res,200,{catalog_digest:publisher.digest(draft),current_version:Number(pub?.version||0),
       changes:draft.map(p=>({product:p.id,title:p.name,description:p.description,price:'R$ '+(p.price_cents/100).toFixed(2).replace('.',','),checkout:p.checkout_url})),
       changed,publisher_enabled:true,store_url:'https://nexa-digital-academy.onrender.com',
       restrictions:'Dois e-books existentes; checkouts oficiais Kiwify ou Eduzz. Edicoes em plataformas externas e imagens aguardam integracao.'});
   }catch(e){return json(res,409,{error:e.message==='site_template_changed'?'site_template_changed':'catalog_not_publishable'});}
 }
 if(route==='/api/publish'&&req.method==='POST'){
   if(!await requireAuth(req,res,true))return;
   const reqBody=await parse(req,2048);
   if(reqBody.confirm_checkout_prices!==true||!Number.isSafeInteger(reqBody.current_version)||typeof reqBody.catalog_digest!=='string')
     return json(res,400,{error:'publish_confirmation_required'});
   const cx=await pool.connect();
   try{
     await cx.query('BEGIN');
     const pub=(await cx.query('SELECT catalog,version FROM published_catalog WHERE id=1 FOR UPDATE')).rows[0];
     if(!pub||Number(pub.version)!==reqBody.current_version){await cx.query('ROLLBACK');return json(res,409,{error:'catalog_changed_since_preview'});}
     const draft=(await cx.query('SELECT id,name,description,price_cents,checkout_url,image_url,published FROM products ORDER BY id')).rows;
     if(publisher.digest(draft)!==reqBody.catalog_digest){await cx.query('ROLLBACK');return json(res,409,{error:'catalog_changed_since_preview'});}
     // The store supports two existing products and checkout URLs from approved providers.
     publisher.assertCatalog(draft);
     if(publisher.digest(pub.catalog)===publisher.digest(draft)){await cx.query('ROLLBACK');return json(res,200,{ok:true,changed:false});}
     await cx.query('UPDATE published_catalog SET catalog=$1::jsonb,version=version+1,published_at=now() WHERE id=1',[JSON.stringify(draft)]);
     await cx.query('INSERT INTO catalog_revisions(catalog,action) VALUES($1,$2)',[JSON.stringify(draft),'site_publish']);
     await cx.query('INSERT INTO admin_audit(event,detail) VALUES($1,$2)', ['site_publish',JSON.stringify({mode:'public_snapshot',products:draft.length})]);
     await cx.query('COMMIT');
     return json(res,200,{ok:true,changed:true,published_live:true});
   }catch(e){await cx.query('ROLLBACK').catch(()=>{});if(['only_two_original_products_supported','hidden_products_not_supported','image_upload_not_supported','invalid_checkout','site_template_changed'].includes(e.message))return json(res,409,{error:e.message});throw e;}
   finally{cx.release();}
 }
 return json(res,404,{error:'not_found'});
 }catch(e){if(e.message==='too_large')return json(res,413,{error:'payload_too_large'});if(e instanceof SyntaxError)return json(res,400,{error:'invalid_json'});console.error('Nexa admin request failed',e.code||e.message);return json(res,503,{error:'service_unavailable'});}
});
server.listen(port,()=>console.log('Nexa Admin listening on '+port+'; configured='+ready));
