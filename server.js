"use strict";
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {Pool}=require('pg');
const port=process.env.PORT||3000;
const dbUrl=process.env.DATABASE_URL;
const adminPassword=process.env.ADMIN_PASSWORD||'';
const secret=process.env.SESSION_SECRET||'';
if(!dbUrl||!adminPassword||secret.length<32){console.error('DATABASE_URL, ADMIN_PASSWORD, SESSION_SECRET(32자 이상) 설정이 필요합니다.');process.exit(1);}
const pool=new Pool({connectionString:dbUrl,max:5});
const features=new Set(['pain','walk','mind','learn','chat']);
const secure=process.env.NODE_ENV==='production'||Boolean(process.env.RAILWAY_ENVIRONMENT);
const cookieOptions='Path=/; HttpOnly; SameSite=Lax'+(secure?'; Secure':'');
function parseCookies(req){const out={};for(const v of (req.headers.cookie||'').split(';')){const n=v.indexOf('=');if(n>0)out[v.slice(0,n).trim()]=v.slice(n+1).trim();}return out;}
function hash(s){return crypto.createHash('sha256').update(s).digest('hex');}
function safeEq(a,b){const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);}
function sign(s){return crypto.createHmac('sha256',secret).update(s).digest('hex');}
function json(res,status,obj,headers={}){const body=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers});res.end(body);}
function getBody(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>4096){reject(Error('Too large'));req.destroy();}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{});}catch(e){reject(e);}});req.on('error',reject);});}
function isSameOrigin(req){const o=req.headers.origin;if(!o)return true;try{return new URL(o).host===req.headers.host;}catch{return false;}}
function adminAuth(req){const token=parseCookies(req).enact_admin||'';const [expiry,sig]=token.split('.');if(!expiry||!sig||!/^\d+$/.test(expiry)||Number(expiry)<Date.now())return false;return safeEq(sign('admin:'+expiry),sig);}
async function participant(req){const token=parseCookies(req).enact_pid||'';if(!/^[a-f0-9]{64}$/.test(token))return null;const r=await pool.query('SELECT id, code FROM participants WHERE token_hash=$1',[hash(token)]);return r.rows[0]||null;}
async function api(req,res,pathname){
 if(!isSameOrigin(req))return json(res,403,{error:'Origin rejected'});
 if(pathname==='/api/participant'&&req.method==='POST'){
  let p=await participant(req),token;
  if(!p){token=crypto.randomBytes(32).toString('hex');const r=await pool.query("INSERT INTO participants(token_hash) VALUES ($1) RETURNING id",[hash(token)]);const id=r.rows[0].id;await pool.query("UPDATE participants SET code='P'||lpad(id::text,5,'0') WHERE id=$1",[id]);p={id,code:'P'+String(id).padStart(5,'0')};}
  await pool.query('UPDATE participants SET last_seen=NOW() WHERE id=$1',[p.id]);
  const r=await pool.query('SELECT feature FROM completions WHERE participant_id=$1',[p.id]);
  return json(res,200,{code:p.code,completed:r.rows.map(x=>x.feature)},token?{'Set-Cookie':'enact_pid='+token+'; '+cookieOptions+'; Max-Age=7776000'}:{});
 }
 if(pathname==='/api/complete'&&req.method==='POST'){
  const p=await participant(req);if(!p)return json(res,401,{error:'Participant session missing'});
  const b=await getBody(req);if(!features.has(b.feature))return json(res,400,{error:'Invalid feature'});
  await pool.query('INSERT INTO completions(participant_id,feature) VALUES($1,$2) ON CONFLICT DO NOTHING',[p.id,b.feature]);
  await pool.query('UPDATE participants SET last_seen=NOW() WHERE id=$1',[p.id]);return json(res,200,{ok:true});
 }
 if(pathname==='/api/admin/login'&&req.method==='POST'){
  const b=await getBody(req);if(typeof b.password!=='string'||!safeEq(b.password,adminPassword))return json(res,401,{error:'비밀번호를 확인해 주세요.'});
  const expiry=String(Date.now()+8*60*60*1000);return json(res,200,{ok:true},{'Set-Cookie':'enact_admin='+expiry+'.'+sign('admin:'+expiry)+'; '+cookieOptions+'; Max-Age=28800'});
 }
 if(pathname==='/api/admin/logout'&&req.method==='POST')return json(res,200,{ok:true},{'Set-Cookie':'enact_admin=; '+cookieOptions+'; Max-Age=0'});
 if(pathname==='/api/admin/records'&&req.method==='GET'){
  if(!adminAuth(req))return json(res,401,{error:'Login required'});
  const r=await pool.query(`SELECT p.code,p.created_at,p.last_seen,c.feature,c.completed_at FROM participants p LEFT JOIN completions c ON c.participant_id=p.id ORDER BY p.id DESC`);
  const map=new Map();for(const x of r.rows){if(!map.has(x.code))map.set(x.code,{code:x.code,created_at:x.created_at,last_seen:x.last_seen,completed:{}});if(x.feature)map.get(x.code).completed[x.feature]=x.completed_at;}
  return json(res,200,{records:[...map.values()]});
 }
 return json(res,404,{error:'Not found'});
}
const mime={'.html':'text/html; charset=utf-8','.mp4':'video/mp4','.webm':'video/webm','.png':'image/png','.jpg':'image/jpeg'};
function serve(req,res,pathname){
 const file=pathname==='/'?'index.html':pathname==='/admin'?'admin.html':pathname.slice(1);
 if(file!=='index.html'&&file!=='admin.html'&&!/^videos\/[a-zA-Z0-9_-]+\.(mp4|webm)$/.test(file))return res.writeHead(404).end('Not found');
 const target=path.join(__dirname,file);
 fs.stat(target,(e,st)=>{if(e||!st.isFile()){res.writeHead(404);return res.end('Not found');}
 const ext=path.extname(file),headers={'Content-Type':mime[ext]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Accept-Ranges':'bytes'};
 const range=req.headers.range;if(range&&ext==='.mp4'){const m=/bytes=(\d*)-(\d*)/.exec(range);if(m){const start=m[1]?Number(m[1]):0,end=m[2]?Math.min(Number(m[2]),st.size-1):st.size-1;if(start<=end&&end<st.size){res.writeHead(206,{...headers,'Content-Range':`bytes ${start}-${end}/${st.size}`,'Content-Length':end-start+1});return fs.createReadStream(target,{start,end}).pipe(res);}}res.writeHead(416,{'Content-Range':`bytes */${st.size}`});return res.end();}
 res.writeHead(200,{...headers,'Content-Length':st.size});fs.createReadStream(target).pipe(res);
 });
}
async function init(){await pool.query(`CREATE TABLE IF NOT EXISTS participants(id BIGSERIAL PRIMARY KEY, code TEXT UNIQUE, token_hash TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS completions(participant_id BIGINT NOT NULL REFERENCES participants(id) ON DELETE CASCADE, feature TEXT NOT NULL CHECK(feature IN ('pain','walk','mind','learn','chat')), completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(participant_id,feature))`);
 http.createServer((req,res)=>{let pathname;try{pathname=new URL(req.url,'http://localhost').pathname;}catch{return json(res,400,{error:'Bad URL'});}if(pathname.startsWith('/api/'))api(req,res,pathname).catch(e=>{console.error('API error:',e.message);if(!res.headersSent)json(res,500,{error:'Server error'});});else if(req.method==='GET'||req.method==='HEAD')serve(req,res,pathname);else json(res,405,{error:'Method not allowed'});}).listen(port,'0.0.0.0',()=>console.log('ENACT demo running on '+port));}
init().catch(e=>{console.error('Database init failed:',e.message);process.exit(1);});
