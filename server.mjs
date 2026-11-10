import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,scryptSync,timingSafeEqual,createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
process.env.PUBLIC_ORIGIN ||= process.env.RENDER_EXTERNAL_URL;
const prod=process.env.NODE_ENV==='production', port=Number(process.env.PORT||8000);
if(prod&&!process.env.PUBLIC_ORIGIN)throw Error('PUBLIC_ORIGIN required in production');
mkdirSync(process.env.DATA_DIR||'data',{recursive:true,mode:0o700});
const sql=new DatabaseSync(resolve(process.env.DATA_DIR||'data','tawasol.sqlite'));
sql.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,salt TEXT NOT NULL,profile TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL,FOREIGN KEY(uid) REFERENCES accounts(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS media(id TEXT PRIMARY KEY,owner TEXT NOT NULL,kind TEXT NOT NULL,mime TEXT NOT NULL,bytes BLOB NOT NULL,duration REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT,action TEXT,time INTEGER);
CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY,count INTEGER,until INTEGER);`);
sql.prepare('INSERT OR IGNORE INTO state VALUES(1,?)').run(JSON.stringify({posts:[],groups:[],messages:[],reports:[],notifications:[],rooms:[],settings:{registration:true}}));
const hash=t=>createHash('sha256').update(t).digest('hex'),fail=(s,m)=>{throw Object.assign(Error(m),{status:s})};
const text=(v,n=5000)=>{if(typeof v!=='string'||!v.trim()||v.length>n)fail(400,'نص غير صالح');return v.trim()};
const profile=r=>JSON.parse(r.profile), accounts=()=>sql.prepare('SELECT * FROM accounts').all().map(profile);
const storeUser=u=>sql.prepare('UPDATE accounts SET profile=? WHERE id=?').run(JSON.stringify(u),u.id);
const permission=(u,p)=>u.role==='super'||u.role==='admin'&&u.permissions?.includes(p);
function rate(key,max=60){const now=Date.now(),r=sql.prepare('SELECT * FROM limits WHERE key=?').get(key);if(r&&r.until>now&&r.count>=max)fail(429,'طلبات كثيرة، حاول لاحقًا');sql.prepare('INSERT OR REPLACE INTO limits VALUES(?,?,?)').run(key,r&&r.until>now?r.count+1:1,r&&r.until>now?r.until:now+900000)}
const blocked=(a,b)=>(a.blocked||[]).includes(b.id)||(b.blocked||[]).includes(a.id);
const friends=(a,b)=>a&&b&&a.active&&b.active&&!blocked(a,b)&&a.following.includes(b.id)&&b.following.includes(a.id);
const readable=(p,u,us=accounts())=>p.author===u.id||permission(u,'content')||friends(u,us.find(x=>x.id===p.author));
const publicUser=x=>({id:x.id,name:x.name,photo:x.photo||'',bio:x.bio||'',following:[],active:true,email:'',role:'user'});
function view(db,u){
const us=accounts(),visible=new Set([u.id,...u.following,...db.messages.filter(m=>m.from===u.id||m.to===u.id).flatMap(m=>[m.from,m.to])]);
return {...db,posts:db.posts.filter(p=>readable(p,u,us)),users:us.filter(x=>x.id===u.id||permission(u,'users')||permission(u,'content')||visible.has(x.id)&&!blocked(u,x)).map(x=>x.id===u.id||permission(u,'users')?x:{...publicUser(x),following:x.following.includes(u.id)?[u.id]:[],typing:x.typing?.to===u.id&&x.typing.until>Date.now()}),
messages:db.messages.filter(m=>m.from===u.id||m.to===u.id),notifications:db.notifications.filter(n=>n.to===u.id),reports:permission(u,'reports')?db.reports:[],rooms:db.rooms.map(r=>r.members.includes(u.id)?r:{id:r.id,name:r.name,members:r.members,host:r.host,chat:[],video:''})}
}
function attachedMedia(id,u,kind){if(!id)return null;const m=sql.prepare('SELECT id,owner,kind,duration FROM media WHERE id=?').get(id);if(!m||m.owner!==u.id||m.kind!==kind)fail(400,'ملف صوتي غير صالح');return {id:m.id,duration:m.duration}}
function wav(bytes,max){if(bytes.length<44||bytes.toString('ascii',0,4)!=='RIFF'||bytes.toString('ascii',8,12)!=='WAVE'||bytes.toString('ascii',12,16)!=='fmt '||bytes.readUInt32LE(16)!==16||bytes.readUInt16LE(20)!==1||bytes.readUInt16LE(22)!==1||bytes.readUInt16LE(34)!==16||bytes.toString('ascii',36,40)!=='data')fail(400,'الصوت يجب أن يكون WAV PCM أحادي القناة');
const sr=bytes.readUInt32LE(24),size=bytes.readUInt32LE(40);if(sr<8000||sr>48000||bytes.readUInt16LE(32)!==2||bytes.readUInt32LE(28)!==sr*2||size!==bytes.length-44||size%2||bytes.readUInt32LE(4)!==bytes.length-8)fail(400,'بنية الصوت غير صالحة');
const duration=size/(sr*2);if(duration<=0||duration>max+0.1)fail(400,'مدة الصوت تتجاوز الحد');return duration}
function action(db,u,a){const id=u.id,find=(xs,k)=>xs.find(x=>x.id===k)||fail(404,'غير موجود'),own=(owner,p)=>{if(owner!==id&&!permission(u,p))fail(403,'ليست لديك صلاحية')};
const postAccess=p=>{if(!readable(p,u))fail(403,'منشورات الأصدقاء فقط')};
const image=v=>{if(!v)return '';if(typeof v!=='string'||v.length>2000000||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(v))fail(400,'صورة غير صالحة');return v};
switch(a.type){
case 'post':{const content=typeof a.text==='string'?a.text.trim():'';if(content.length>5000||!content&&!a.image||a.music&&!a.image)fail(400,'منشور غير صالح');db.posts.unshift({id:randomUUID(),author:id,text:content,image:image(a.image),music:a.music?{...attachedMedia(a.music,u,'music'),name:text(a.musicName||'موسيقى',80)}:null,likes:[],comments:[],time:Date.now()});break}
case 'like':{const p=find(db.posts,a.id);postAccess(p);p.likes=p.likes.includes(id)?p.likes.filter(x=>x!==id):[...p.likes,id];break}
case 'comment':{const p=find(db.posts,a.id);postAccess(p);p.comments.push({author:id,text:text(a.text,1000)});break}
case 'deleteComment':{const p=find(db.posts,a.id),c=p.comments[a.index];postAccess(p);if(!c)fail(404,'غير موجود');own(c.author,'content');p.comments.splice(a.index,1);break}
case 'deletePost':{own(find(db.posts,a.id).author,'content');db.posts=db.posts.filter(p=>p.id!==a.id);break}
case 'profile':u.name=text(a.name,60);u.bio=String(a.bio||'').slice(0,250);if(a.photo)u.photo=image(a.photo);if(a.cover)u.cover=image(a.cover);storeUser(u);break;
case 'follow':{if(!accounts().some(x=>x.id===a.id&&x.active&&!blocked(u,x))||a.id===id)fail(400,'حساب غير صالح');u.following=u.following.includes(a.id)?u.following.filter(x=>x!==a.id):[...u.following,a.id];storeUser(u);break}
case 'block':{const target=find(accounts(),a.id);if(target.id===id)fail(400,'غير صالح');u.blocked=u.blocked||[];if(u.blocked.includes(a.id))u.blocked=u.blocked.filter(x=>x!==a.id);else {u.blocked.push(a.id);u.following=u.following.filter(x=>x!==a.id);target.following=target.following.filter(x=>x!==id);storeUser(target)}storeUser(u);break}
case 'ackMessages':db.messages.filter(m=>m.to===id&&!m.deliveredAt).forEach(m=>m.deliveredAt=Date.now());break;
case 'readMessages':db.messages.filter(m=>m.to===id&&m.from===a.from).forEach(m=>m.readAt=m.readAt||Date.now());break;
case 'typing':{const target=find(accounts(),a.to);if(!friends(u,target))fail(403,'الأصدقاء فقط');u.typing={to:a.to,until:Date.now()+7000};storeUser(u);break}
case 'message':{if(!friends(u,accounts().find(x=>x.id===a.to)))fail(403,'الرسائل للأصدقاء فقط');db.messages.push({id:randomUUID(),from:id,to:a.to,text:a.audio?'':text(a.text,2000),audio:a.audio?attachedMedia(a.audio,u,'voice'):null,time:Date.now(),readAt:null});db.notifications.push({id:randomUUID(),to:a.to,text:'رسالة جديدة من '+u.name,read:false});break}
case 'readNotifications':db.notifications.filter(n=>n.to===id).forEach(n=>n.read=true);break;
case 'group':db.groups.push({id:randomUUID(),name:text(a.name,70),desc:text(a.desc,180),icon:'✦',members:[id]});break;
case 'joinGroup':{const g=find(db.groups,a.id);g.members=g.members.includes(id)?g.members.filter(x=>x!==id):[...g.members,id];break}
case 'deleteGroup':if(u.role!=='super')fail(403,'غير مسموح');db.groups=db.groups.filter(g=>g.id!==a.id);break;
case 'report':postAccess(find(db.posts,a.id));db.reports.push({id:randomUUID(),post:a.id,by:id,reason:text(a.reason,200),status:'pending'});break;
case 'resolveReport':{if(!permission(u,'reports'))fail(403,'غير مسموح');const r=find(db.reports,a.id);if(a.remove){if(!permission(u,'content'))fail(403,'غير مسموح');db.posts=db.posts.filter(p=>p.id!==r.post)}r.status='resolved';break}
case 'toggleUser':{const target=find(accounts(),a.id);if(!permission(u,'users')||id===target.id||u.role!=='super'&&target.role!=='user')fail(403,'غير مسموح');target.active=!target.active;storeUser(target);sql.prepare('DELETE FROM sessions WHERE uid=?').run(target.id);break}
case 'user':{if(u.role!=='super')fail(403,'غير مسموح');const target=find(accounts(),a.id);if(target.role==='super'||!['user','admin'].includes(a.role))fail(403,'غير مسموح');target.name=text(a.name,60);target.role=a.role;target.permissions=(a.permissions||[]).filter(p=>['users','content','reports'].includes(p));storeUser(target);break}
case 'registration':if(u.role!=='super')fail(403,'غير مسموح');db.settings.registration=!!a.value;break;
case 'room':{const r={id:randomUUID(),host:id,name:text(a.name,60),members:[id],chat:[],video:''};db.rooms.push(r);return r.id}
case 'enterRoom':{const r=find(db.rooms,a.id);if(!r.members.includes(id)){if(r.members.length>=5)fail(409,'الغرفة مكتملة');r.members.push(id)}break}
case 'leaveRoom':{const r=find(db.rooms,a.id);r.members=r.members.filter(x=>x!==id);if(!r.members.length)db.rooms=db.rooms.filter(x=>x.id!==r.id);else if(r.host===id)r.host=r.members[0];break}
case 'video':{const r=find(db.rooms,a.id);if(r.host!==id)fail(403,'المضيف فقط');if(!/^[\w-]{11}$/.test(a.video))fail(400,'فيديو غير صالح');r.video=a.video;break}
case 'roomMessage':{const r=find(db.rooms,a.id);if(!r.members.includes(id))fail(403,'انضم أولًا');r.chat.push({by:id,text:text(a.text,1000)});break}
default:fail(400,'عملية غير مدعومة')}
}
const headers={'X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Cache-Control':'no-store','X-Frame-Options':'SAMEORIGIN','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src https://www.youtube-nocookie.com; connect-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'"};
http.createServer(async(req,res)=>{const reply=(s,data,h={})=>{res.writeHead(s,{...headers,'Content-Type':'application/json; charset=utf-8',...h});res.end(JSON.stringify(data))};try{
const path=new URL(req.url,'http://localhost').pathname;
if(!path.startsWith('/api/')){if(path!=='/'&&path!=='/index.html')return reply(404,{error:'غير موجود'});res.writeHead(200,{...headers,'Content-Type':'text/html; charset=utf-8'});return res.end(readFileSync('index.html'))}
let body={};if(req.method==='POST'){const origin=process.env.PUBLIC_ORIGIN||'http://localhost:'+port;if(req.headers.origin!==origin)fail(403,'مصدر الطلب غير مسموح');if(!req.headers['content-type']?.startsWith('application/json'))fail(415,'JSON مطلوب');let raw='';for await(const part of req){raw+=part;if(Buffer.byteLength(raw)>17000000)fail(413,'الطلب كبير')}try{body=JSON.parse(raw)}catch{fail(400,'JSON غير صالح')}}
const state=()=>JSON.parse(sql.prepare('SELECT json FROM state WHERE id=1').get().json);
if(req.method==='POST'&&['/api/login','/api/register'].includes(path)){
rate('auth:'+req.socket.remoteAddress,20);const email=text(body.email,254).toLowerCase(),password=text(body.password,256);if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))fail(400,'بريد غير صالح');let account;
if(path==='/api/register'){if(!state().settings.registration)fail(403,'التسجيل مغلق');if(password.length<12)fail(400,'كلمة المرور 12 حرفًا على الأقل');const salt=randomBytes(16).toString('hex'),id=randomUUID(),u={id,email,name:text(body.name,60),role:'user',following:[],active:true,bio:''};try{sql.prepare('INSERT INTO accounts VALUES(?,?,?,?,?)').run(id,email,scryptSync(password,salt,64).toString('hex'),salt,JSON.stringify(u))}catch{fail(409,'تعذر إنشاء الحساب بهذا البريد')}account=sql.prepare('SELECT * FROM accounts WHERE id=?').get(id)
}else{account=sql.prepare('SELECT * FROM accounts WHERE email=?').get(email);const derived=scryptSync(password,account?.salt||'dummy-salt',64);if(!account||!timingSafeEqual(derived,Buffer.from(account.hash,'hex'))||!profile(account).active)fail(401,'بيانات الدخول غير صحيحة')}
const token=randomBytes(32).toString('hex'),csrf=randomBytes(32).toString('hex');sql.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(hash(token),account.id,csrf,Date.now()+86400000);return reply(200,{user:profile(account),csrf},{'Set-Cookie':'sid='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400'+(prod?'; Secure':'')})}
const token=req.headers.cookie?.match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/)?.[1],session=token&&sql.prepare('SELECT * FROM sessions WHERE token=? AND expires>?').get(hash(token),Date.now());if(!session)fail(401,'سجّل الدخول');const row=sql.prepare('SELECT * FROM accounts WHERE id=?').get(session.uid),u=row&&profile(row);if(!u?.active)fail(401,'الحساب غير متاح');
if(req.method==='GET'&&path==='/api/search'){const q=new URL(req.url,'http://localhost').searchParams.get('q')?.trim().toLocaleLowerCase()||'';if(q.length<2||q.length>60)fail(400,'اكتب حرفين على الأقل');return reply(200,{users:accounts().filter(x=>x.active&&x.id!==u.id&&!blocked(u,x)&&x.name.toLocaleLowerCase().includes(q)).slice(0,20).map(publicUser)})}
if(req.method==='GET'&&path.startsWith('/api/media/')){
const id=path.slice('/api/media/'.length),m=sql.prepare('SELECT * FROM media WHERE id=?').get(id);if(!m)fail(404,'غير موجود');const db=state();
const allowed=db.posts.some(p=>p.music?.id===id&&readable(p,u))||db.messages.some(x=>x.audio?.id===id&&(x.from===u.id||x.to===u.id));
if(!allowed)fail(403,'غير مسموح');res.writeHead(200,{...headers,'Content-Type':'audio/wav','Content-Length':m.bytes.length});return res.end(Buffer.from(m.bytes))}
if(req.method==='GET'&&path==='/api/state')return reply(200,{db:view(state(),u),current:u.id,csrf:session.csrf});
if(req.method!=='POST')fail(405,'غير مسموح');if(req.headers['x-csrf-token']!==session.csrf)fail(403,'رمز الحماية غير صالح');rate('user:'+u.id,200);
if(path==='/api/upload'){rate('upload:'+u.id,25);if(!['voice','music'].includes(body.kind)||typeof body.data!=='string'||!/^[A-Za-z0-9+/=]+$/.test(body.data))fail(400,'ملف غير صالح');const bytes=Buffer.from(body.data,'base64');if(bytes.length>12000000)fail(413,'الصوت كبير');const duration=wav(bytes,body.kind==='voice'?120:30),id=randomUUID();sql.prepare('INSERT INTO media VALUES(?,?,?,?,?,?)').run(id,u.id,body.kind,'audio/wav',bytes,duration);return reply(200,{id,duration})}
if(path==='/api/logout'){sql.prepare('DELETE FROM sessions WHERE token=?').run(hash(token));return reply(200,{}, {'Set-Cookie':'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'+(prod?'; Secure':'')})}
if(path!=='/api/action')fail(404,'غير موجود');sql.exec('BEGIN IMMEDIATE');try{const db=state(),result=action(db,u,body);sql.prepare('UPDATE state SET json=? WHERE id=1').run(JSON.stringify(db));sql.prepare('INSERT INTO audit(actor,action,time) VALUES(?,?,?)').run(u.id,body.type,Date.now());sql.exec('COMMIT');return reply(200,{db:view(db,u),current:u.id,result})}catch(e){sql.exec('ROLLBACK');throw e}
}catch(e){reply(e.status||500,{error:e.status?e.message:'حدث خطأ في الخادم'})}}).listen(port,'127.0.0.1',()=>console.log('TAWASOL listening on http://localhost:'+port));
