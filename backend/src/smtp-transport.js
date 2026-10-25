import net from 'node:net';
import tls from 'node:tls';
import {randomUUID} from 'node:crypto';

// Dependency-free SMTP sender (implicit TLS on 465, or STARTTLS on 587) so a
// self-hosted instance can send verification mail without Tencent SES.
const CRLF='\r\n',TIMEOUT=15000;
const titles={register:'注册邮箱验证',bind:'邮箱绑定验证',reset:'找回密码验证',password_changed:'密码变更通知',email_changed:'邮箱变更通知'};
const b64=s=>Buffer.from(s,'utf8').toString('base64');
const wrap=s=>s.replace(/.{1,76}/g,'$&'+CRLF);

export function smtpConfig(env=process.env) {
 const host=env.SMTP_HOST,port=Number(env.SMTP_PORT||465),user=env.SMTP_USER,pass=env.SMTP_PASS;
 if(!host||!/^[A-Za-z0-9.-]+$/.test(host)||!Number.isInteger(port)||port<1||port>65535||!user||!pass||/[\r\n]/.test(user+pass))return null;
 const secure=env.SMTP_SECURE?env.SMTP_SECURE!=='false':port===465;
 return {host,port,secure,user,pass,from:env.SMTP_FROM||user};
}

export function mailContent(mail,beta=false) {
 const subject=(beta?'[Beta 测试] ':'')+'DDL Killer · '+titles[mail.purpose];
 const text=mail.code
  ?'你的 DDL Killer '+titles[mail.purpose]+'验证码是：'+mail.code+'\n\n验证码 10 分钟内有效。如果这不是你本人的操作，请忽略这封邮件，不要把验证码告诉任何人。'
  :mail.purpose==='password_changed'?'你的 DDL Killer 账号密码刚刚被修改。如果这不是你本人的操作，请尽快联系开发者。'
  :'你的 DDL Killer 账号绑定的邮箱刚刚被更换。如果这不是你本人的操作，请尽快联系开发者。';
 return {subject,text};
}

function build(cfg,mail,id) {
 return ['From: DDL Killer <'+cfg.from+'>','To: <'+mail.to+'>','Subject: =?UTF-8?B?'+b64(mail.subject)+'?=','Date: '+new Date().toUTCString(),'Message-ID: '+id,
  'MIME-Version: 1.0','Content-Type: text/plain; charset=utf-8','Content-Transfer-Encoding: base64','',wrap(b64(mail.text))].join(CRLF);
}

// Error names reuse the vocabulary that email-service's safeError() whitelists.
function fail(res) {
 return new Error(res.code===535||res.code===534?'AuthFailure':res.code>=400&&res.code<500?'ServiceUnavailable':'FailedOperation');
}

function listen(socket) {
 let buf='',lines=[],failure=null;const ready=[],waiting=[];
 const pump=()=>{while(waiting.length&&(ready.length||failure)){const w=waiting.shift();if(ready.length)w.resolve(ready.shift());else w.reject(failure);}};
 socket.on('data',d=>{buf+=d.toString('utf8');let i;
  while((i=buf.indexOf(CRLF))>=0){const line=buf.slice(0,i);buf=buf.slice(i+2);lines.push(line);
   if(/^\d{3}( |$)/.test(line)){ready.push({code:Number(line.slice(0,3)),text:lines.join('\n')});lines=[];}}
  pump();});
 socket.on('error',e=>{failure=failure||e;pump();});
 socket.on('close',()=>{failure=failure||Object.assign(new Error('closed'),{code:'ECONNRESET'});pump();});
 return ()=>new Promise((resolve,reject)=>{waiting.push({resolve,reject});pump();});
}

function open(cfg,existing) {
 return new Promise((resolve,reject)=>{
  const s=existing?tls.connect({socket:existing,servername:cfg.host}):cfg.secure?tls.connect({host:cfg.host,port:cfg.port,servername:cfg.host}):net.connect({host:cfg.host,port:cfg.port});
  s.once(existing||cfg.secure?'secureConnect':'connect',()=>resolve(s));s.once('error',reject);
  s.setTimeout(TIMEOUT,()=>{const e=new Error('timeout');e.name='TimeoutError';s.destroy(e);});
 });
}

export async function sendSmtp(cfg,mail) {
 let socket=await open(cfg),next=listen(socket);
 const id='<'+randomUUID()+'@'+cfg.from.split('@').pop()+'>';
 const expect=(res,codes)=>{if(!codes.includes(res.code))throw fail(res);return res;};
 const cmd=async(line,codes)=>{socket.write(line+CRLF);return expect(await next(),codes);};
 try {
  expect(await next(),[220]);
  const hello=await cmd('EHLO ddl-killer.local',[250]);
  if(!cfg.secure) {
   if(!/STARTTLS/i.test(hello.text))throw new Error('FailedOperation.TlsRequired');
   await cmd('STARTTLS',[220]);socket.removeAllListeners('data');
   socket=await open(cfg,socket);next=listen(socket);
   await cmd('EHLO ddl-killer.local',[250]);
  }
  await cmd('AUTH LOGIN',[334]);await cmd(b64(cfg.user),[334]);await cmd(b64(cfg.pass),[235]);
  await cmd('MAIL FROM:<'+cfg.from+'>',[250]);await cmd('RCPT TO:<'+mail.to+'>',[250,251]);await cmd('DATA',[354]);
  socket.write(build(cfg,mail,id)+'.'+CRLF);expect(await next(),[250]);
  try{socket.write('QUIT'+CRLF);}catch{}
  return id;
 } finally {socket.destroy();}
}
