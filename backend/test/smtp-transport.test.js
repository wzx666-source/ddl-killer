import test from 'node:test';import assert from 'node:assert/strict';
import net from 'node:net';
const {smtpConfig,mailContent,sendSmtp}=await import('../src/smtp-transport.js');

test('smtpConfig needs host, user and password, and picks the TLS mode from the port',()=>{
 assert.equal(smtpConfig({}),null);
 assert.equal(smtpConfig({SMTP_HOST:'smtp.example.com',SMTP_USER:'a@example.com'}),null);
 const c=smtpConfig({SMTP_HOST:'smtp.example.com',SMTP_USER:'a@example.com',SMTP_PASS:'x'});
 assert.equal(c.port,465);assert.equal(c.secure,true);assert.equal(c.from,'a@example.com');
 assert.equal(smtpConfig({SMTP_HOST:'smtp.example.com',SMTP_PORT:'587',SMTP_USER:'a@example.com',SMTP_PASS:'x'}).secure,false);
 assert.equal(smtpConfig({SMTP_HOST:'bad host',SMTP_USER:'u',SMTP_PASS:'x'}),null);
 assert.equal(smtpConfig({SMTP_HOST:'h.example.com',SMTP_USER:'u\r\nRCPT',SMTP_PASS:'x'}),null);
});

test('mailContent carries the code for verification mail and none for notices',()=>{
 const a=mailContent({purpose:'register',code:'123456'});
 assert.match(a.subject,/注册邮箱验证/);assert.ok(a.text.includes('123456'));
 assert.ok(mailContent({purpose:'bind',code:'123456'},true).subject.startsWith('[Beta 测试]'));
 assert.ok(!mailContent({purpose:'password_changed'}).text.includes('验证码'));
});

test('never sends credentials in clear text when the server lacks STARTTLS',async()=>{
 const seen=[];
 const server=net.createServer(s=>{s.write('220 fake\r\n');s.on('data',d=>{const t=d.toString();seen.push(t);s.write(/^EHLO/.test(t)?'250 fake\r\n':'500 no\r\n');});});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  await assert.rejects(sendSmtp({host:'127.0.0.1',port:server.address().port,secure:false,user:'u',pass:'p',from:'u@example.com'},{to:'t@example.com',subject:'s',text:'x'}),/FailedOperation/);
  assert.ok(!seen.join('').includes('AUTH'));
 }finally{server.close();}
});
