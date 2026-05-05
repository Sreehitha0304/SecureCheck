/**
 * network.js — ThreatShield AI v3
 * Real DNS · TLS · HTTP · IP Reputation · Real-time monitor sessions
 * Every analysis generates AI insights and is saved to MongoDB
 */

const router = require('express').Router();
const https  = require('https');
const http   = require('http');
const dns    = require('dns').promises;
const tls    = require('tls');
const axios  = require('axios');
const auth   = require('../middleware/auth');
const Scan   = require('../models/Scan');
const User   = require('../models/User');

/* Active monitor sessions */
const sessions = new Map();

/* ══════════════════════════════════════════════════
   DNS ANALYSIS
   ══════════════════════════════════════════════════ */
function parseUrl(raw) {
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  return new URL(raw);
}

async function dnsAnalysis(hostname) {
  const results = [];
  for (const type of ['A','AAAA','MX','TXT','NS','CNAME']) {
    try {
      let data;
      if (type==='A')     data = await dns.resolve4(hostname);
      if (type==='AAAA')  data = await dns.resolve6(hostname).catch(()=>[]);
      if (type==='MX')    data = (await dns.resolveMx(hostname).catch(()=>[])).map(m=>m.exchange);
      if (type==='TXT')   data = (await dns.resolveTxt(hostname).catch(()=>[])).map(r=>r.join(' '));
      if (type==='NS')    data = await dns.resolveNs(hostname).catch(()=>[]);
      if (type==='CNAME') data = await dns.resolveCname(hostname).catch(()=>[]);
      if (data && data.length>0) results.push({ type:'DNS_'+type, data, status:'ok' });
    } catch{}
  }
  if (!results.find(r=>r.type==='DNS_A')) results.push({ type:'DNS_A', data:[], status:'failed' });
  return results;
}

/* ══════════════════════════════════════════════════
   TLS ANALYSIS
   ══════════════════════════════════════════════════ */
async function tlsAnalysis(hostname, port=443) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const sock = tls.connect({ host:hostname, port, servername:hostname, rejectUnauthorized:false, timeout:8000 }, () => {
      try {
        const cert  = sock.getPeerCertificate(true);
        const proto = sock.getProtocol();
        if (!cert||!cert.subject) { sock.destroy(); return resolve({ status:'no_cert', tlsVersion:proto }); }
        const validTo   = new Date(cert.valid_to);
        const now       = new Date();
        const daysLeft  = Math.floor((validTo-now)/86400000);
        const selfSigned= cert.issuer?.O===cert.subject?.O && cert.issuer?.CN===cert.subject?.CN;
        sock.destroy();
        resolve({
          status:      daysLeft<0?'expired':'valid',
          tlsVersion:  proto,
          cipher:      sock.getCipher?.()?.name||'—',
          issuer:      cert.issuer?.O||cert.issuer?.CN||'Unknown',
          validTo:     cert.valid_to,
          validFrom:   cert.valid_from,
          daysLeft,
          expired:     daysLeft<0,
          expiringSoon:daysLeft>=0&&daysLeft<30,
          selfSigned,
          subject:     cert.subject?.CN||hostname,
          subjectAltNames: cert.subjectaltname||null,
          timeMs:      Date.now()-t0
        });
      } catch(e) { sock.destroy(); resolve({ status:'error', error:e.message }); }
    });
    sock.on('error', e=>resolve({ status:'error', error:e.message }));
    sock.setTimeout(8000, ()=>{ sock.destroy(); resolve({ status:'timeout' }); });
  });
}

/* ══════════════════════════════════════════════════
   HTTP ANALYSIS
   ══════════════════════════════════════════════════ */
async function httpAnalysis(rawUrl) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let redirectChain=[], redirectCount=0;

    function follow(url, depth) {
      if (depth>10) return resolve({ error:'Too many redirects', redirectCount, redirectChain });
      let parsed;
      try { parsed = new URL(url); } catch { return resolve({ error:'Invalid URL', redirectCount, redirectChain }); }
      const mod   = parsed.protocol==='https:'?https:http;
      const hopT0 = Date.now();
      const req = mod.request({
        hostname:parsed.hostname, port:parsed.port||(parsed.protocol==='https:'?443:80),
        path:parsed.pathname+parsed.search, method:'GET', timeout:10000,
        headers:{ 'User-Agent':'Mozilla/5.0 (compatible; ThreatShield-Analyzer/3.0)', 'Accept':'text/html,*/*', 'Accept-Language':'en-US,en;q=0.9' }
      }, res => {
        const hopMs = Date.now()-hopT0;
        redirectChain.push({ url, status:res.statusCode, timeMs:hopMs });
        if ([301,302,303,307,308].includes(res.statusCode)&&res.headers.location) {
          res.resume(); redirectCount++;
          const next = res.headers.location.startsWith('http')?res.headers.location:new URL(res.headers.location,url).href;
          return follow(next, depth+1);
        }
        const hdr = res.headers;
        const SEC_HDRS = ['strict-transport-security','x-frame-options','x-content-type-options','content-security-policy','x-xss-protection','referrer-policy','permissions-policy'];
        const missingSecHeaders = SEC_HDRS.filter(h=>!hdr[h]);
        const cookies = hdr['set-cookie']||[];
        const trackingCookies = cookies.filter(c=>/(_ga|_gid|fbp|_fbp|_gcl|tracker|_utm)/i.test(c)).length;
        // Read a snippet of body for content analysis
        let bodyChunk = '';
        res.on('data', chunk => { if (bodyChunk.length < 3000) bodyChunk += chunk.toString('utf8','0','3000'); });
        res.on('end', () => {
          const isLoginPage = /(<input[^>]+type=['"]?password['"]?|login|sign.?in|credential)/i.test(bodyChunk);
          const hasIframe   = /<iframe/i.test(bodyChunk);
          const hasObfJS    = /eval\s*\(|atob\s*\(|fromCharCode|unescape\s*\(/i.test(bodyChunk);
          resolve({
            status: res.statusCode, timeMs: Date.now()-t0,
            server: hdr['server']||null, poweredBy: hdr['x-powered-by']||null,
            contentType: hdr['content-type']||null, redirectCount, redirectChain,
            missingSecHeaders, trackingCookies,
            hasHSTS:!!hdr['strict-transport-security'], hasXFrame:!!hdr['x-frame-options'],
            hasCSP:!!hdr['content-security-policy'], hasXContentType:!!hdr['x-content-type-options'],
            isLoginPage, hasIframe, hasObfuscatedJS: hasObfJS,
            allHeaders: Object.fromEntries(Object.entries(hdr).slice(0,20))
          });
        });
      });
      req.on('error', e=>{ redirectChain.push({url,status:'ERR',error:e.message,timeMs:Date.now()-hopT0}); resolve({error:e.message,redirectCount,redirectChain}); });
      req.on('timeout', ()=>{ req.destroy(); resolve({error:'Request timed out',redirectCount,redirectChain}); });
      req.end();
    }
    follow(rawUrl, 0);
  });
}

/* ══════════════════════════════════════════════════
   IP REPUTATION (same logic as scan.js)
   ══════════════════════════════════════════════════ */
async function lookupIPReputation(ip) {
  const result = { ip, geo:null, asn:null, abuseScore:0, isTor:false, isProxy:false, reports:0, country:null, org:null, isp:null, verdict:'unknown' };
  try {
    const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting`, { timeout:6000 });
    if (r.data?.status==='success') {
      result.country    = `${r.data.city||''}, ${r.data.regionName||''}, ${r.data.country||''}`.replace(/^,\s*/,'').replace(/,\s*,/,',');
      result.countryCode= r.data.countryCode;
      result.isp        = r.data.isp;
      result.org        = r.data.org;
      result.asn        = r.data.as;
      result.isProxy    = r.data.proxy||false;
      result.isHosting  = r.data.hosting||false;
    }
  } catch{}
  const orgL = (result.org||'').toLowerCase();
  const ispL = (result.isp||'').toLowerCase();
  const SUSP = ['tor','vpn','proxy','bulletproof','hosting','datacenter','vps','cloud','linode','digitalocean','vultr','hetzner','ovh','choopa','frantech'];
  if (SUSP.some(s=>orgL.includes(s)||ispL.includes(s))) { result.abuseScore+=20; result.isHosting=true; }
  if (result.isProxy) result.abuseScore+=35;
  result.verdict = result.abuseScore>=50?'malicious':result.abuseScore>=20?'suspicious':'clean';
  return result;
}

/* ══════════════════════════════════════════════════
   THREAT SCORING + AI INSIGHTS
   ══════════════════════════════════════════════════ */
function computeThreatScore(dnsResult, tlsResult, httpResult, hostname, ipRep) {
  const flags = [];
  let score = 0;

  /* TLS */
  if (!tlsResult||tlsResult.status==='error'||tlsResult.status==='timeout') {
    flags.push({sev:'warn',msg:'TLS check failed or timed out',cat:'TLS'}); score+=10;
  } else if (tlsResult.expired) {
    flags.push({sev:'danger',msg:`TLS certificate EXPIRED on ${tlsResult.validTo}`,cat:'TLS'}); score+=30;
  } else if (tlsResult.selfSigned) {
    flags.push({sev:'danger',msg:'Self-signed certificate — not trusted by browsers',cat:'TLS'}); score+=25;
  } else if (tlsResult.expiringSoon) {
    flags.push({sev:'warn',msg:`Certificate expires in ${tlsResult.daysLeft} days`,cat:'TLS'}); score+=8;
  } else {
    flags.push({sev:'ok',msg:`Valid TLS (${tlsResult.issuer}) · ${tlsResult.daysLeft}d remaining`,cat:'TLS'});
  }

  /* HTTP */
  if (httpResult&&!httpResult.error) {
    if (httpResult.status>=400) { flags.push({sev:'danger',msg:`HTTP ${httpResult.status} error`,cat:'HTTP'}); score+=15; }
    if (httpResult.redirectCount>3) { flags.push({sev:'danger',msg:`Excessive redirects (${httpResult.redirectCount}) — phishing chain`,cat:'HTTP'}); score+=20; }
    else if (httpResult.redirectCount>1) { flags.push({sev:'warn',msg:`${httpResult.redirectCount} redirect(s) detected`,cat:'HTTP'}); score+=5; }
    if ((httpResult.missingSecHeaders||[]).length>=4) { flags.push({sev:'warn',msg:`${httpResult.missingSecHeaders.length} security headers missing`,cat:'Headers'}); score+=10; }
    if (!httpResult.hasHSTS) { flags.push({sev:'warn',msg:'HSTS missing — susceptible to downgrade attacks',cat:'Headers'}); score+=5; }
    if (!httpResult.hasCSP) { flags.push({sev:'warn',msg:'Content-Security-Policy missing',cat:'Headers'}); score+=3; }
    if (httpResult.trackingCookies>0) flags.push({sev:'info',msg:`${httpResult.trackingCookies} tracking cookie(s)`,cat:'Cookies'});
    if (httpResult.poweredBy) flags.push({sev:'info',msg:`Server technology exposed: ${httpResult.poweredBy}`,cat:'Info'});
    if (httpResult.isLoginPage) { flags.push({sev:'warn',msg:'Login/credential form detected on this page',cat:'Content'}); score+=10; }
    if (httpResult.hasObfuscatedJS) { flags.push({sev:'danger',msg:'Obfuscated JavaScript detected (eval/atob/fromCharCode)',cat:'Content'}); score+=20; }
    if (httpResult.hasIframe) flags.push({sev:'info',msg:'Iframe element found on page',cat:'Content'});
  } else if (httpResult?.error) {
    flags.push({sev:'danger',msg:`HTTP request failed: ${httpResult.error}`,cat:'HTTP'}); score+=20;
  }

  /* DNS */
  const aRec = dnsResult?.find(d=>d.type==='DNS_A');
  if (!aRec||aRec.status==='failed') { flags.push({sev:'danger',msg:'DNS resolution failed — domain may not exist',cat:'DNS'}); score+=30; }
  else { flags.push({sev:'ok',msg:`DNS resolves to: ${aRec.data.slice(0,3).join(', ')}`,cat:'DNS'}); }

  /* Suspicious TLD */
  const domParts = hostname.split('.');
  const tld = '.'+domParts[domParts.length-1];
  const suspTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.work','.date','.loan','.win'];
  if (suspTlds.includes(tld)) { flags.push({sev:'danger',msg:`Suspicious TLD: ${tld}`,cat:'Domain'}); score+=20; }

  /* IP as hostname */
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) { flags.push({sev:'danger',msg:'URL uses raw IP address instead of domain',cat:'Domain'}); score+=25; }

  /* IP reputation */
  if (ipRep) {
    if (ipRep.isProxy) { flags.push({sev:'danger',msg:`IP ${ipRep.ip} is a known proxy/VPN`,cat:'IP Reputation'}); score+=20; }
    else if (ipRep.isHosting) { flags.push({sev:'warn',msg:`IP ${ipRep.ip} hosted on ${ipRep.isp||'hosting provider'}`,cat:'IP Reputation'}); score+=8; }
    if (ipRep.abuseScore>=50) { flags.push({sev:'danger',msg:`IP abuse score: ${ipRep.abuseScore}/100`,cat:'IP Reputation'}); score+=15; }
    else if (ipRep.abuseScore>=20) { flags.push({sev:'warn',msg:`IP moderate abuse score: ${ipRep.abuseScore}/100`,cat:'IP Reputation'}); score+=8; }
    if (ipRep.country) flags.push({sev:'info',msg:`Server location: ${ipRep.country}`,cat:'IP Reputation'});
    if (ipRep.asn) flags.push({sev:'info',msg:`ASN: ${ipRep.asn}`,cat:'IP Reputation'});
  }

  score = Math.min(score, 100);

  const verdict = score>=50?'FAKE / MALICIOUS WEBSITE':score>=25?'SUSPICIOUS — EXERCISE CAUTION':'APPEARS LEGITIMATE';

  // AI insight
  const insight = generateNetworkInsight(score, verdict, flags, hostname, tlsResult, httpResult, ipRep);

  return { score, verdict, flags, insight };
}

function generateNetworkInsight(score, verdict, flags, hostname, tls, http, ipRep) {
  const parts = [];

  if (score >= 50) {
    parts.push(`⛔ HIGH RISK: ${hostname} shows ${flags.filter(f=>f.sev==='danger').length} critical security issues.`);
    if (tls?.expired) parts.push('The SSL certificate has expired — browsers will show a security warning. Legitimate sites keep their certificates current.');
    if (tls?.selfSigned) parts.push('Self-signed certificate detected — this site is not verified by a trusted authority, a hallmark of phishing and fake sites.');
    if (http?.hasObfuscatedJS) parts.push('Obfuscated JavaScript found — attackers use this to hide malicious code that runs in your browser.');
    if (http?.isLoginPage) parts.push('A login form is present on this suspicious page — entering credentials here would compromise your account.');
    if (ipRep?.isProxy) parts.push(`The server IP (${ipRep.ip}) is associated with a proxy/VPN service — often used to hide malicious infrastructure.`);
    parts.push('⛔ Recommended: Do NOT visit this site. Do NOT enter any personal information.');
  } else if (score >= 25) {
    parts.push(`⚠ CAUTION: ${hostname} has ${flags.filter(f=>f.sev==='warn').length} warning(s) that require attention.`);
    if (tls?.expiringSoon) parts.push(`Certificate expires in ${tls.daysLeft} days — contact the site administrator.`);
    if ((http?.missingSecHeaders||[]).length >= 4) parts.push('Several security headers are missing — the site may be vulnerable to clickjacking or XSS attacks.');
    if (http?.redirectCount > 1) parts.push(`${http.redirectCount} redirects detected — verify you end up at the expected domain.`);
    parts.push('⚠ Recommended: Proceed with caution. Verify the domain carefully before entering credentials.');
  } else {
    parts.push(`✅ ${hostname} appears legitimate based on network analysis.`);
    if (tls?.status==='valid') parts.push(`Valid TLS certificate from ${tls.issuer} — ${tls.daysLeft} days remaining.`);
    if (http?.status===200) parts.push('Site is reachable and returns HTTP 200 OK.');
    if (http?.hasHSTS) parts.push('HSTS enabled — browser will enforce HTTPS connections.');
    parts.push('No significant security issues detected in this scan.');
  }

  return parts.join(' ');
}

/* ══════════════════════════════════════════════════
   POST /api/network/analyze — full one-shot scan
   ══════════════════════════════════════════════════ */
router.post('/analyze', auth, async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required.' });
  let parsed;
  try { parsed = parseUrl(url); url = parsed.href; }
  catch { return res.status(400).json({ error: 'Invalid URL.' }); }

  const hostname = parsed.hostname;
  const t0 = Date.now();

  try {
    // Get IPs first for reputation lookup
    const addrs = await dns.resolve4(hostname).catch(()=>[]);
    const primaryIP = addrs[0] || null;

    const [dnsRes, tlsRes, httpRes, ipRep] = await Promise.all([
      dnsAnalysis(hostname),
      tlsAnalysis(hostname, 443),
      httpAnalysis(url),
      primaryIP ? lookupIPReputation(primaryIP) : Promise.resolve(null)
    ]);

    const { score, verdict, flags, insight } = computeThreatScore(dnsRes, tlsRes, httpRes, hostname, ipRep);
    const dbVerdict  = score>=50?'Malicious':score>=25?'Suspicious':'Benign';
    const confidence = parseFloat((score/100).toFixed(4));
    const pt         = Date.now()-t0;

    try {
      await Scan.create({
        userId: req.userId, scanType:'network', target:url, verdict:dbVerdict, confidence,
        domain: hostname, modelUsed:'network_analyzer_v3',
        details: { threatScore:score, flags, insight, tlsIssuer:tlsRes?.issuer, httpStatus:httpRes?.status, ipReputation:ipRep },
        processingTime: pt
      });
      User.findByIdAndUpdate(req.userId, { $inc:{ scanCount:1 } }).catch(()=>{});
      console.log(`✅ Network scan saved: ${dbVerdict} (${hostname})`);
    } catch(dbErr) {
      console.error(`❌ Network DB save: ${dbErr.message}`);
    }

    return res.json({ threatScore:score, verdict, flags, insight, dns:dnsRes, tls:tlsRes, http:httpRes, ipReputation:ipRep, hostname, url });

  } catch(e) {
    console.error('Network analyze error:', e);
    return res.status(500).json({ error: 'Analysis failed: '+e.message });
  }
});

/* ══════════════════════════════════════════════════
   POST /api/network/start — start live monitor
   ══════════════════════════════════════════════════ */
router.post('/start', auth, async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required.' });
  try { url = parseUrl(url).href; } catch { return res.status(400).json({ error: 'Invalid URL.' }); }

  const sessionId = Date.now().toString(36)+Math.random().toString(36).slice(2);
  const hostname  = new URL(url).hostname;
  const addrs     = await dns.resolve4(hostname).catch(()=>[]);
  const primaryIP = addrs[0]||null;

  const [dnsRes, tlsRes, httpRes, ipRep] = await Promise.all([
    dnsAnalysis(hostname), tlsAnalysis(hostname), httpAnalysis(url),
    primaryIP ? lookupIPReputation(primaryIP) : Promise.resolve(null)
  ]).catch(()=>[[],{status:'error'},{error:'failed'},null]);

  const { score, verdict, flags, insight } = computeThreatScore(dnsRes, tlsRes, httpRes, hostname, ipRep);

  sessions.set(sessionId, {
    url, hostname, primaryIP, pollCount:0,
    lastResult:{ type:'full', threatScore:score, verdict, flags, insight, dns:dnsRes, tls:tlsRes, http:httpRes, ipReputation:ipRep },
    createdAt: Date.now()
  });

  // Cleanup stale sessions
  for (const [id,s] of sessions.entries()) {
    if (Date.now()-s.createdAt > 3600000) sessions.delete(id);
  }

  return res.json({ sessionId, result:{ type:'full', threatScore:score, verdict, flags, insight, dns:dnsRes, tls:tlsRes, http:httpRes, ipReputation:ipRep } });
});

/* ══════════════════════════════════════════════════
   POST /api/network/poll/:id — live poll
   ══════════════════════════════════════════════════ */
router.post('/poll/:id', auth, async (req, res) => {
  const sess = sessions.get(req.params.id);
  if (!sess) return res.json({ result:{ type:'offline' } });

  try {
    sess.pollCount = (sess.pollCount||0)+1;
    const httpRes = await httpAnalysis(sess.url);

    // Every 4 polls, re-check TLS too
    let tlsUpdate = null;
    if (sess.pollCount % 4 === 0) {
      tlsUpdate = await tlsAnalysis(sess.hostname).catch(()=>null);
    }

    // Recompute threat score
    const { score, verdict, flags, insight } = computeThreatScore(
      sess.lastResult.dns||[], tlsUpdate||sess.lastResult.tls||{}, httpRes, sess.hostname, null
    );

    const result = {
      type:'poll', pollCount:sess.pollCount,
      threatScore:score, verdict, insight,
      status: httpRes.status, timeMs: httpRes.timeMs,
      server: httpRes.server, redirectCount: httpRes.redirectCount||0,
      redirectChain: httpRes.redirectChain||[], trackingCookies: httpRes.trackingCookies||0,
      hasObfuscatedJS: httpRes.hasObfuscatedJS||false,
      isLoginPage: httpRes.isLoginPage||false,
      newFlags: flags.filter(f=>f.sev==='danger'||f.sev==='warn'),
      error: httpRes.error||null,
      ...(tlsUpdate?{ tlsUpdate }:{})
    };
    sess.lastResult = { ...sess.lastResult, ...result };
    return res.json({ result });
  } catch(e) {
    return res.json({ result:{ type:'poll', error:e.message } });
  }
});

/* ══════════════════════════════════════════════════
   POST /api/network/stop/:id
   ══════════════════════════════════════════════════ */
router.post('/stop/:id', auth, (req, res) => {
  sessions.delete(req.params.id);
  return res.json({ ok:true });
});

/* ══════════════════════════════════════════════════
   GET /api/network/ip/:ip — standalone IP lookup
   ══════════════════════════════════════════════════ */
router.get('/ip/:ip', auth, async (req, res) => {
  try {
    const result = await lookupIPReputation(req.params.ip);
    return res.json(result);
  } catch(e) {
    return res.status(500).json({ error:e.message });
  }
});

module.exports = router;