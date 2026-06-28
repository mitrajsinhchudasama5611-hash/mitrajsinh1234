/* ============================================================
   CipherGuard — Password Security Suite
   script.js — All JavaScript
   Developer: Chudasama Mitrajsinh
   Sir Bhavsinhji Polytechnic Institute
   ============================================================ */

// ══════════════════════════════════════
// HASH VISUALIZER
// ══════════════════════════════════════
let prevHashes = { sha256: '', md5: '', sha1: '', sha512: '' };

async function sha256(msg) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
async function sha1(msg) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
async function sha512(msg) {
  const buf = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Pure-JS MD5 (educational — 32 hex chars)
function md5(str) {
  function safeAdd(x,y){const lsw=(x&0xffff)+(y&0xffff);return(((x>>16)+(y>>16)+(lsw>>16))<<16)|(lsw&0xffff);}
  function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
  function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
  function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|((~b)&d),a,b,x,s,t);}
  function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&(~d)),a,b,x,s,t);}
  function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
  function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|(~d)),a,b,x,s,t);}
  const m=[];let i;
  const l=str.length;
  for(i=0;i<l;i++){m[i>>2]|=(str.charCodeAt(i)&0xff)<<((i%4)*8);}
  m[l>>2]|=0x80<<((l%4)*8);m[(((l+64)>>>9)<<4)+14]=l*8;
  let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for(i=0;i<m.length;i+=16){
    const [oa,ob,oc,od]=[a,b,c,d];
    a=md5ff(a,b,c,d,m[i],7,-680876936);d=md5ff(d,a,b,c,m[i+1],12,-389564586);c=md5ff(c,d,a,b,m[i+2],17,606105819);b=md5ff(b,c,d,a,m[i+3],22,-1044525330);
    a=md5ff(a,b,c,d,m[i+4],7,-176418897);d=md5ff(d,a,b,c,m[i+5],12,1200080426);c=md5ff(c,d,a,b,m[i+6],17,-1473231341);b=md5ff(b,c,d,a,m[i+7],22,-45705983);
    a=md5ff(a,b,c,d,m[i+8],7,1770035416);d=md5ff(d,a,b,c,m[i+9],12,-1958414417);c=md5ff(c,d,a,b,m[i+10],17,-42063);b=md5ff(b,c,d,a,m[i+11],22,-1990404162);
    a=md5ff(a,b,c,d,m[i+12],7,1804603682);d=md5ff(d,a,b,c,m[i+13],12,-40341101);c=md5ff(c,d,a,b,m[i+14],17,-1502002290);b=md5ff(b,c,d,a,m[i+15],22,1236535329);
    a=md5gg(a,b,c,d,m[i+1],5,-165796510);d=md5gg(d,a,b,c,m[i+6],9,-1069501632);c=md5gg(c,d,a,b,m[i+11],14,643717713);b=md5gg(b,c,d,a,m[i],20,-373897302);
    a=md5gg(a,b,c,d,m[i+5],5,-701558691);d=md5gg(d,a,b,c,m[i+10],9,38016083);c=md5gg(c,d,a,b,m[i+15],14,-660478335);b=md5gg(b,c,d,a,m[i+4],20,-405537848);
    a=md5gg(a,b,c,d,m[i+9],5,568446438);d=md5gg(d,a,b,c,m[i+14],9,-1019803690);c=md5gg(c,d,a,b,m[i+3],14,-187363961);b=md5gg(b,c,d,a,m[i+8],20,1163531501);
    a=md5gg(a,b,c,d,m[i+13],5,-1444681467);d=md5gg(d,a,b,c,m[i+2],9,-51403784);c=md5gg(c,d,a,b,m[i+7],14,1735328473);b=md5gg(b,c,d,a,m[i+12],20,-1926607734);
    a=md5hh(a,b,c,d,m[i+5],4,-378558);d=md5hh(d,a,b,c,m[i+8],11,-2022574463);c=md5hh(c,d,a,b,m[i+11],16,1839030562);b=md5hh(b,c,d,a,m[i+14],23,-35309556);
    a=md5hh(a,b,c,d,m[i+1],4,-1530992060);d=md5hh(d,a,b,c,m[i+4],11,1272893353);c=md5hh(c,d,a,b,m[i+7],16,-155497632);b=md5hh(b,c,d,a,m[i+10],23,-1094730640);
    a=md5hh(a,b,c,d,m[i+13],4,681279174);d=md5hh(d,a,b,c,m[i],11,-358537222);c=md5hh(c,d,a,b,m[i+3],16,-722521979);b=md5hh(b,c,d,a,m[i+6],23,76029189);
    a=md5hh(a,b,c,d,m[i+9],4,-640364487);d=md5hh(d,a,b,c,m[i+12],11,-421815835);c=md5hh(c,d,a,b,m[i+15],16,530742520);b=md5hh(b,c,d,a,m[i+2],23,-995338651);
    a=md5ii(a,b,c,d,m[i],6,-198630844);d=md5ii(d,a,b,c,m[i+7],10,1126891415);c=md5ii(c,d,a,b,m[i+14],15,-1416354905);b=md5ii(b,c,d,a,m[i+5],21,-57434055);
    a=md5ii(a,b,c,d,m[i+12],6,1700485571);d=md5ii(d,a,b,c,m[i+3],10,-1894986606);c=md5ii(c,d,a,b,m[i+10],15,-1051523);b=md5ii(b,c,d,a,m[i+1],21,-2054922799);
    a=md5ii(a,b,c,d,m[i+8],6,1873313359);d=md5ii(d,a,b,c,m[i+15],10,-30611744);c=md5ii(c,d,a,b,m[i+6],15,-1560198380);b=md5ii(b,c,d,a,m[i+13],21,1309151649);
    a=md5ii(a,b,c,d,m[i+4],6,-145523070);d=md5ii(d,a,b,c,m[i+11],10,-1120210379);c=md5ii(c,d,a,b,m[i+2],15,718787259);b=md5ii(b,c,d,a,m[i+9],21,-343485551);
    a=safeAdd(a,oa);b=safeAdd(b,ob);c=safeAdd(c,oc);d=safeAdd(d,od);
  }
  return [a,b,c,d].map(n=>('00000000'+(n>>>0).toString(16)).slice(-8).match(/../g).reverse().join('')).join('');
}

function countBitDiffs(hex1, hex2) {
  if (!hex1 || !hex2 || hex1.length !== hex2.length) return 0;
  let diff = 0;
  for (let i = 0; i < hex1.length; i += 2) {
    const b1 = parseInt(hex1.substr(i,2),16);
    const b2 = parseInt(hex2.substr(i,2),16);
    let xor = b1 ^ b2;
    while (xor) { diff += xor & 1; xor >>= 1; }
  }
  return diff;
}

function renderHashWithDiff(elId, newHash, prevHash, color) {
  const el = document.getElementById(elId);
  if (!newHash) { el.innerHTML = '<span class="hash-placeholder">Hash will appear here as you type…</span>'; return; }
  el.innerHTML = newHash.split('').map((c, i) => {
    const changed = prevHash && prevHash[i] !== c;
    return `<span class="hash-char${changed?' changed':''}" style="color:${changed?'var(--accent)':color}">${c}</span>`;
  }).join('');
}

async function updateHashes(val) {
  if (!val) {
    ['sha256out','md5out','sha1out','sha512out'].forEach(id => {
      document.getElementById(id).innerHTML = '<span class="hash-placeholder">Hash will appear here as you type…</span>';
    });
    ['sha256changed','md5changed','sha1changed','sha512changed'].forEach(id => {
      document.getElementById(id).textContent = '—';
    });
    prevHashes = {sha256:'',md5:'',sha1:'',sha512:''};
    return;
  }
  const [h256, h1, h512] = await Promise.all([sha256(val), sha1(val), sha512(val)]);
  const hmd5 = md5(val);

  renderHashWithDiff('sha256out', h256, prevHashes.sha256, 'var(--accent)');
  renderHashWithDiff('md5out', hmd5, prevHashes.md5, '#fca5a5');
  renderHashWithDiff('sha1out', h1, prevHashes.sha1, 'var(--warn)');
  renderHashWithDiff('sha512out', h512, prevHashes.sha512, 'var(--accent3)');

  const d256 = countBitDiffs(h256, prevHashes.sha256);
  const dmd5 = countBitDiffs(hmd5, prevHashes.md5);
  const d1   = countBitDiffs(h1,   prevHashes.sha1);
  const d512 = countBitDiffs(h512, prevHashes.sha512);

  if (prevHashes.sha256) {
    document.getElementById('sha256changed').textContent = d256;
    document.getElementById('md5changed').textContent = dmd5;
    document.getElementById('sha1changed').textContent = d1;
    document.getElementById('sha512changed').textContent = d512;
  }

  prevHashes = { sha256: h256, md5: hmd5, sha1: h1, sha512: h512 };
}

async function updateAvalanche() {
  const a = document.getElementById('avalA').value;
  const b = document.getElementById('avalB').value;
  const ha = a ? await sha256(a) : '';
  const hb = b ? await sha256(b) : '';

  const fmtHash = (h, other, colSame, colDiff) => {
    if (!h) return '<span style="color:var(--text3)">—</span>';
    return h.split('').map((c,i) => {
      const diff = other && other[i] && other[i] !== c;
      return `<span style="color:${diff?'var(--accent)':colSame};${diff?'font-weight:700':''};">${c}</span>`;
    }).join('');
  };

  document.getElementById('avalHashA').innerHTML = fmtHash(ha, hb, 'var(--text2)', 'var(--accent)');
  document.getElementById('avalHashB').innerHTML = fmtHash(hb, ha, 'var(--text2)', 'var(--accent)');

  const diffEl = document.getElementById('avalDiff');
  if (!ha || !hb) {
    diffEl.innerHTML = '<div style="color:var(--text3);font-size:.875rem;text-align:center;padding:8px">Enter text in both fields</div>';
    return;
  }
  const bitsTotal = 256;
  const bitsDiff = countBitDiffs(ha, hb);
  const pct = Math.round((bitsDiff / bitsTotal) * 100);
  const hexDiffs = ha.split('').filter((c,i) => hb[i] !== c).length;

  diffEl.innerHTML = `
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;font-size:.8rem;color:var(--text2);margin-bottom:6px">
        <span>Bit difference</span><span style="color:var(--accent);font-weight:700">${bitsDiff} / ${bitsTotal} bits (${pct}%)</span>
      </div>
      <div class="diff-bar-row">
        <div class="diff-bar-track"><div class="diff-bar-fill" style="width:${pct}%"></div></div>
        <div class="diff-stat">${pct}%</div>
      </div>
    </div>
    <div style="margin-bottom:8px;font-size:.75rem;color:var(--text2)">Hex character changes (highlighted <span style="color:var(--accent)">■</span>):</div>
    <div style="line-height:2.2;word-break:break-all">
      ${ha.split('').map((c,i)=>{
        const d = hb[i] !== c;
        return `<span style="display:inline-block;width:14px;height:14px;border-radius:2px;margin:1px;background:${d?'var(--accent)':'rgba(148,163,184,.12)'};vertical-align:middle" title="${d?'Different':'Same'}"></span>`;
      }).join('')}
    </div>
    <div style="margin-top:10px;font-size:.8rem;color:var(--text2)">${hexDiffs} of 64 hex characters changed (${Math.round(hexDiffs/64*100)}% of visible output)</div>
  `;
}

function copyHash(elId, btnId) {
  const el = document.getElementById(elId);
  const text = el.textContent || el.innerText;
  if (!text || text.includes('Hash will appear')) return;
  copyText(text.trim());
  const btn = document.getElementById(btnId);
  btn.textContent = '✅';
  setTimeout(() => btn.textContent = '📋', 2000);
}

// ══════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════
const pages = ['home','checker','generator','compare','tips','about','hash'];

function showPage(id) {
  pages.forEach(p => document.getElementById('page-'+p)?.classList.remove('active'));
  document.getElementById('page-'+id)?.classList.add('active');
  document.querySelectorAll('.nav-link').forEach((el,i) => el.classList.toggle('active', pages[i] === id));
  document.querySelectorAll('.mob-link').forEach((el,i) => el.classList.toggle('active', pages[i] === id));
  window.scrollTo(0,0);
}

// ══════════════════════════════════════
// THEME
// ══════════════════════════════════════
let dark = true;
function toggleTheme() {
  dark = !dark;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  document.getElementById('themeBtn').textContent = dark ? '🌙' : '☀️';
}

function toggleVisibility(id, btn) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁️' : '🙈';
}

// ══════════════════════════════════════
// MATRIX RAIN ANIMATION
// ══════════════════════════════════════
(function initMatrix() {
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/\\`~"\'';
  let cols, drops;
  const fontSize = 14;

  function resize() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols = Math.floor(canvas.width / fontSize);
    drops = Array(cols).fill(1);
  }
  resize();
  window.addEventListener('resize', resize);

  function draw() {
    ctx.fillStyle = dark ? 'rgba(10,13,20,0.05)' : 'rgba(240,244,255,0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00e5ff';
    ctx.font = fontSize + 'px JetBrains Mono, monospace';
    for (let i = 0; i < drops.length; i++) {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 50);
})();

// ══════════════════════════════════════
// ATTACK TICKER ANIMATION
// ══════════════════════════════════════
const weakPasses = ['password','123456','qwerty','letmein','abc123','iloveyou','admin','111111','monkey','dragon','master','123123','sunshine','princess','trustno1'];
let tickerIdx = 0;
function animateTicker() {
  const el = document.getElementById('tickerPass');
  const pass = weakPasses[tickerIdx % weakPasses.length];
  tickerIdx++;
  let i = 0;
  el.textContent = '';
  const interval = setInterval(() => {
    el.textContent += pass[i] || '';
    i++;
    if (i >= pass.length) {
      clearInterval(interval);
      setTimeout(animateTicker, 1800);
    }
  }, 60);
}
animateTicker();

// ══════════════════════════════════════
// COMMON PASSWORDS DATABASE
// ══════════════════════════════════════
const COMMON_PASSWORDS = new Set([
  'password','123456','12345678','1234567','password1','123456789',
  'qwerty','abc123','letmein','monkey','master','dragon','baseball',
  'iloveyou','trustno1','sunshine','princess','welcome','shadow',
  'superman','michael','football','123123','admin','pass','test',
  'qwerty123','1q2w3e4r','111111','000000','1234','12345','123',
  'pass123','asdfgh','zxcvbn','qwertyuiop','654321','666666',
  'password123','aa123456','donald','samsung','starwars','mustang',
  'hello','whatever','batman','flower','2000','charlie','cheese',
  'computer','internet','service','bandit','george','cookie'
]);

const DICT_WORDS = new Set([
  'love','hate','home','life','time','year','good','girl','boy',
  'word','game','name','day','man','woman','child','world','house',
  'work','school','place','city','country','water','food','money',
  'family','friend','book','music','movie','phone','email','site',
  'fire','gold','blue','red','black','white','green','night','morning'
]);

// ══════════════════════════════════════
// STRENGTH TIMELINE
// ══════════════════════════════════════
let timelineData = [];

function drawTimeline() {
  const canvas = document.getElementById('timelineCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.offsetWidth * window.devicePixelRatio;
  canvas.height = 60 * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  const w = canvas.offsetWidth, h = 60;
  ctx.clearRect(0,0,w,h);

  if (timelineData.length < 2) return;

  // Grid lines
  ctx.strokeStyle = 'rgba(30,42,64,0.8)';
  ctx.lineWidth = 1;
  [25,50,75].forEach(y => {
    ctx.beginPath();
    ctx.moveTo(0, h - (y/100)*h);
    ctx.lineTo(w, h - (y/100)*h);
    ctx.stroke();
  });

  // Line
  const step = w / Math.max(timelineData.length - 1, 1);
  ctx.beginPath();
  timelineData.forEach((v, i) => {
    const x = i * step, y = h - (v/100) * h;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#00e5ff';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();

  // Fill
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
  ctx.fillStyle = 'rgba(0,229,255,0.08)';
  ctx.fill();

  // Last point dot
  const last = timelineData[timelineData.length - 1];
  const lx = (timelineData.length - 1) * step, ly = h - (last/100) * h;
  ctx.beginPath();
  ctx.arc(lx, ly, 4, 0, Math.PI*2);
  ctx.fillStyle = '#00e5ff';
  ctx.fill();
}

// ══════════════════════════════════════
// PASSWORD ANALYSIS ENGINE
// ══════════════════════════════════════
let currentAnalysis = null;

function analyzePassword(pass) {
  const len = pass.length;

  const reqs = {
    length: len >= 8, upper: /[A-Z]/.test(pass),
    lower: /[a-z]/.test(pass), number: /[0-9]/.test(pass),
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pass),
    maxlen: len <= 128
  };
  Object.keys(reqs).forEach(k => {
    document.getElementById('req-'+k)?.classList.toggle('met', reqs[k]);
  });

  let variety = [reqs.upper, reqs.lower, reqs.number, reqs.special].filter(Boolean).length;
  let pool = (reqs.lower?26:0) + (reqs.upper?26:0) + (reqs.number?10:0) + (reqs.special?32:0);
  if (pool === 0 && len > 0) pool = 26;
  const entropy = len > 0 ? Math.floor(len * Math.log2(Math.max(pool,1))) : 0;

  let score = Math.min(len*3,30) + variety*10 + Math.min(entropy*0.4,20);
  if (reqs.length) score += 5;
  if (len >= 12) score += 5;
  if (len >= 16) score += 5;
  if (len >= 20) score += 5;

  const passLow = pass.toLowerCase();
  const isCommon = COMMON_PASSWORDS.has(passLow);
  if (isCommon) score = Math.min(score, 15);

  const hasSeq = /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890|qwerty|asdf|zxcv)/i.test(pass);
  if (hasSeq) score -= 15;
  const hasRepeat = /(.)\1{2,}/.test(pass);
  if (hasRepeat) score -= 10;
  let hasDictWord = false;
  for (let w of DICT_WORDS) { if (passLow.includes(w) && w.length > 3) { hasDictWord = true; break; } }
  if (hasDictWord) score -= 5;
  score = Math.max(0, Math.min(100, Math.round(score)));

  let strength, color;
  if (len === 0) { strength = '—'; color = 'var(--text3)'; }
  else if (score < 30) { strength = 'Weak'; color = '#ef4444'; }
  else if (score < 55) { strength = 'Medium'; color = '#f59e0b'; }
  else if (score < 80) { strength = 'Strong'; color = '#10b981'; }
  else { strength = 'Very Strong'; color = '#00e5ff'; }

  // Update bars
  document.getElementById('strengthLabel').textContent = strength;
  document.getElementById('strengthLabel').style.color = color;
  const bar = document.getElementById('strengthBar');
  bar.style.width = len === 0 ? '0%' : score + '%';
  bar.style.background = `linear-gradient(90deg,${color},${color}aa)`;

  // Timeline
  if (len > 0) {
    timelineData.push(score);
    if (timelineData.length > 60) timelineData.shift();
    document.getElementById('timelineWrap').style.display = 'block';
    setTimeout(drawTimeline, 0);
  } else {
    timelineData = [];
    document.getElementById('timelineWrap').style.display = 'none';
  }

  document.getElementById('metLength').textContent = len;
  document.getElementById('metEntropy').textContent = entropy;
  document.getElementById('metScore').textContent = score + '/100';
  document.getElementById('metVariety').textContent = variety + '/4';

  const crackTime = estimateCrackTime(entropy);
  const crackEl = document.getElementById('crackVal');
  crackEl.textContent = len === 0 ? '—' : crackTime;
  document.getElementById('crackTile').className = 'adv-tile ' + (entropy<40?'danger-tile':entropy<60?'warn-tile':'good-tile');

  const breachEl = document.getElementById('breachVal');
  if (len === 0) { breachEl.textContent = 'Enter password'; document.getElementById('breachTile').className='adv-tile'; }
  else if (isCommon) { breachEl.innerHTML = '⚠️ Found in breaches!'; document.getElementById('breachTile').className='adv-tile danger-tile'; }
  else { breachEl.innerHTML = '✅ Not in common lists'; document.getElementById('breachTile').className='adv-tile good-tile'; }

  let patterns = [];
  if (hasSeq) patterns.push('Sequential chars');
  if (hasRepeat) patterns.push('Repeated chars');
  if (/qwerty|asdfgh|zxcvbn/i.test(pass)) patterns.push('Keyboard walk');
  const patEl = document.getElementById('patternVal');
  if (len === 0) { patEl.textContent='—'; document.getElementById('patternTile').className='adv-tile'; }
  else if (patterns.length) { patEl.textContent = patterns.join(', '); document.getElementById('patternTile').className='adv-tile warn-tile'; }
  else { patEl.textContent = '✅ No patterns found'; document.getElementById('patternTile').className='adv-tile good-tile'; }

  const dictEl = document.getElementById('dictVal');
  if (len === 0) { dictEl.textContent='—'; document.getElementById('dictTile').className='adv-tile'; }
  else if (hasDictWord) { dictEl.textContent = '⚠️ Contains dict word'; document.getElementById('dictTile').className='adv-tile warn-tile'; }
  else { dictEl.textContent = '✅ No dict words'; document.getElementById('dictTile').className='adv-tile good-tile'; }

  // Score ring 2
  const scoreSection2 = document.getElementById('scoreSection2');
  if (len > 0) {
    scoreSection2.style.display = 'flex';
    const circumference = 213.6;
    const ring = document.getElementById('scoreRingFill2');
    ring.style.strokeDashoffset = circumference - (score/100)*circumference;
    ring.style.stroke = color;
    document.getElementById('scoreNum2').textContent = score;
    document.getElementById('scoreTitle2').textContent = strength;
    document.getElementById('scoreDesc2').textContent = getScoreDesc(score, len);
    document.getElementById('aiTipBox').style.display = 'block';
    document.getElementById('aiTipBtn').disabled = false;
    document.getElementById('aiTipText').textContent = 'Click "Get AI Tip" to receive personalized security advice.';
  } else {
    scoreSection2.style.display = 'none';
    document.getElementById('aiTipBox').style.display = 'none';
  }

  // Suggestions
  const suggestions = buildSuggestions(pass, reqs, variety, score, hasSeq, hasRepeat, hasDictWord, isCommon);
  const sugBox = document.getElementById('suggestionsBox');
  if (len > 0 && suggestions.length > 0) {
    sugBox.style.display = 'block';
    document.getElementById('suggestionsList').innerHTML = suggestions.map(s => `<div class="suggestion-item">${s}</div>`).join('');
  } else {
    sugBox.style.display = 'none';
  }

  // Store for export
  currentAnalysis = { pass, len, score, strength, entropy, variety, crackTime, isCommon, hasSeq, hasRepeat, hasDictWord, patterns, reqs, suggestions, color };
}

function getScoreDesc(score, len) {
  if (score >= 80) return 'Excellent! This password provides strong protection against modern attacks.';
  if (score >= 55) return 'Good password. A few improvements could make it even stronger.';
  if (score >= 30) return 'Moderate security. Consider adding more character types and length.';
  return 'This password is vulnerable to common attack methods. Please improve it.';
}

function buildSuggestions(pass, reqs, variety, score, hasSeq, hasRepeat, hasDictWord, isCommon) {
  const s = [];
  if (isCommon) s.push('This is an extremely common password — change it immediately!');
  if (!reqs.upper) s.push('Add uppercase letters (A-Z) to increase strength.');
  if (!reqs.lower) s.push('Add lowercase letters (a-z).');
  if (!reqs.number) s.push('Include at least one number (0-9).');
  if (!reqs.special) s.push('Add special characters like !@#$%^&* for stronger security.');
  if (pass.length < 12) s.push('Increase password length to at least 12 characters.');
  if (pass.length < 16 && pass.length >= 12) s.push('Consider making it 16+ characters for even better security.');
  if (hasSeq) s.push('Avoid sequential characters like "123", "abc", or "qwerty".');
  if (hasRepeat) s.push('Remove repeated characters like "aaa" or "111".');
  if (hasDictWord) s.push('Avoid common dictionary words — use random combinations instead.');
  if (score >= 80) return [];
  return s;
}

function estimateCrackTime(entropy) {
  const seconds = Math.pow(2, entropy) / 1e9;
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds/60)} min`;
  if (seconds < 86400) return `${Math.round(seconds/3600)} hrs`;
  if (seconds < 2592000) return `${Math.round(seconds/86400)} days`;
  if (seconds < 31536000) return `${Math.round(seconds/2592000)} months`;
  if (seconds < 3.154e10) return `${Math.round(seconds/31536000)} years`;
  if (seconds < 3.154e13) return `${(seconds/3.154e10).toFixed(0)}K years`;
  if (seconds < 3.154e16) return `${(seconds/3.154e13).toFixed(0)}M years`;
  return 'Billions of years';
}

// ══════════════════════════════════════
// AI TIP (Claude API)
// ══════════════════════════════════════
async function getAITip() {
  if (!currentAnalysis) return;
  const btn = document.getElementById('aiTipBtn');
  const textEl = document.getElementById('aiTipText');
  btn.disabled = true;
  btn.textContent = '⏳ Analyzing...';
  textEl.textContent = 'Consulting AI security advisor…';

  const { len, score, strength, entropy, isCommon, hasSeq, hasRepeat, hasDictWord, reqs } = currentAnalysis;
  const prompt = `You are a concise cybersecurity expert. A user's password has been analyzed with these results:
- Length: ${len} characters
- Security Score: ${score}/100 (${strength})
- Entropy: ${entropy} bits
- Has uppercase: ${reqs.upper}, lowercase: ${reqs.lower}, numbers: ${reqs.number}, symbols: ${reqs.special}
- Found in common breach lists: ${isCommon}
- Sequential characters: ${hasSeq}
- Repeated characters: ${hasRepeat}
- Contains dictionary words: ${hasDictWord}

Give 2-3 short, specific, actionable security tips for this exact password's weaknesses. Be direct and practical. No more than 60 words total.`;

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await resp.json();
    const tip = data.content?.map(b => b.text || '').join('') || 'Could not get AI tip. Try again.';
    textEl.textContent = tip;
    btn.textContent = '🔄 Refresh Tip';
  } catch(e) {
    textEl.textContent = 'AI tip unavailable. Check your network connection.';
    btn.textContent = '✨ Get AI Tip';
  }
  btn.disabled = false;
}

// ══════════════════════════════════════
// EXPORT REPORT
// ══════════════════════════════════════
function exportReport() {
  if (!currentAnalysis) return;
  const { len, score, strength, entropy, variety, crackTime, isCommon, hasSeq, hasRepeat, hasDictWord, patterns, reqs, suggestions } = currentAnalysis;
  const date = new Date().toLocaleString();
  const reqList = Object.entries(reqs).map(([k,v]) => `  ${v?'✅':'❌'} ${k}`).join('\n');
  const suggList = suggestions.length ? suggestions.map(s => '  → '+s).join('\n') : '  (No suggestions — great password!)';

  const txt = `═══════════════════════════════════════════
    CIPHERGUARD — PASSWORD SECURITY REPORT
═══════════════════════════════════════════
Generated: ${date}
Developer: Chudasama Mitrajsinh
Institute: Sir Bhavsinhji Polytechnic Institute

───────────────────────────────────────────
SECURITY SUMMARY
───────────────────────────────────────────
Overall Score  : ${score}/100
Strength Level : ${strength}
Password Length: ${len} characters
Entropy        : ${entropy} bits
Char Types Used: ${variety}/4
Crack Time Est : ${crackTime}

───────────────────────────────────────────
REQUIREMENTS CHECK
───────────────────────────────────────────
${reqList}

───────────────────────────────────────────
SECURITY FLAGS
───────────────────────────────────────────
  ${isCommon?'⚠️':'✅'} Common password breach list: ${isCommon?'FOUND — DANGER':'Not found'}
  ${hasSeq?'⚠️':'✅'} Sequential patterns: ${hasSeq?'Detected':'None'}
  ${hasRepeat?'⚠️':'✅'} Repeated characters: ${hasRepeat?'Detected':'None'}
  ${hasDictWord?'⚠️':'✅'} Dictionary words: ${hasDictWord?'Detected':'None'}
  Patterns found: ${patterns.length ? patterns.join(', ') : 'None'}

───────────────────────────────────────────
IMPROVEMENT SUGGESTIONS
───────────────────────────────────────────
${suggList}

═══════════════════════════════════════════
Analysis performed 100% locally. Your password was never transmitted.
CipherGuard — Password Security Suite
═══════════════════════════════════════════
`;
  const blob = new Blob([txt], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'cipherguard-report.txt';
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('📥 Report downloaded!');
}

// ══════════════════════════════════════
// PASSWORD COMPARISON
// ══════════════════════════════════════
function getMetrics(pass) {
  const len = pass.length;
  const reqs = {
    upper: /[A-Z]/.test(pass), lower: /[a-z]/.test(pass),
    number: /[0-9]/.test(pass), special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pass)
  };
  const variety = Object.values(reqs).filter(Boolean).length;
  const pool = (reqs.lower?26:0)+(reqs.upper?26:0)+(reqs.number?10:0)+(reqs.special?32:0) || 26;
  const entropy = len > 0 ? Math.floor(len * Math.log2(pool)) : 0;

  let score = Math.min(len*3,30)+variety*10+Math.min(entropy*0.4,20);
  if (len>=8) score+=5; if(len>=12) score+=5; if(len>=16) score+=5; if(len>=20) score+=5;
  if (COMMON_PASSWORDS.has(pass.toLowerCase())) score = Math.min(score,15);
  if (/(?:abc|123|qwerty|asdf)/i.test(pass)) score -= 15;
  if (/(.)\1{2,}/.test(pass)) score -= 10;
  score = Math.max(0, Math.min(100, Math.round(score)));

  let strength, color;
  if (len===0) { strength='—'; color='var(--text3)'; }
  else if (score<30) { strength='Weak'; color='#ef4444'; }
  else if (score<55) { strength='Medium'; color='#f59e0b'; }
  else if (score<80) { strength='Strong'; color='#10b981'; }
  else { strength='Very Strong'; color='#00e5ff'; }

  const crackTime = estimateCrackTime(entropy);
  return { len, entropy, variety, score, strength, color, crackTime };
}

function comparePasswords() {
  const a = document.getElementById('cmpInputA').value;
  const b = document.getElementById('cmpInputB').value;
  const mA = getMetrics(a), mB = getMetrics(b);

  function updateBar(suffix, m) {
    const bar = document.getElementById('cmpBar'+suffix);
    const fill = document.getElementById('cmpFill'+suffix);
    const lbl = document.getElementById('cmpLbl'+suffix);
    if (m.len === 0) { bar.style.display='none'; return; }
    bar.style.display='flex';
    fill.style.width = m.score+'%';
    fill.style.background = `linear-gradient(90deg,${m.color},${m.color}aa)`;
    lbl.textContent = m.strength;
    lbl.style.color = m.color;
  }
  updateBar('A', mA); updateBar('B', mB);

  if (a.length === 0 && b.length === 0) {
    document.getElementById('cmpResult').style.display='none'; return;
  }
  document.getElementById('cmpResult').style.display='block';

  const winner = mA.score > mB.score ? 'A' : mB.score > mA.score ? 'B' : null;
  const verdictEl = document.getElementById('cmpVerdict');
  if (!winner) verdictEl.textContent = '🤝 Both passwords are equally strong!';
  else verdictEl.innerHTML = `🏆 Password ${winner} is stronger! <span class="winner-badge">Winner</span>`;

  const rows = [
    ['Length', mA.len+' chars', mB.len+' chars', 'len'],
    ['Security Score', mA.score+'/100', mB.score+'/100', 'score'],
    ['Entropy (bits)', mA.entropy, mB.entropy, 'entropy'],
    ['Char Types', mA.variety+'/4', mB.variety+'/4', 'variety'],
    ['Strength', mA.strength, mB.strength, null],
    ['Crack Time', mA.crackTime, mB.crackTime, null],
  ];

  document.getElementById('cmpTableBody').innerHTML = rows.map(([label, va, vb, key]) => {
    let badgeA='', badgeB='';
    if (key) {
      const numA = parseFloat(va), numB = parseFloat(vb);
      if (numA > numB) badgeA = '<span class="winner-badge">Better</span>';
      else if (numB > numA) badgeB = '<span class="winner-badge">Better</span>';
    }
    return `<tr><td>${label}</td><td>${va}${badgeA}</td><td>${vb}${badgeB}</td></tr>`;
  }).join('');
}

// ══════════════════════════════════════
// PASSWORD GENERATOR
// ══════════════════════════════════════
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const NUMS  = '0123456789';
const SYMS  = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIG = /[0Ol1I]/g;
let genHistory = [];

function generatePassword() {
  const len   = parseInt(document.getElementById('lengthSlider').value);
  const useUp = document.getElementById('cb-upper').checked;
  const useLo = document.getElementById('cb-lower').checked;
  const useNu = document.getElementById('cb-num').checked;
  const useSy = document.getElementById('cb-sym').checked;
  const noAmb = document.getElementById('cb-amb').checked;
  const pron  = document.getElementById('cb-pro').checked;

  if (!useUp && !useLo && !useNu && !useSy) { showToast('Select at least one character type!'); return; }

  let charset = '';
  if (useLo) charset += LOWER;
  if (useUp) charset += UPPER;
  if (useNu) charset += NUMS;
  if (useSy) charset += SYMS;
  if (noAmb) charset = charset.replace(AMBIG, '');

  let password = '';
  if (pron) {
    password = generatePronounceablePassword(len);
  } else {
    const arr = new Uint32Array(len * 2);
    crypto.getRandomValues(arr);
    for (let i = 0; i < len; i++) password += charset[arr[i] % charset.length];
    const required = [];
    if (useLo) required.push(randomChar(noAmb ? LOWER.replace(AMBIG,'') : LOWER));
    if (useUp) required.push(randomChar(noAmb ? UPPER.replace(AMBIG,'') : UPPER));
    if (useNu) required.push(randomChar(noAmb ? NUMS.replace(AMBIG,'') : NUMS));
    if (useSy) required.push(randomChar(SYMS));
    for (let i = 0; i < required.length && i < len; i++) {
      const pos = Math.floor(Math.random() * len);
      password = password.substring(0,pos) + required[i] + password.substring(pos+1);
    }
  }

  document.getElementById('genOutput').value = password;
  showGenStrength(password, 'genStrBar', 'genStrLabel', 'genStrengthBar');
  addToHistory(password);
}

function showGenStrength(password, barId, labelId, wrapId) {
  document.getElementById(wrapId).style.display = 'block';
  const ent = calcEntropy(password);
  let sc = Math.min(100, Math.floor(ent * 1.2));
  let col, lbl;
  if (sc < 30) { lbl='Weak'; col='#ef4444'; }
  else if (sc < 55) { lbl='Medium'; col='#f59e0b'; }
  else if (sc < 80) { lbl='Strong'; col='#10b981'; }
  else { lbl='Very Strong'; col='#00e5ff'; }
  document.getElementById(labelId).textContent = lbl;
  document.getElementById(labelId).style.color = col;
  document.getElementById(barId).style.width = sc+'%';
  document.getElementById(barId).style.background = `linear-gradient(90deg,${col},${col}aa)`;
}

function calcEntropy(pass) {
  let pool = (/[a-z]/.test(pass)?26:0)+(/[A-Z]/.test(pass)?26:0)+(/[0-9]/.test(pass)?10:0)+(/[^a-zA-Z0-9]/.test(pass)?32:0);
  return pass.length * Math.log2(Math.max(pool,1));
}

function randomChar(charset) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return charset[arr[0] % charset.length];
}

function generatePronounceablePassword(len) {
  const vowels = 'aeiou', cons = 'bcdfghjklmnprstvwxyz';
  let p = '', useVowel = Math.random() > 0.5;
  while (p.length < len) { p += randomChar(useVowel ? vowels : cons); useVowel = !useVowel; }
  if (len > 8) { const pos = Math.floor(len * 0.6); p = p.substring(0,pos) + Math.floor(Math.random()*90+10) + p.substring(pos+2); }
  return p.substring(0,len);
}

// ══════════════════════════════════════
// PASSPHRASE GENERATOR
// ══════════════════════════════════════
// EFF-inspired word list (condensed)
const WORD_LIST = [
  'apple','brave','castle','dance','eagle','flame','grace','happy',
  'ivory','jungle','kite','lemon','mango','noble','ocean','piano',
  'quiet','river','solar','tiger','ultra','vivid','water','xenon',
  'yacht','zebra','amber','blaze','coral','dingo','ember','frost',
  'globe','hinge','igloo','jewel','knack','lunar','mirth','nymph',
  'oasis','pixel','quilt','radar','stone','tulip','umbra','vapor',
  'waltz','xenon','yodel','zesty','adobe','blunt','crisp','drift',
  'elbow','finch','gruff','haven','infer','joust','kneel','ledge',
  'mocha','notch','orbit','perch','quaff','relic','shire','tonic',
  'unity','verge','whirl','xeric','yearn','zonal','adorn','brisk',
  'chunk','delta','epoch','fjord','graze','heist','imply','jumbo',
  'kinky','lofty','moxie','nudge','ovoid','pluck','qualm','renew',
  'scalp','thyme','unzip','vouch','wedge','xylem','yeoman','zippy',
  'algae','brawl','cleft','dwarf','expel','fluke','gripe','hoist',
  'inept','jerky','kapow','lyric','musty','niche','onset','proxy',
  'quota','rustic','sniff','talon','usher','vault','wrath','xyster',
  'yawl','zilch','acorn','booth','craft','depot','envy','flair',
  'gloom','husky','impel','jumpy','knob','lusty','mural','novel',
  'optic','plaid','quirk','robin','sleek','throb','unwed','valid'
];

let ppSeparator = '-';

function setPPSep(sep, btn) {
  ppSeparator = sep;
  document.querySelectorAll('.pp-sep-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

function generatePassphrase() {
  const wordCount = parseInt(document.getElementById('ppWordSlider').value);
  const addNum = document.getElementById('cb-ppnum').checked;
  const capitalize = document.getElementById('cb-ppcap').checked;

  const words = [];
  const arr = new Uint32Array(wordCount);
  crypto.getRandomValues(arr);
  for (let i = 0; i < wordCount; i++) {
    let word = WORD_LIST[arr[i] % WORD_LIST.length];
    if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
    words.push(word);
  }

  let passphrase = words.join(ppSeparator);
  if (addNum) {
    const numArr = new Uint32Array(1);
    crypto.getRandomValues(numArr);
    passphrase += ppSeparator + (numArr[0] % 9000 + 1000);
  }

  document.getElementById('ppOutput').value = passphrase;

  // Show word pills
  const pills = document.getElementById('ppPills');
  pills.innerHTML = words.map(w => `<div class="pp-pill">${w}</div>`).join('');

  showGenStrength(passphrase, 'ppStrBar', 'ppStrLabel', 'ppStrengthBar');
  addToHistory(passphrase);
}

function copyPassphrase() {
  const val = document.getElementById('ppOutput').value;
  if (!val) return;
  copyText(val);
  const btn = document.getElementById('ppCopyBtn');
  btn.textContent = '✅'; btn.classList.add('copied');
  setTimeout(() => { btn.textContent='📋'; btn.classList.remove('copied'); }, 2000);
}

// ══════════════════════════════════════
// GENERATOR TABS
// ══════════════════════════════════════
function switchGenTab(tab, btn) {
  document.querySelectorAll('.gen-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.gen-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-'+tab)?.classList.add('active');
}

// ══════════════════════════════════════
// HISTORY
// ══════════════════════════════════════
function addToHistory(p) {
  if (genHistory.length > 0) {
    const sim = similarity(p, genHistory[0]);
    if (sim > 0.6) showToast('⚠️ Similar to a recent password!');
  }
  genHistory.unshift(p);
  if (genHistory.length > 10) genHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('historyList');
  if (genHistory.length === 0) {
    list.innerHTML = '<div class="empty-history">No passwords generated yet.</div>'; return;
  }
  list.innerHTML = genHistory.map(p => `
    <div class="history-item">
      <span class="h-pass">${p}</span>
      <button class="h-copy" onclick="copyText('${p.replace(/'/g,"\\'").replace(/\\/g,'\\\\')}')">📋</button>
    </div>
  `).join('');
}

function clearHistory() { genHistory = []; renderHistory(); }

function similarity(a, b) {
  const longer = a.length > b.length ? a : b, shorter = a.length > b.length ? b : a;
  if (longer.length === 0) return 1;
  let matches = 0;
  for (let c of shorter) if (longer.includes(c)) matches++;
  return matches / longer.length;
}

function copyGenerated() {
  const val = document.getElementById('genOutput').value;
  if (!val) return;
  copyText(val);
  const btn = document.getElementById('copyBtn');
  btn.textContent = '✅'; btn.classList.add('copied');
  setTimeout(() => { btn.textContent='📋'; btn.classList.remove('copied'); }, 2000);
}

function copyText(text) {
  navigator.clipboard.writeText(text)
    .then(() => showToast('✓ Copied to clipboard!'))
    .catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      showToast('✓ Copied!');
    });
}

function updateCheckStyle(cbId, lblId) {
  document.getElementById(lblId).classList.toggle('checked-item', document.getElementById(cbId).checked);
}

// ══════════════════════════════════════
// SECURITY QUIZ
// ══════════════════════════════════════
const QUIZ_QUESTIONS = [
  {
    q: 'Which password is the STRONGEST?',
    opts: ['Password123!', 'correct-horse-battery-staple', 'P@55w0rd', 'qwerty1234'],
    answer: 1,
    exp: '✅ "correct-horse-battery-staple" is a passphrase — long, memorable, and has massive entropy from word combinations.'
  },
  {
    q: 'How many guesses per second can a modern offline attacker typically make?',
    opts: ['1,000', '1 million', '1 billion or more', '10,000'],
    answer: 2,
    exp: '✅ Modern GPUs can test 1 billion+ passwords per second using offline attacks against hashed databases.'
  },
  {
    q: 'What is the BEST way to store unique passwords for every site?',
    opts: ['Write them in a notebook', 'Use a password manager', 'Same password with slight variations', 'Store in a browser notepad'],
    answer: 1,
    exp: '✅ Password managers generate, store, and autofill strong unique passwords — the gold standard for password management.'
  },
  {
    q: 'What does "entropy" mean in the context of password security?',
    opts: ['How fast a password can be typed', 'The randomness and unpredictability of a password', 'Whether a password has been leaked', 'The number of characters in a password'],
    answer: 1,
    exp: '✅ Entropy measures randomness. Higher entropy means more possible combinations, making the password harder to guess.'
  },
  {
    q: 'Which factor has the MOST impact on password strength?',
    opts: ['Using symbols like !@#', 'Password length', 'Using capital letters', 'Avoiding dictionary words'],
    answer: 1,
    exp: '✅ Length wins. Each extra character multiplies the number of possible combinations exponentially.'
  }
];

let quizAnswers = {};
let quizAnswered = new Set();

function initQuiz() {
  quizAnswers = {};
  quizAnswered = new Set();
  document.getElementById('quizScore').classList.remove('show');
  const container = document.getElementById('quizContainer');
  container.innerHTML = QUIZ_QUESTIONS.map((q, qi) => `
    <div class="quiz-q" id="quizQ${qi}">
      <div class="quiz-q-text">${qi+1}. ${q.q}</div>
      <div class="quiz-options">
        ${q.opts.map((opt, oi) => `
          <button class="quiz-opt" onclick="answerQuiz(${qi},${oi})" id="qopt-${qi}-${oi}">${opt}</button>
        `).join('')}
      </div>
      <div class="quiz-feedback" id="qfb-${qi}"></div>
    </div>
  `).join('');
}

function answerQuiz(qi, oi) {
  if (quizAnswered.has(qi)) return;
  quizAnswered.add(qi);
  quizAnswers[qi] = oi;

  const q = QUIZ_QUESTIONS[qi];
  const correct = oi === q.answer;

  // Disable all buttons for this question
  for (let i = 0; i < q.opts.length; i++) {
    const btn = document.getElementById(`qopt-${qi}-${i}`);
    btn.disabled = true;
    if (i === q.answer) btn.classList.add('correct');
    else if (i === oi && !correct) btn.classList.add('wrong');
  }

  const fb = document.getElementById(`qfb-${qi}`);
  fb.textContent = correct ? q.exp : `❌ Incorrect. ${q.exp}`;
  fb.className = `quiz-feedback show ${correct?'good':'bad'}`;

  if (quizAnswered.size === QUIZ_QUESTIONS.length) {
    setTimeout(showQuizScore, 500);
  }
}

function showQuizScore() {
  const total = QUIZ_QUESTIONS.length;
  const correct = Object.entries(quizAnswers).filter(([qi, oi]) => QUIZ_QUESTIONS[qi].answer === oi).length;
  const scoreEl = document.getElementById('quizScore');
  document.getElementById('quizScoreBig').textContent = `${correct}/${total}`;
  const msgs = ['Keep studying! 📚', 'Getting there! 🌱', 'Good effort! 👍', 'Well done! 🎉', 'Security expert! 🏆'];
  document.getElementById('quizScoreMsg').textContent = msgs[Math.min(correct, msgs.length-1)];
  scoreEl.classList.add('show');
  scoreEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ══════════════════════════════════════
// TOAST
// ══════════════════════════════════════
let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

// ══════════════════════════════════════
// INIT
// ══════════════════════════════════════
initQuiz();
renderHistory();