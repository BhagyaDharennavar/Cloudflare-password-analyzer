/* Advanced Option B - Pattern detection + common-password checks
   Features:
   - SHA-1 (Web Crypto) + HIBP k-anonymity check
   - Entropy estimate
   - Strength meter
   - Pattern detection: sequential, repeated, keyboard patterns, year, email/username patterns
   - Common password set (practical ~200 entries here; you can expand)
*/

// Elements
const pwd = document.getElementById('pwd');
const toggle = document.getElementById('toggle');
const sha1El = document.getElementById('sha1');
const pwnedEl = document.getElementById('pwned');
const entropyEl = document.getElementById('entropy');
const suggestionsEl = document.getElementById('suggestions');
const flagsEl = document.getElementById('flags');

toggle.addEventListener('click', () => {
  pwd.type = pwd.type === 'password' ? 'text' : 'password';
  toggle.textContent = pwd.type === 'password' ? 'Show' : 'Hide';
});

pwd.addEventListener('input', onInput);

// ---------- Common passwords (sample ~200) ----------
// Replace/expand this list with a larger file or fetch it if you wish.
const commonPasswords = new Set([
  "123456","123456789","password","12345678","qwerty","12345","1234567890","1234567","qwerty123",
  "1q2w3e","111111","123123","abc123","password1","iloveyou","admin","welcome","monkey","dragon",
  "passw0rd","letmein","baseball","football","shadow","master","killer","superman","login","flower",
  "hottie","loveme","zaq1zaq1","password123","zaq12wsx","qazwsx","trustno1","starwars","654321",
  "batman","zaq1@WSX","mustang","michael","pokemon","computer","internet","hello","freedom","whatever",
  "qwertyuiop","1qaz2wsx","dragon123","password!","summer","donald","football1","princess","azerty",
  "pass","pass1234","qwe123","1234","1q2w3e4r","555555","loveyou","123qwe","passwords","welcome1",
  "11111111","987654321","121212","000000","qwerty1","1q2w3e4","00000000","ashley","fluffy","mynoob",
  "superman1","charlie","andrew","letmein1","monkey123","hello123","trustno1","123321","654321","!@#$%^",
  "password1!","zaq!@WSX","1qaz2wsx3edc","football123","qwertyui","qwer1234","welcome123","loveme123",
  "1q2w3e4r5t","!@#$","marina","hannah","michael1","nicole","jessica","daniel","jordan","hunter",
  "buster","soccer","killer123","passw0rd1","steven","tigger","bailey","pepper","gregory","summer123",
  "1qazxsw2","flower123","147258369","mypass","mypassword","q1w2e3r4","trustno1!","cookie","computer1",
  "qweasd","asdfgh","asdf1234","zxcvbnm","zxcvbn","zaq12swx","159753","159357","aa123456","qweqwe",
  "monkey1","shadow1","iloveyou1","123abc","password1234","abc123456","qazwsxedc","1qaz2wsx3","love"
  // ... you can expand this list to top-1000 externally
]);

// ---------- Main input handler ----------
async function onInput(){
  const value = pwd.value || '';
  clearUIIfEmpty(value);
  if(!value) return;

  // 1) SHA-1 in browser
  const sha1 = await sha1hex(value);
  sha1El.textContent = sha1;

  // 2) Entropy estimate
  const charset = charsetSize(value);
  const entropy = charset ? Math.log2(charset) * value.length : 0;
  entropyEl.textContent = Math.round(entropy * 10) / 10;

  // 3) Strength score
  const baseScore = computeScore(value);

  // 4) Advanced pattern checks (flags)
  const flags = [];
  if(commonPasswordCheck(value)) flags.push({t:'Common password', s:'danger', detail:'Matches a commonly used password list'});
  if(isSequential(value)) flags.push({t:'Sequential characters', s:'warn', detail:'Contains sequential characters like 1234 or abcd'});
  if(isRepeatedChars(value)) flags.push({t:'Repeated characters', s:'warn', detail:'Contains repeated characters or repeated substrings'});
  if(isKeyboardPattern(value)) flags.push({t:'Keyboard pattern', s:'warn', detail:'Contains keyboard sequences like qwerty or asdf'});
  if(containsYear(value)) flags.push({t:'Year detected', s:'info', detail:'Contains a year (e.g., 1990, 2023). Avoid using birth years'});
  if(looksLikeEmailOrUsername(value)) flags.push({t:'Email/username pattern', s:'info', detail:'Looks like an email/username pattern. Avoid reuse across accounts'});

  // 5) Adjust score based on flags (penalize)
  let adjustedScore = baseScore;
  if(flags.some(f=>f.s==='danger')) adjustedScore = Math.max(0, adjustedScore - 2);
  else if(flags.length) adjustedScore = Math.max(0, adjustedScore - 1);

  updateStrengthUI(adjustedScore, value);
  renderFlags(flags);

  // 6) HIBP check in background (non-blocking)
  pwnedEl.textContent = 'Checking HIBP...';
  try {
    const pwnCount = await checkPwned(sha1);
    if(pwnCount > 0){
      pwnedEl.textContent = `FOUND in ${pwnCount.toLocaleString()} breaches ❌`;
      pwnedEl.style.color = getComputedStyle(document.documentElement).getPropertyValue('--bad') || '#ff6b6b';
      // add a high priority flag if not already
      if(!flags.some(f=>f.t==='Common password')) {
        flags.unshift({t:'Found in breaches', s:'danger', detail:`This password appears in public breaches (${pwnCount} times)`});
        renderFlags(flags);
        adjustedScore = Math.max(0, adjustedScore - 2);
        updateStrengthUI(adjustedScore, value);
      }
    } else {
      pwnedEl.textContent = 'Not found in known breaches ✔️';
      pwnedEl.style.color = getComputedStyle(document.documentElement).getPropertyValue('--good') || '#8ee7ff';
    }
  } catch(err){
    pwnedEl.textContent = 'HIBP check unavailable';
    pwnedEl.style.color = '#fbbf24';
  }
}

// ---------- small helpers ----------
function clearUIIfEmpty(value){
  if(!value){
    sha1El.textContent = '—';
    pwnedEl.textContent = '—';
    pwnedEl.style.color = '';
    entropyEl.textContent = '—';
    suggestionsEl.textContent = '';
    flagsEl.innerHTML = '';
    updateStrengthUI(0,'');
  }
}

// SHA-1 using Web Crypto API
async function sha1hex(text){
  const b = new TextEncoder().encode(text);
  const h = await crypto.subtle.digest('SHA-1', b);
  return Array.from(new Uint8Array(h)).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
}

// charset estimate
function charsetSize(s){
  let size=0;
  if(/[a-z]/.test(s)) size+=26;
  if(/[A-Z]/.test(s)) size+=26;
  if(/[0-9]/.test(s)) size+=10;
  if(/[^A-Za-z0-9]/.test(s)) size+=32;
  return size;
}

// basic score 0-5
function computeScore(p){
  let score=0;
  if(p.length>=8) score++;
  if(/[a-z]/.test(p)) score++;
  if(/[A-Z]/.test(p)) score++;
  if(/[0-9]/.test(p)) score++;
  if(/[^A-Za-z0-9]/.test(p)) score++;
  return score;
}

// ---------- Pattern detection functions ----------

// common password list check
function commonPasswordCheck(p){
  return commonPasswords.has(p.toLowerCase());
}

// sequential detection (numbers or letters) - checks substrings length >=4
function isSequential(s){
  const lower = s.toLowerCase();
  // check for ascending sequences in alpha and numeric
  for(let i=0;i<lower.length-3;i++){
    const chunk = lower.slice(i,i+4);
    if(isConsecutive(chunk)) return true;
  }
  return false;
}
function isConsecutive(chunk){
  for(let i=1;i<chunk.length;i++){
    if(chunk.charCodeAt(i) !== chunk.charCodeAt(i-1) + 1) return false;
  }
  return true;
}

// repeated characters (aaaa) or repeated substring like xyzxyz
function isRepeatedChars(s){
  if(/(.)\1{3,}/.test(s)) return true; // 4+ repeats
  // repeated substring (e.g., 'abcabc' or '1212')
  for(let size=2; size <= Math.floor(s.length/2); size++){
    for(let i=0;i<=s.length - size*2;i++){
      const a = s.substr(i,size);
      const b = s.substr(i+size,size);
      if(a === b) return true;
    }
  }
  return false;
}

// keyboard patterns - check for known patterns in lower-case
function isKeyboardPattern(s){
  const patterns = ['qwerty','asdfgh','zxcvbn','1q2w','qaz','wasd','qwert','passw','!@#','$%^','123qwe'];
  const lower = s.toLowerCase();
  return patterns.some(p => lower.includes(p));
}

// detect 4-digit year between 1900 and 2029
function containsYear(s){
  const m = s.match(/(19\d{2}|20[0-2]\d)/);
  return !!m;
}

// looks like email or username (contains @ or dot with letters/digits)
function looksLikeEmailOrUsername(s){
  if(s.includes('@')) return true;
  // username-like: contains name + digits (e.g., john1990)
  if(/[a-z]+\d{2,}/i.test(s)) return true;
  return false;
}

// ---------- UI Rendering ----------

function updateStrengthUI(score, password){
  const fill = document.getElementById('strength-fill');
  const text = document.getElementById('strength-text');

  const percent = (score/5) * 100;
  fill.style.width = percent + '%';

  if(score <= 1) fill.style.background = getComputedStyle(document.documentElement).getPropertyValue('--bad') || '#ef4444';
  else if(score === 2) fill.style.background = getComputedStyle(document.documentElement).getPropertyValue('--warn') || '#f59e0b';
  else fill.style.background = getComputedStyle(document.documentElement).getPropertyValue('--good') || '#10b981';

  const labels = ["Very Weak","Weak","Medium","Strong","Very Strong"];
  text.textContent = 'Strength: ' + (labels[Math.max(0,score-1)] || labels[0]);

  // suggestions (improve UX)
  const tips = [];
  if(password.length < 12) tips.push('Increase length to at least 12+ characters.');
  if(!/[A-Z]/.test(password)) tips.push('Add an uppercase letter (A-Z).');
  if(!/[a-z]/.test(password)) tips.push('Add a lowercase letter (a-z).');
  if(!/[0-9]/.test(password)) tips.push('Include numbers (0-9).');
  if(!/[^A-Za-z0-9]/.test(password)) tips.push('Add special characters like @, #, %, !.');

  suggestionsEl.innerHTML = tips.length ? tips.map(t => '• ' + t).join('<br>') : 'Your password looks strong!';
}

// render flags/warnings
function renderFlags(flags){
  if(!flags || !flags.length){ flagsEl.innerHTML = ''; return; }
  // Build HTML
  const parts = flags.map(f=>{
    const cls = f.s === 'danger' ? 'warning' : '';
    return `<div class="flag ${cls}"><strong>${escapeHTML(f.t)}</strong><div>${escapeHTML(f.detail)}</div></div>`;
  });
  flagsEl.innerHTML = parts.join('');
}

// simple HTML escaper
function escapeHTML(s){ return (s+'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// ---------- HIBP k-anonymity (same as before) ----------
async function checkPwned(sha1){
  const prefix = sha1.slice(0,5);
  const suffix = sha1.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;
  const res = await fetch(url, { headers: {'Add-Padding':'true'} });
  if(!res.ok) throw new Error('HIBP request failed: ' + res.status);
  const text = await res.text();
  const lines = text.split('\n');
  for(const line of lines){
    const [hashSuffix, count] = line.trim().split(':');
    if(!hashSuffix) continue;
    if(hashSuffix.toUpperCase() === suffix) return parseInt(count,10) || 0;
  }
  return 0;
}
