'use strict';

/* =====================================================================
   Data
   ===================================================================== */

// Kata/password umum (campuran Inggris & Indonesia). Dipakai untuk
// deteksi password persis sama dan kata yang terselip di dalam password.
const COMMON_WORDS = [
  'password', 'passw0rd', 'qwerty', 'qwertyuiop', 'abc123', 'admin', 'administrator',
  'letmein', 'welcome', 'iloveyou', 'dragon', 'monkey', 'master', 'login', 'princess',
  'football', 'baseball', 'sunshine', 'shadow', 'superman', 'batman', 'trustno1',
  'whatever', 'freedom', 'hello', 'secret', 'root', 'user', 'test', 'guest',
  'sayang', 'cintaku', 'rahasia', 'bismillah', 'indonesia', 'garuda', 'jakarta',
  'bandung', 'surabaya', 'solo', 'jogja', 'kucing', 'anjing', 'bunga', 'matahari',
  'merdeka', 'nusantara', 'selamat', 'kamu', 'aku', 'cinta', 'sandi', 'katasandi',
  'kunci', 'gantengbanget', 'cantik', 'ganteng', 'bangsat', 'persija', 'persib'
];

const COMMON_SET = new Set(COMMON_WORDS.concat([
  '123456', '1234567', '12345678', '123456789', '1234567890', '12345', '111111',
  '000000', '123123', '654321', '666666', '121212', '112233', 'password1',
  'qwerty123', '1q2w3e4r', 'abc12345'
]));

const KEYBOARD_ROWS = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };

const GUESSES_PER_SECOND = 1e10; // serangan offline pada hash cepat (asumsi)

const LEVELS = [
  { label: 'Sangat lemah', max: 28 },
  { label: 'Lemah', max: 36 },
  { label: 'Sedang', max: 60 },
  { label: 'Kuat', max: 80 },
  { label: 'Sangat kuat', max: Infinity }
];

/* =====================================================================
   Analisis kekuatan password
   ===================================================================== */

function normalizeLeet(text) {
  return text.toLowerCase().replace(/[013457@$!]/g, (c) => LEET[c] || c);
}

function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[ -/:-@[-`{-~]/.test(pw)) pool += 33;
  if (/[^\x20-\x7e]/.test(pw)) pool += 100;
  return pool;
}

/**
 * Memperkirakan entropi (bit) dan mengumpulkan temuan pola.
 * Pendekatan: entropi dasar = panjang_efektif * log2(pool). Setiap pola
 * yang terdeteksi (pengulangan, urutan, jalur keyboard, kata umum, tahun)
 * "memakan" karakter sehingga panjang efektif berkurang.
 */
function analyze(pw) {
  const findings = [];
  const len = pw.length;
  if (len === 0) return { bits: 0, findings, pool: 0 };

  const lower = pw.toLowerCase();
  const normalized = normalizeLeet(pw);
  const mask = new Array(len).fill(false);
  let wasted = 0;

  // Tandai segmen pola; `keep` = jumlah karakter yang tetap dihitung sebagai informasi.
  function mark(start, length, keep) {
    let fresh = 0;
    for (let i = start; i < start + length && i < len; i++) {
      if (!mask[i]) { mask[i] = true; fresh++; }
    }
    wasted += Math.max(0, fresh - keep);
  }

  // 1. Password umum persis sama
  const isCommon = COMMON_SET.has(lower) || COMMON_SET.has(normalized);
  if (isCommon) findings.push('Password ini termasuk daftar password yang sangat umum.');

  // 2. Kata umum di dalam password (termasuk versi leetspeak)
  if (!isCommon) {
    const hits = new Set();
    for (const word of COMMON_WORDS) {
      if (word.length < 4) continue;
      for (const source of [lower, normalized]) {
        let idx = source.indexOf(word);
        while (idx !== -1) {
          mark(idx, word.length, 2); // satu kata ~ 13 bit ~ 2 karakter acak
          hits.add(word);
          idx = source.indexOf(word, idx + 1);
        }
      }
    }
    if (hits.size) findings.push('Mengandung kata umum: ' + [...hits].slice(0, 4).join(', ') + '.');
  }

  // 3. Karakter berulang (aaa, 1111)
  const repeatRe = /(.)\1{2,}/g;
  let m;
  let hasRepeat = false;
  while ((m = repeatRe.exec(pw)) !== null) {
    mark(m.index, m[0].length, 1);
    hasRepeat = true;
  }
  if (hasRepeat) findings.push('Ada karakter yang berulang beruntun (misalnya aaa atau 111).');

  // 4. Urutan karakter (abc, 123, cba, 321)
  let hasSeq = false;
  let runStart = 0;
  let runDir = 0;
  for (let i = 1; i <= len; i++) {
    const diff = i < len ? lower.charCodeAt(i) - lower.charCodeAt(i - 1) : 0;
    const dir = diff === 1 ? 1 : diff === -1 ? -1 : 0;
    if (dir !== 0 && (runDir === 0 || dir === runDir)) {
      if (runDir === 0) runStart = i - 1;
      runDir = dir;
    } else {
      const runLen = i - runStart;
      if (runDir !== 0 && runLen >= 3) { mark(runStart, runLen, 1); hasSeq = true; }
      runDir = dir;
      runStart = dir !== 0 ? i - 1 : i;
    }
  }
  if (hasSeq) findings.push('Ada urutan karakter yang mudah ditebak (misalnya abc atau 1234).');

  // 5. Jalur keyboard (qwer, asdf, 7890) maju maupun mundur
  let hasWalk = false;
  for (const row of KEYBOARD_ROWS) {
    const rev = row.split('').reverse().join('');
    for (const r of [row, rev]) {
      for (let size = Math.min(r.length, len); size >= 4; size--) {
        for (let s = 0; s + size <= r.length; s++) {
          const chunk = r.slice(s, s + size);
          let idx = lower.indexOf(chunk);
          while (idx !== -1) {
            mark(idx, size, 1);
            hasWalk = true;
            idx = lower.indexOf(chunk, idx + 1);
          }
        }
      }
    }
  }
  if (hasWalk) findings.push('Ada pola jalur keyboard (misalnya qwerty atau asdf).');

  // 6. Tahun (1900-2099)
  const yearRe = /(?:19|20)\d{2}/g;
  let hasYear = false;
  while ((m = yearRe.exec(pw)) !== null) {
    mark(m.index, 4, 2);
    hasYear = true;
  }
  if (hasYear) findings.push('Mengandung tahun, yang mudah ditebak penyerang.');

  // 7. Terlalu pendek
  if (len < 8) findings.push('Terlalu pendek. Gunakan minimal 12 karakter.');

  const pool = poolSize(pw);
  const effectiveLen = Math.max(0, len - wasted);
  let bits = effectiveLen * Math.log2(Math.max(pool, 2));
  if (isCommon) bits = Math.min(bits, 10);

  return { bits, findings, pool };
}

function levelFor(bits) {
  return LEVELS.findIndex((l) => bits < l.max);
}

function formatDuration(seconds) {
  if (seconds < 1) return 'kurang dari 1 detik';
  const fmt = (n) => Math.round(n).toLocaleString('id-ID');
  if (seconds < 60) return fmt(seconds) + ' detik';
  const minutes = seconds / 60;
  if (minutes < 60) return fmt(minutes) + ' menit';
  const hours = minutes / 60;
  if (hours < 24) return fmt(hours) + ' jam';
  const days = hours / 24;
  if (days < 365) return fmt(days) + ' hari';
  const years = days / 365;
  if (years < 100) return fmt(years) + ' tahun';
  if (years < 1e6) return fmt(years / 100) + ' abad';
  if (years < 1e12) return fmt(years) + ' tahun';
  return 'lebih dari 1 triliun tahun';
}

function crackTimeSeconds(bits) {
  return Math.pow(2, Math.max(bits - 1, 0)) / GUESSES_PER_SECOND;
}

/* =====================================================================
   Cek kebocoran (Have I Been Pwned, k-anonymity)
   ===================================================================== */

async function sha1Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-1', data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

async function breachCount(pw) {
  if (!window.crypto || !crypto.subtle) {
    throw new Error('Web Crypto tidak tersedia (butuh HTTPS atau localhost).');
  }
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch('https://api.pwnedpasswords.com/range/' + prefix, {
    headers: { 'Add-Padding': 'true' },
    referrerPolicy: 'no-referrer'
  });
  if (!res.ok) throw new Error('Layanan merespons dengan status ' + res.status);
  const body = await res.text();
  for (const line of body.split('\n')) {
    const [s, c] = line.trim().split(':');
    if (s === suffix) return parseInt(c, 10) || 0;
  }
  return 0;
}

/* =====================================================================
   Generator (CSPRNG)
   ===================================================================== */

const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~'
};
const AMBIGUOUS = /[Il1O0o]/g;

// Bilangan acak seragam di [0, max) tanpa modulo bias (rejection sampling).
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function generatePassword(length, options) {
  const sets = [];
  for (const key of ['lower', 'upper', 'digits', 'symbols']) {
    if (!options[key]) continue;
    let chars = CHARSETS[key];
    if (options.noAmbiguous) chars = chars.replace(AMBIGUOUS, '');
    if (chars.length) sets.push(chars);
  }
  if (sets.length === 0) return null;

  const all = sets.join('');
  const result = sets.map((s) => s[randomInt(s.length)]); // minimal 1 dari tiap jenis
  while (result.length < length) result.push(all[randomInt(all.length)]);
  return { password: shuffle(result).join(''), poolLength: all.length };
}

/* =====================================================================
   UI
   ===================================================================== */

function $(id) { return document.getElementById(id); }

function initChecker() {
  const input = $('pw-input');
  const toggle = $('toggle-visibility');
  const meter = $('meter');
  const summaryEmpty = $('summary-empty');
  const summaryBody = $('summary-body');
  const findingsWrap = $('findings-wrap');
  const label = $('meter-label');
  const entropyEl = $('entropy');
  const crackEl = $('crack-time');
  const checklist = $('checklist');
  const findingsEl = $('findings');
  const hibpBtn = $('hibp-btn');
  const hibpResult = $('hibp-result');

  let checkToken = 0; // membatalkan hasil HIBP yang sudah usang

  function clearHibp() {
    checkToken++;
    hibpResult.textContent = '';
    hibpResult.className = 'hibp-result';
  }

  function renderChecklist(pw) {
    const rules = [
      ['Minimal 12 karakter', pw.length >= 12],
      ['Ada huruf kecil', /[a-z]/.test(pw)],
      ['Ada huruf besar', /[A-Z]/.test(pw)],
      ['Ada angka', /[0-9]/.test(pw)],
      ['Ada simbol', /[^A-Za-z0-9]/.test(pw)]
    ];
    checklist.replaceChildren(
      ...rules.map(([text, ok]) => {
        const li = document.createElement('li');
        li.className = ok ? 'ok' : 'no';
        li.textContent = text;
        return li;
      })
    );
  }

  function renderFindings(list, hasInput) {
    const items = !hasInput ? [] : list.length ? list : ['Tidak ada pola lemah yang terdeteksi.'];
    findingsEl.replaceChildren(
      ...items.map((text) => {
        const li = document.createElement('li');
        if (list.length === 0) li.className = 'none';
        li.textContent = text;
        return li;
      })
    );
  }

  function render() {
    const pw = input.value;
    clearHibp();
    hibpBtn.disabled = pw.length === 0;
    renderChecklist(pw);

    summaryEmpty.hidden = pw.length > 0;
    summaryBody.hidden = pw.length === 0;
    findingsWrap.hidden = pw.length === 0;

    if (!pw) {
      meter.className = 'meter';
      meter.setAttribute('aria-valuenow', '0');
      label.textContent = 'Belum ada input';
      entropyEl.textContent = '-';
      crackEl.textContent = '-';
      renderFindings([], false);
      return;
    }

    const { bits, findings } = analyze(pw);
    const level = levelFor(bits);
    const pct = Math.min(100, Math.round(bits));

    meter.className = 'meter lvl' + level;
    meter.setAttribute('aria-valuenow', String(pct));
    label.textContent = LEVELS[level].label;
    entropyEl.textContent = '\u2248 ' + Math.round(bits) + ' bit';
    crackEl.textContent = formatDuration(crackTimeSeconds(bits));
    renderFindings(findings, true);
  }

  input.addEventListener('input', render);

  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    const text = show ? 'Sembunyikan password' : 'Tampilkan password';
    toggle.setAttribute('aria-label', text);
    toggle.title = text;
    toggle.setAttribute('aria-pressed', String(show));
  });

  hibpBtn.addEventListener('click', async () => {
    const pw = input.value;
    if (!pw) return;
    const token = ++checkToken;
    hibpBtn.disabled = true;
    hibpResult.className = 'hibp-result';
    hibpResult.textContent = 'Memeriksa...';
    try {
      const count = await breachCount(pw);
      if (token !== checkToken) return;
      if (count > 0) {
        hibpResult.className = 'hibp-result bad';
        hibpResult.textContent =
          'Password ini muncul ' + count.toLocaleString('id-ID') + ' kali dalam data kebocoran. Jangan dipakai.';
      } else {
        hibpResult.className = 'hibp-result good';
        hibpResult.textContent = 'Tidak ditemukan dalam data kebocoran yang diketahui.';
      }
    } catch (err) {
      if (token !== checkToken) return;
      hibpResult.className = 'hibp-result err';
      hibpResult.textContent = 'Gagal memeriksa: ' + err.message;
    } finally {
      if (token === checkToken) hibpBtn.disabled = input.value.length === 0;
    }
  });

  render();
}

function initTheme() {
  const btn = $('theme-toggle');
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');

  function current() {
    return root.dataset.theme || (media.matches ? 'dark' : 'light');
  }
  function sync() {
    const dark = current() === 'dark';
    const text = dark ? 'Mode terang' : 'Mode gelap';
    btn.setAttribute('aria-label', text);
    btn.title = text;
    btn.setAttribute('aria-pressed', String(dark));
  }

  btn.addEventListener('click', () => {
    root.dataset.theme = current() === 'dark' ? 'light' : 'dark';
    sync();
  });
  media.addEventListener('change', sync);
  sync();
}

function initGenerator() {
  const out = $('gen-output');
  const copyBtn = $('gen-copy');
  const copyStatus = $('copy-status');
  const lengthInput = $('gen-length');
  const lengthValue = $('gen-length-value');
  const meta = $('gen-meta');
  const boxes = {
    lower: $('gen-lower'),
    upper: $('gen-upper'),
    digits: $('gen-digits'),
    symbols: $('gen-symbols'),
    noAmbiguous: $('gen-ambiguous')
  };

  function generate() {
    copyStatus.textContent = '';
    const length = parseInt(lengthInput.value, 10);
    const options = {
      lower: boxes.lower.checked,
      upper: boxes.upper.checked,
      digits: boxes.digits.checked,
      symbols: boxes.symbols.checked,
      noAmbiguous: boxes.noAmbiguous.checked
    };
    const result = generatePassword(length, options);
    if (!result) {
      out.textContent = '-';
      copyBtn.disabled = true;
      meta.textContent = 'Pilih minimal satu jenis karakter.';
      return;
    }
    out.textContent = result.password;
    copyBtn.disabled = false;
    const bits = length * Math.log2(result.poolLength);
    meta.textContent =
      'Entropi \u2248 ' + Math.round(bits) + ' bit (' + LEVELS[levelFor(bits)].label.toLowerCase() + '). ' +
      'Dibuat dengan crypto.getRandomValues.';
  }

  lengthInput.addEventListener('input', () => {
    lengthValue.textContent = lengthInput.value;
    generate();
  });
  Object.values(boxes).forEach((box) => box.addEventListener('change', generate));
  $('gen-btn').addEventListener('click', generate);

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(out.textContent);
      copyStatus.textContent = 'Tersalin ke clipboard.';
      copyBtn.textContent = 'Tersalin';
      setTimeout(() => { copyBtn.textContent = 'Salin'; }, 1500);
    } catch (_) {
      copyStatus.textContent = 'Gagal menyalin otomatis. Blok teks lalu salin manual.';
    }
  });

  generate();
}

// Ekspor untuk pengujian di Node; di browser blok ini dilewati.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyze, levelFor, formatDuration, crackTimeSeconds, generatePassword, randomInt, LEVELS };
} else {
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initChecker();
    initGenerator();
  });
}
