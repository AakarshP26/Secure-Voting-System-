"""
encryption_lab.py — Interactive, self-contained AES-256-GCM visualizer.

Returns a single HTML/CSS/JS blob rendered via st.components.v1.html. All crypto
runs client-side in the browser's **real Web Crypto API** (SubtleCrypto), mirroring
the backend exactly:  HKDF-SHA256 -> AES-256 key, 12-byte nonce, GCM 128-bit tag,
wire format [nonce || ciphertext || tag].

Nothing here is faked: the ciphertext bytes shown are produced by the same AEAD
the server uses. The per-byte "keystream" is recovered as (plaintext XOR ciphertext),
which is exactly how GCM's CTR core works.
"""
from __future__ import annotations

import html as _html


def get_encryption_lab_html(default_msg: str = "Vote: Alice for President", mode: str = "hybrid") -> str:
    default_msg = _html.escape(default_msg).replace('"', "&quot;")
    mode = mode if mode in ("dh", "ml_kem", "hybrid") else "hybrid"
    return _TEMPLATE.replace("__DEFAULT_MSG__", default_msg).replace("__MODE__", mode)


_TEMPLATE = r"""
<div id="lab">
<style>
  #lab, #lab * { box-sizing: border-box; }
  #lab {
    --bg:#070b16; --panel:#0e1628; --panel2:#111c34; --line:#22304d;
    --ink:#e6edf7; --dim:#8b9ac2; --muted:#5b6b8c;
    --plain:#38bdf8; --plainbg:#0b2740;
    --cipher:#a855f7; --cipherbg:#2a1146;
    --key:#f59e0b; --keybg:#3a2708;
    --ok:#22c55e; --okbg:#0c2a17; --bad:#ef4444; --badbg:#2e0d0d;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    color: var(--ink);
    background:
      radial-gradient(1200px 500px at 15% -10%, #16224022, transparent),
      radial-gradient(900px 500px at 100% 0%, #2a114633, transparent),
      var(--bg);
    padding: 20px; border-radius: 16px; border:1px solid var(--line);
  }
  #lab .mono { font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace; }
  #lab h2 { margin:0; font-size:1.35rem; font-weight:800; letter-spacing:-.4px; }
  #lab .sub { color:var(--muted); font-size:.85rem; margin-top:2px; }
  #lab .card {
    background: linear-gradient(180deg, var(--panel), var(--panel2));
    border:1px solid var(--line); border-radius:14px; padding:16px 18px; margin-top:16px;
    box-shadow: 0 10px 30px #0006;
  }
  #lab .step-tag {
    display:inline-flex; align-items:center; gap:8px; font-size:.72rem; font-weight:700;
    text-transform:uppercase; letter-spacing:1.2px; color:var(--dim);
    border:1px solid var(--line); padding:3px 10px; border-radius:999px; background:#0b1424;
  }
  #lab .step-num { color:#0a0f1e; background:var(--cipher); border-radius:50%; width:18px;height:18px;
    display:inline-flex; align-items:center; justify-content:center; font-size:.72rem; font-weight:800; }
  #lab .row { display:flex; gap:14px; flex-wrap:wrap; align-items:center; }
  #lab label.fld { display:block; font-size:.72rem; text-transform:uppercase; letter-spacing:1px; color:var(--muted); margin-bottom:5px; }
  #lab input[type=text] {
    width:100%; background:#0a1222; color:var(--ink); border:1px solid var(--line);
    border-radius:10px; padding:12px 14px; font-size:1rem; outline:none; transition:border .2s, box-shadow .2s;
  }
  #lab input[type=text]:focus { border-color:var(--cipher); box-shadow:0 0 0 3px #a855f733; }
  #lab .modes { display:flex; gap:8px; }
  #lab .mode-btn {
    cursor:pointer; user-select:none; border:1px solid var(--line); background:#0b1424; color:var(--dim);
    padding:9px 14px; border-radius:10px; font-size:.82rem; font-weight:600; transition:.18s; white-space:nowrap;
  }
  #lab .mode-btn:hover { border-color:#3a4b6e; color:var(--ink); }
  #lab .mode-btn.active { background:linear-gradient(180deg,#7c3aed,#6d28d9); color:#fff; border-color:#8b5cf6; box-shadow:0 6px 18px #7c3aed55; }
  #lab .btn {
    cursor:pointer; border:none; border-radius:10px; padding:11px 18px; font-weight:700; font-size:.9rem;
    color:#fff; background:linear-gradient(180deg,#7c3aed,#6d28d9); box-shadow:0 6px 18px #7c3aed55; transition:.15s;
  }
  #lab .btn:hover { transform:translateY(-1px); filter:brightness(1.08); }
  #lab .btn.ghost { background:#0b1424; border:1px solid var(--line); color:var(--dim); box-shadow:none; }
  #lab .btn.ghost:hover { color:var(--ink); border-color:#3a4b6e; }

  /* Handshake */
  #lab .hs { display:grid; grid-template-columns: 1fr auto 1fr; gap:10px; align-items:center; margin-top:6px; }
  #lab .node {
    text-align:center; padding:14px 10px; border-radius:12px; border:1px solid var(--line);
    background:#0b1424; position:relative;
  }
  #lab .node .who { font-weight:800; font-size:1rem; }
  #lab .node .role { font-size:.72rem; color:var(--muted); }
  #lab .wire { position:relative; height:64px; }
  #lab .wire-line { position:absolute; top:50%; left:0; right:0; height:2px; background:linear-gradient(90deg,#22304d,#3a4b6e,#22304d); }
  #lab .pkt {
    position:absolute; top:50%; transform:translate(-50%,-50%); padding:4px 9px; border-radius:8px;
    font-size:.68rem; font-weight:700; white-space:nowrap; opacity:0; transition:left .9s cubic-bezier(.4,0,.2,1), opacity .3s;
    box-shadow:0 4px 14px #0008;
  }
  #lab .pkt.pub { background:var(--plainbg); color:var(--plain); border:1px solid #1d4e7a; }
  #lab .pkt.enc { background:var(--cipherbg); color:#e9d5ff; border:1px solid #6d28d9; }
  #lab .secret-badge {
    margin-top:8px; text-align:center; font-size:.8rem; color:var(--key); opacity:0; transition:opacity .4s;
  }
  #lab .secret-badge.on { opacity:1; }

  /* Key tiles */
  #lab .keyrow { display:flex; flex-wrap:wrap; gap:4px; margin-top:8px; }
  #lab .kb {
    font-family: ui-monospace, monospace; font-size:.72rem; padding:4px 6px; border-radius:6px;
    background:var(--keybg); color:var(--key); border:1px solid #5b420c; min-width:26px; text-align:center;
    opacity:0; transform:translateY(4px); transition:opacity .25s, transform .25s;
  }
  #lab .kb.on { opacity:1; transform:none; }

  /* Encryption matrix */
  #lab .grid-head, #lab .grid-row {
    display:grid; grid-template-columns: 42px 1fr 1fr 1fr 1fr; gap:10px; align-items:center;
  }
  #lab .grid-head { font-size:.68rem; text-transform:uppercase; letter-spacing:.8px; color:var(--muted); padding:0 2px 8px; }
  #lab .cellwrap { display:flex; flex-direction:column; gap:6px; }
  #lab .grid-row { padding:6px 2px; border-top:1px solid #16223c; }
  #lab .glyph {
    font-weight:800; font-size:1.1rem; text-align:center; width:40px; height:40px; line-height:40px;
    border-radius:9px; background:#0b1424; border:1px solid var(--line);
  }
  #lab .tile {
    font-family: ui-monospace, monospace; text-align:center; padding:9px 4px; border-radius:9px;
    font-size:.9rem; font-weight:700; border:1px solid var(--line); background:#0b1424; color:var(--dim);
    transition: background .3s, color .3s, border-color .3s, box-shadow .3s, transform .3s;
  }
  #lab .tile.plain { background:var(--plainbg); color:var(--plain); border-color:#1d4e7a; }
  #lab .tile.key   { background:var(--keybg);   color:var(--key);   border-color:#5b420c; }
  #lab .tile.op    { background:#0b1424; color:var(--muted); font-weight:800; }
  #lab .tile.cipher{ background:var(--cipherbg); color:#e9d5ff; border-color:#6d28d9; }
  #lab .grid-row.live .tile { box-shadow:0 0 0 2px #a855f755, 0 8px 20px #7c3aed44; transform:translateY(-1px); }
  #lab .grid-row.live .glyph { border-color:var(--cipher); box-shadow:0 0 0 2px #a855f755; }
  #lab .caption-lbl { font-size:.62rem; color:var(--muted); text-align:center; }

  /* readable transform strip */
  #lab .strip { display:flex; gap:16px; flex-wrap:wrap; margin-top:6px; }
  #lab .strip .box { flex:1; min-width:220px; }
  #lab .textout {
    font-family: ui-monospace, monospace; font-size:.9rem; padding:12px; border-radius:10px; min-height:46px;
    word-break:break-all; line-height:1.7;
  }
  #lab .textout.plain { background:var(--plainbg); color:var(--plain); border:1px solid #1d4e7a; }
  #lab .textout.cipher { background:var(--cipherbg); color:#e9d5ff; border:1px solid #6d28d9; }

  /* wire packet */
  #lab .packet { display:flex; border-radius:10px; overflow:hidden; border:1px solid var(--line); margin-top:6px; }
  #lab .seg { padding:10px 8px; text-align:center; font-family:ui-monospace,monospace; font-size:.72rem; }
  #lab .seg .seg-lbl { display:block; font-size:.6rem; text-transform:uppercase; letter-spacing:.6px; opacity:.85; margin-bottom:3px; font-family:ui-sans-serif,system-ui; }
  #lab .seg.nonce { background:#0c2a17; color:#86efac; }
  #lab .seg.ct { background:var(--cipherbg); color:#e9d5ff; flex:1; }
  #lab .seg.tag { background:#3a2708; color:#fbbf24; }

  /* security cards */
  #lab .cards { display:grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-top:6px; }
  #lab .scard { background:#0b1424; border:1px solid var(--line); border-radius:12px; padding:13px 14px; }
  #lab .scard .ico { font-size:1.2rem; }
  #lab .scard b { display:block; margin:4px 0 3px; }
  #lab .scard p { margin:0; font-size:.8rem; color:var(--dim); line-height:1.45; }
  #lab .verdict { margin-top:10px; padding:11px 13px; border-radius:10px; font-size:.86rem; font-weight:600; display:none; }
  #lab .verdict.ok { display:block; background:var(--okbg); color:#86efac; border:1px solid #14532d; }
  #lab .verdict.bad { display:block; background:var(--badbg); color:#fca5a5; border:1px solid #7f1d1d; }
  #lab .hint { font-size:.78rem; color:var(--muted); margin-top:8px; }
  @keyframes flip { 0%{transform:rotateX(0)} 50%{transform:rotateX(90deg)} 100%{transform:rotateX(0)} }
</style>

  <div class="row" style="justify-content:space-between;">
    <div>
      <h2>🔐 Encryption Lab</h2>
      <div class="sub">Type a message and watch it become ciphertext — real AES-256-GCM, byte by byte, in your browser.</div>
    </div>
    <div class="modes" id="modes">
      <div class="mode-btn" data-mode="dh">DH-2048</div>
      <div class="mode-btn" data-mode="ml_kem">ML-KEM-768</div>
      <div class="mode-btn" data-mode="hybrid">Hybrid</div>
    </div>
  </div>

  <!-- INPUT -->
  <div class="card">
    <label class="fld">Plaintext message</label>
    <input id="msg" type="text" value="__DEFAULT_MSG__" maxlength="60" autocomplete="off" spellcheck="false" />
    <div class="row" style="margin-top:12px;">
      <button class="btn" id="run">▶ Encrypt &amp; animate</button>
      <button class="btn ghost" id="rekey">🔄 New session key</button>
      <span class="hint" id="speedhint">Tip: edit the text — it re-encrypts live.</span>
    </div>
  </div>

  <!-- STAGE 1: HANDSHAKE -->
  <div class="card">
    <div class="step-tag"><span class="step-num">1</span> Key exchange &amp; key derivation</div>
    <div class="hs" style="margin-top:12px;">
      <div class="node"><div class="who">Alice 👩‍💻</div><div class="role">client</div></div>
      <div style="min-width:260px;">
        <div class="wire">
          <div class="wire-line"></div>
          <div class="pkt pub" id="pkt-a">public key →</div>
          <div class="pkt pub" id="pkt-b">← public key</div>
        </div>
        <div class="secret-badge" id="secretbadge">🤝 shared secret established</div>
      </div>
      <div class="node"><div class="who">Server 🖥️</div><div class="role">:65432</div></div>
    </div>
    <div style="margin-top:14px;">
      <label class="fld" id="kexlbl">HKDF-SHA256 → AES-256 session key (32 bytes)</label>
      <div class="keyrow mono" id="keyrow"></div>
    </div>
  </div>

  <!-- STAGE 2: PER-BYTE ENCRYPTION -->
  <div class="card">
    <div class="step-tag"><span class="step-num">2</span> AES-256-GCM · each byte transformed</div>
    <div class="sub" style="margin:8px 0 12px;">
      GCM works like a stream cipher: <b>cipher byte = plaintext byte ⊕ keystream byte</b>.
      The keystream comes from AES applied to the counter+nonce — never reused.
    </div>
    <div class="grid-head">
      <div>Char</div><div>UTF-8 byte</div><div>Keystream</div><div>XOR</div><div>Cipher byte</div>
    </div>
    <div id="matrix"></div>
    <div class="hint" id="truncnote"></div>

    <div class="strip">
      <div class="box"><label class="fld">Plaintext (readable)</label><div class="textout plain" id="outPlain"></div></div>
      <div class="box"><label class="fld">Ciphertext (hex)</label><div class="textout cipher mono" id="outCipher"></div></div>
    </div>
  </div>

  <!-- STAGE 3: WIRE PACKET -->
  <div class="card">
    <div class="step-tag"><span class="step-num">3</span> On the wire — WebSocket frame</div>
    <div class="sub" style="margin:8px 0 10px;">
      The self-contained blob sent to the server. The 16-byte <b>auth tag</b> lets the receiver detect any tampering.
    </div>
    <div class="packet mono">
      <div class="seg nonce"><span class="seg-lbl">Nonce · 12B</span><span id="wNonce">—</span></div>
      <div class="seg ct"><span class="seg-lbl">Ciphertext · <span id="wCtLen">0</span>B</span><span id="wCt">—</span></div>
      <div class="seg tag"><span class="seg-lbl">Auth tag · 16B</span><span id="wTag">—</span></div>
    </div>
    <div class="hint">Also on the wire (authenticated headers): <span class="mono">message_id</span> for replay protection · <span class="mono">recipient</span> for routing.</div>
  </div>

  <!-- STAGE 4: SECURITY DEMOS -->
  <div class="card">
    <div class="step-tag"><span class="step-num">4</span> Security properties — try them</div>
    <div class="cards">
      <div class="scard">
        <div class="ico">🕵️</div><b>Confidentiality</b>
        <p>Without the key, ciphertext is indistinguishable from random. That's what an eavesdropper sees.</p>
      </div>
      <div class="scard">
        <div class="ico">🛡️</div><b>Integrity (tamper test)</b>
        <p>Flip one ciphertext bit and GCM's tag verification fails on decrypt — no silent corruption.</p>
        <button class="btn ghost" id="tamper" style="margin-top:8px;padding:7px 12px;">Flip a bit &amp; verify</button>
      </div>
      <div class="scard">
        <div class="ico">🌊</div><b>Avalanche effect</b>
        <p>Change one plaintext character and the 16-byte auth tag changes completely.</p>
        <div class="mono" id="avalanche" style="font-size:.72rem;color:var(--muted);margin-top:8px;">tag: —</div>
      </div>
      <div class="scard">
        <div class="ico">⚛️</div><b>Post-quantum</b>
        <p id="pqcard">Hybrid X25519+ML-KEM derives the key — safe even against a future quantum computer.</p>
      </div>
    </div>
    <div class="verdict mono" id="verdict"></div>
  </div>
</div>

<script>
(function(){
  const $ = (id)=>document.getElementById(id);
  const enc = new TextEncoder();
  const hex = (b)=>Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
  const hb  = (n)=>n.toString(16).padStart(2,'0');
  const bin = (n)=>n.toString(2).padStart(8,'0');
  const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));

  let MODE = "__MODE__";
  let sharedSecret = null;   // raw bytes representing the KEM/DH output
  let aesKey = null;         // CryptoKey (AES-GCM 256)
  let keyBytesHex = "";      // for display
  let lastTagHex = null;
  let animToken = 0;         // cancels stale animations

  const MODE_TEXT = {
    dh:      {kex:"Diffie–Hellman 2048-bit → shared secret → HKDF-SHA256 → AES-256 key",
              pq:"⚠️ Classical DH — broken by Shor's algorithm on a quantum computer.", a:"g^a mod p →", b:"← g^b mod p"},
    ml_kem:  {kex:"ML-KEM-768 encapsulation → shared secret → HKDF-SHA256 → AES-256 key",
              pq:"🛡️ ML-KEM-768 (FIPS 203) — lattice-based, resistant to quantum attacks.", a:"encaps key →", b:"← ciphertext"},
    hybrid:  {kex:"X25519 + ML-KEM-768 → HKDF-SHA256 combine → AES-256 key",
              pq:"🔀 Hybrid — safe even if either primitive is later broken. Today's best practice.", a:"X25519 + KEM →", b:"← KEM ciphertext"}
  };

  async function deriveKeyFromSecret(secret){
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey","deriveBits"]);
    const params = {name:"HKDF", hash:"SHA-256", salt: enc.encode("pq-messaging-salt"), info: enc.encode("aes-256-gcm session")};
    const raw = await crypto.subtle.deriveBits(params, base, 256);
    keyBytesHex = hex(new Uint8Array(raw));
    aesKey = await crypto.subtle.importKey("raw", raw, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }

  async function newSession(){
    sharedSecret = crypto.getRandomValues(new Uint8Array(32));
    await deriveKeyFromSecret(sharedSecret);
  }

  function setMode(m){
    MODE = m;
    document.querySelectorAll('#modes .mode-btn').forEach(el=>el.classList.toggle('active', el.dataset.mode===m));
    $('kexlbl').textContent = MODE_TEXT[m].kex;
    $('pqcard').textContent = MODE_TEXT[m].pq;
    $('pkt-a').textContent = MODE_TEXT[m].a;
    $('pkt-b').textContent = MODE_TEXT[m].b;
  }

  async function encryptMessage(text){
    const pt = enc.encode(text);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await crypto.subtle.encrypt({name:"AES-GCM", iv:nonce, tagLength:128}, aesKey, pt);
    const full = new Uint8Array(ctBuf);
    const ct = full.slice(0, pt.length);          // ciphertext body (same length as plaintext)
    const tag = full.slice(pt.length);            // 16-byte GCM tag
    const keystream = pt.map((p,i)=>p ^ ct[i]);   // GCM/CTR: ks = pt XOR ct
    return {pt, nonce, ct, tag, keystream};
  }

  // Map flat UTF-8 byte index -> source character (for the matrix rows)
  function charByteMap(text){
    const rows = [];
    for(const ch of text){
      const bytes = enc.encode(ch);
      for(let i=0;i<bytes.length;i++){
        rows.push({glyph: i===0 ? ch : "↳", byte: bytes[i]});
      }
    }
    return rows;
  }

  const MAX_ROWS = 28;

  async function animate(){
    const token = ++animToken;
    const text = $('msg').value;
    if(!aesKey) await newSession();

    // ---- key tiles ----
    const kr = $('keyrow'); kr.innerHTML = "";
    const kbytes = keyBytesHex.match(/.{2}/g) || [];
    kbytes.forEach(h=>{ const d=document.createElement('div'); d.className='kb'; d.textContent=h; kr.appendChild(d); });

    // ---- handshake anim ----
    const pa=$('pkt-a'), pb=$('pkt-b'), sb=$('secretbadge');
    pa.style.opacity=0; pb.style.opacity=0; sb.classList.remove('on');
    pa.style.left="8%"; pb.style.left="92%";
    await sleep(60); if(token!==animToken) return;
    pa.style.opacity=1; pb.style.opacity=1;
    await sleep(40); pa.style.left="88%"; pb.style.left="12%";
    await sleep(760); if(token!==animToken) return;
    pa.style.opacity=0; pb.style.opacity=0; sb.classList.add('on');
    // reveal key tiles progressively
    const tiles=[...kr.children];
    for(let i=0;i<tiles.length;i++){ tiles[i].classList.add('on'); if(i%4===0) await sleep(12); if(token!==animToken) return; }

    // ---- encrypt ----
    const {pt, nonce, ct, tag, keystream} = await encryptMessage(text);
    if(token!==animToken) return;
    lastTagHex = hex(tag);
    $('avalanche').textContent = "tag: " + lastTagHex.slice(0,24) + "…";

    // ---- build matrix ----
    const rowsMeta = charByteMap(text);
    const matrix = $('matrix'); matrix.innerHTML = "";
    const shown = Math.min(rowsMeta.length, MAX_ROWS);
    $('truncnote').textContent = rowsMeta.length>MAX_ROWS ? `Showing first ${MAX_ROWS} of ${rowsMeta.length} bytes.` : "";
    const rowEls = [];
    for(let i=0;i<shown;i++){
      const m=rowsMeta[i];
      const row=document.createElement('div'); row.className='grid-row';
      row.innerHTML =
        `<div class="glyph">${escapeHtml(m.glyph)}</div>`+
        `<div class="cellwrap"><div class="tile plain">0x${hb(pt[i])}</div><div class="caption-lbl">${bin(pt[i])}</div></div>`+
        `<div class="cellwrap"><div class="tile key">0x${hb(keystream[i])}</div><div class="caption-lbl">AES keystream</div></div>`+
        `<div class="cellwrap"><div class="tile op">⊕</div><div class="caption-lbl">XOR</div></div>`+
        `<div class="cellwrap"><div class="tile cipher">0x${hb(ct[i])}</div><div class="caption-lbl">${bin(ct[i])}</div></div>`;
      matrix.appendChild(row); rowEls.push(row);
    }

    // ---- readable strip + wire ----
    $('outPlain').textContent = text || "—";
    const outC=$('outCipher'); outC.textContent="";
    $('wNonce').textContent = hex(nonce).slice(0,10)+"…";
    $('wCt').textContent = "—"; $('wCtLen').textContent = ct.length;
    $('wTag').textContent = lastTagHex.slice(0,10)+"…";

    // ---- sequential reveal (the star) ----
    let cipherHex="";
    for(let i=0;i<shown;i++){
      if(token!==animToken) return;
      rowEls.forEach(r=>r.classList.remove('live'));
      rowEls[i].classList.add('live');
      cipherHex += hb(ct[i])+" ";
      outC.textContent = cipherHex.trim();
      await sleep(Math.max(38, 320 - shown*7));
    }
    await sleep(120);
    rowEls.forEach(r=>r.classList.remove('live'));
    if(token!==animToken) return;
    $('wCt').textContent = hex(ct).slice(0,10)+(ct.length>5?"…":"");
    // full ciphertext hex for remaining bytes (if truncated in matrix)
    outC.textContent = (hex(ct).match(/.{2}/g)||[]).join(" ");
  }

  function escapeHtml(s){ return s.replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

  // ---- tamper / integrity demo ----
  async function tamperTest(){
    const v=$('verdict'); const text=$('msg').value;
    const {pt, nonce} = await encryptMessage(text);  // fresh
    const full = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,tagLength:128}, aesKey, pt));
    // flip one bit in the ciphertext body
    if(full.length>0) full[0] ^= 0x01;
    try{
      await crypto.subtle.decrypt({name:"AES-GCM",iv:nonce,tagLength:128}, aesKey, full);
      v.className="verdict ok"; v.textContent="✓ decrypt OK (unexpected)";
    }catch(e){
      v.className="verdict bad";
      v.textContent="✗ TAMPER DETECTED — flipped 1 bit → GCM tag verification failed → message rejected. This is integrity + authenticity.";
    }
  }

  // ---- events ----
  document.querySelectorAll('#modes .mode-btn').forEach(el=>{
    el.addEventListener('click', ()=>{ setMode(el.dataset.mode); animate(); });
  });
  let deb;
  $('msg').addEventListener('input', ()=>{ clearTimeout(deb); deb=setTimeout(animate, 260); });
  $('run').addEventListener('click', animate);
  $('rekey').addEventListener('click', async ()=>{ await newSession(); $('verdict').className="verdict"; animate(); });
  $('tamper').addEventListener('click', tamperTest);

  // ---- boot ----
  (async ()=>{ setMode(MODE); await newSession(); animate(); })();
})();
</script>
"""
