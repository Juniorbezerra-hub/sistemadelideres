/* Verificação em 2 etapas (TOTP, RFC 6238) só com o módulo `crypto` do Node — sem dependência extra.
   - TOTP: HMAC-SHA1, 6 dígitos, passo de 30 s (o padrão do Google/Microsoft Authenticator e do Authy).
   - Segredo guardado CRIPTOGRAFADO (AES-256-GCM) com a chave TOTP_CHAVE (variável de ambiente).
   - Códigos de recuperação: 15 caracteres hex (60 bits), guardados como HMAC-SHA256 com chave derivada
     (banco vazado sozinho não permite quebrar os códigos). */
const crypto = require('crypto');

const ALFABETO_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Codificar(buf){
  let bits = 0, valor = 0, saida = '';
  for(const byte of buf){
    valor = (valor << 8) | byte; bits += 8;
    while(bits >= 5){ saida += ALFABETO_B32[(valor >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if(bits > 0) saida += ALFABETO_B32[(valor << (5 - bits)) & 31];
  return saida;
}
function base32Decodificar(texto){
  const limpo = String(texto).toUpperCase().replace(/=+$/,'').replace(/\s+/g,'');
  let bits = 0, valor = 0; const bytes = [];
  for(const c of limpo){
    const i = ALFABETO_B32.indexOf(c);
    if(i < 0) throw new Error('base32 inválido');
    valor = (valor << 5) | i; bits += 5;
    if(bits >= 8){ bytes.push((valor >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}

/* Código TOTP para um contador (nº de janelas de 30 s desde 1970). */
function totpCodigo(segredoBuf, contador, digitos){
  const d = digitos || 6;
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(contador));
  const h = crypto.createHmac('sha1', segredoBuf).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  const n = ((h[o] & 0x7f) << 24) | (h[o+1] << 16) | (h[o+2] << 8) | h[o+3];
  return String(n % (10 ** d)).padStart(d, '0');
}

/* Devolve o contador cuja janela bate com o código (aceita ±1 janela = ±30 s de diferença de relógio) ou null. */
function totpContadorValido(segredoBuf, codigo, agoraMs){
  const c = String(codigo == null ? '' : codigo).replace(/\s+/g, '');
  if(!/^\d{6}$/.test(c)) return null;
  const atual = Math.floor((agoraMs == null ? Date.now() : agoraMs) / 1000 / 30);
  let achado = null;
  for(const k of [atual - 1, atual, atual + 1]){
    const esperado = totpCodigo(segredoBuf, k);
    if(crypto.timingSafeEqual(Buffer.from(esperado), Buffer.from(c)) && achado === null) achado = k;   // avalia as 3 janelas sempre
  }
  return achado;
}

function gerarSegredo(){ return crypto.randomBytes(20); }   // 160 bits (recomendado pela RFC 4226)

function montarUriOtpauth(segredoBuf, emissor, conta){
  const rotulo = encodeURIComponent(emissor + ':' + conta);
  return 'otpauth://totp/' + rotulo + '?secret=' + base32Codificar(segredoBuf) + '&issuer=' + encodeURIComponent(emissor) + '&algorithm=SHA1&digits=6&period=30';
}

/* ---- criptografia do segredo em repouso (AES-256-GCM) ---- */
function chaveMestra(){
  const bruto = process.env.TOTP_CHAVE;
  if(!bruto) return null;
  const buf = Buffer.from(bruto, /^[0-9a-fA-F]{64}$/.test(bruto) ? 'hex' : 'base64url');
  return buf.length === 32 ? buf : null;
}
function subchave(mestra, rotulo){ return Buffer.from(crypto.hkdfSync('sha256', mestra, Buffer.alloc(0), rotulo, 32)); }

function cifrar(segredoBuf, conta){
  const mestra = chaveMestra(); if(!mestra) throw new Error('TOTP_CHAVE ausente ou inválida');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', subchave(mestra, 'totp-segredo'), iv);
  c.setAAD(Buffer.from(conta));
  const ct = Buffer.concat([c.update(segredoBuf), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}
function decifrar(texto, conta){
  const mestra = chaveMestra(); if(!mestra) throw new Error('TOTP_CHAVE ausente ou inválida');
  const [v, iv, tag, ct] = String(texto).split('.');
  if(v !== 'v1') throw new Error('formato desconhecido');
  const d = crypto.createDecipheriv('aes-256-gcm', subchave(mestra, 'totp-segredo'), Buffer.from(iv, 'base64url'));
  d.setAAD(Buffer.from(conta)); d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]);
}

/* ---- códigos de recuperação ---- */
function normalizarRecuperacao(codigo){ return String(codigo == null ? '' : codigo).toLowerCase().replace(/[^a-z0-9]/g, ''); }
function pareceCodigoRecuperacao(codigo){ return /^[0-9a-f]{15}$/.test(normalizarRecuperacao(codigo)); }
function hashRecuperacao(codigo){
  const mestra = chaveMestra(); if(!mestra) throw new Error('TOTP_CHAVE ausente ou inválida');
  return crypto.createHmac('sha256', subchave(mestra, 'totp-recuperacao')).update(normalizarRecuperacao(codigo)).digest('hex');
}
function gerarCodigosRecuperacao(qtd){
  const codigos = [];
  for(let i = 0; i < (qtd || 10); i++){ const h = crypto.randomBytes(8).toString('hex').slice(0, 15); codigos.push(h.slice(0,5) + '-' + h.slice(5,10) + '-' + h.slice(10)); }
  return { codigos, hashes: codigos.map(hashRecuperacao) };
}

module.exports = { base32Codificar, base32Decodificar, totpCodigo, totpContadorValido, gerarSegredo, montarUriOtpauth,
  cifrar, decifrar, chaveMestra, hashRecuperacao, gerarCodigosRecuperacao, pareceCodigoRecuperacao, normalizarRecuperacao };
