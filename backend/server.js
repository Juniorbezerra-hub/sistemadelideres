/* Sistema de Evolução de Líderes — JR Telecom
 * Backend: Express + Supabase (Postgres via PostgREST + Storage) — funciona local e em serverless (Vercel).
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const { GoogleAuth } = require('google-auth-library');
const helmet = require('helmet');

/* Carregador mínimo de .env (sem dependência de pacote "dotenv") — lê backend/.env se existir.
   Na Vercel não existe esse arquivo; as variáveis vêm configuradas direto na plataforma. */
(function carregarEnv(){
  const caminho = path.join(__dirname, '.env');
  if(!fs.existsSync(caminho)) return;
  fs.readFileSync(caminho, 'utf8').split(/\r?\n/).forEach(linha=>{
    if(!linha || linha.trim().startsWith('#')) return;
    const idx = linha.indexOf('=');
    if(idx===-1) return;
    const chave = linha.slice(0,idx).trim();
    const valor = linha.slice(idx+1);
    if(!(chave in process.env)) process.env[chave] = valor;
  });
})();

const PORTA = process.env.PORT || 3800;
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const BUCKET_FOTOS = 'fotos';

const USUARIO = process.env.ADMIN_USUARIO;
const SENHA_HASH = process.env.ADMIN_SENHA_HASH;   // scrypt$N$r$p$sal$hash (gerado por backend/gerar-hash-senha.js)
const SENHA = process.env.ADMIN_SENHA;             // legado (texto puro) — só usado se não houver ADMIN_SENHA_HASH
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
[
  ['ADMIN_USUARIO', USUARIO], ['SESSION_SECRET', SESSION_SECRET],
  ['SUPABASE_URL', SUPABASE_URL], ['SUPABASE_SERVICE_ROLE_KEY', SUPABASE_SERVICE_ROLE_KEY]
].forEach(([nome,valor])=>{
  if(!valor){
    console.error('ERRO: defina '+nome+' no backend/.env (local) ou nas variáveis de ambiente da plataforma (produção) antes de iniciar o servidor.');
    process.exit(1);
  }
});
if(!SENHA_HASH && !SENHA){
  console.error('ERRO: defina ADMIN_SENHA_HASH (recomendado) ou ADMIN_SENHA antes de iniciar o servidor.');
  process.exit(1);
}
if(!SENHA_HASH) console.warn('AVISO: usando ADMIN_SENHA em texto puro. Troque por ADMIN_SENHA_HASH (node backend/gerar-hash-senha.js).');
if(SESSION_SECRET.length < 32){
  console.error('ERRO: SESSION_SECRET precisa ter pelo menos 32 caracteres.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession:false } });

/* ---------------- AUTENTICAÇÃO ----------------
   O cookie `sel_auth` carrega só o id da sessão (sid) assinado com HMAC. A sessão de verdade vive na
   tabela `sessoes` do Supabase: dá pra revogar (logout de verdade), expira por inatividade e por
   tempo máximo. Funciona em serverless porque não depende de memória do processo. Falha fechado:
   se o banco não responder, ninguém entra. */
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSAO_MAX_MIN = 12*60;      // tempo máximo absoluto
const SESSAO_OCIOSA_MIN = 120;     // expira depois de 2h sem nenhuma requisição

function assinar(valor){
  return crypto.createHmac('sha256', SESSION_SECRET).update(valor).digest('base64url');
}
function iguais(a, b){
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function ipDoRequest(req){
  const h = req.headers;
  let ip = String(h['x-vercel-forwarded-for'] || h['x-real-ip'] || (h['x-forwarded-for']||'').split(',')[0] || (req.socket && req.socket.remoteAddress) || 'desconhecido').trim();
  if(ip.includes(':') && !ip.includes('.')) ip = ip.split(':').slice(0,4).join(':'); // IPv6: agrupa pelo prefixo /64
  return ip.slice(0,64);
}
function lerCookies(req){
  const cabecalho = req.headers.cookie || '';
  const mapa = {};
  cabecalho.split(';').forEach(par=>{
    const idx = par.indexOf('=');
    if(idx===-1) return;
    const nome = par.slice(0,idx).trim();
    const bruto = par.slice(idx+1).trim();
    try{ mapa[nome] = decodeURIComponent(bruto); }catch(e){ mapa[nome] = bruto; }
  });
  return mapa;
}
function montarSetCookie(nome, valor, maxAgeSeg){
  let s = nome+'='+encodeURIComponent(valor)+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+maxAgeSeg;
  if(IS_PROD) s += '; Secure';
  return s;
}
function sidDoToken(token){
  if(typeof token !== 'string' || token.length > 200) return null;
  const i = token.indexOf('.');
  if(i < 1) return null;
  const sid = token.slice(0,i), assinatura = token.slice(i+1);
  const esperada = assinar(sid);
  if(assinatura.length !== esperada.length) return null;
  if(!crypto.timingSafeEqual(Buffer.from(assinatura), Buffer.from(esperada))) return null;
  return sid;
}
async function criarSessao(ip){
  const sid = crypto.randomBytes(24).toString('base64url');
  const { error } = await supabase.rpc('criar_sessao', { p_sid: sid, p_ttl_min: SESSAO_MAX_MIN, p_ip: ip });
  if(error) throw error;
  return sid+'.'+assinar(sid);
}
async function sessaoValida(req){
  const sid = sidDoToken(lerCookies(req).sel_auth);
  if(!sid) return null;
  const { data, error } = await supabase.rpc('validar_sessao', { p_sid: sid, p_idle_min: SESSAO_OCIOSA_MIN });
  if(error) throw error;
  return data === true ? sid : null;
}
async function exigirLogin(req, res, next){
  try{
    const sid = await sessaoValida(req);
    if(sid){ req.sid = sid; return next(); }
  }catch(e){
    console.error('Erro ao validar sessão:', e.message);
    return res.status(503).json({ erro: 'Serviço temporariamente indisponível. Tente novamente.' });
  }
  res.status(401).json({ erro: 'Não autenticado.' });
}
async function auditar(evento, ip, detalhe){
  try{ await supabase.rpc('registrar_auditoria', { p_evento: evento, p_ip: ip || null, p_detalhe: detalhe || null }); }catch(e){}
}

/* Senha: hash scrypt com comparação em tempo constante. Usuário e senha são SEMPRE ambos verificados
   (sem atalho que revele qual dos dois errou). */
/* Senhas que já vazaram (ficaram públicas no histórico do git): nunca aceitas, mesmo que ainda estejam numa variável de ambiente. */
const SENHAS_COMPROMETIDAS = new Set(['bezerra01']);
function conferirScrypt(senha, hash){
  try{
    const [alg, N, r, p, salB64, hashB64] = String(hash).split('$');
    if(alg !== 'scrypt') return false;
    const esperado = Buffer.from(hashB64, 'base64');
    const candidato = crypto.scryptSync(senha, Buffer.from(salB64, 'base64'), esperado.length, { N:+N, r:+r, p:+p });
    return crypto.timingSafeEqual(candidato, esperado);
  }catch(e){ return false; }
}
/* O hash guardado no banco (tabela admin_credenciais) tem prioridade sobre as variáveis de ambiente: dá pra trocar a
   senha sem redeploy (node backend/definir-senha-admin.js). Se o banco não responder, o login falha fechado (503). */
async function verificarSenha(informada){
  const s = String(informada == null ? '' : informada).slice(0,256);
  const { data, error } = await supabase.from('admin_credenciais').select('senha_hash').eq('usuario', USUARIO).maybeSingle();
  if(error) throw error;
  if(data && data.senha_hash) return conferirScrypt(s, data.senha_hash);
  if(SENHA_HASH) return conferirScrypt(s, SENHA_HASH);
  if(SENHAS_COMPROMETIDAS.has(SENHA)) return false;
  return iguais(s, SENHA);
}
function verificarUsuario(informado){
  return iguais(String(informado == null ? '' : informado).slice(0,256), USUARIO);
}

/* ---------------- SEED (só roda se o banco nascer vazio) ---------------- */
const SEED_LIDERES = [
  {id:'L01', nome:'Adricelio Passos dos Santos',          equipe:'Interior — S.R. Nonato, Casa Nova, Sobradinho, Remanso, Santana do Sobrado, Campo Alegre, Petrolina', qtd:'20'},
  {id:'L02', nome:'Andre Alisson da Cruz Santos',         equipe:'Petrolina — Analista Técnico (coordena os 7 líderes) + 3 técnicos diretos', qtd:'3'},
  {id:'L03', nome:'Claudio Jose dos Passos Borges Junior',equipe:'Petrolina — Projeto, Comercial, Suporte, Remarcações', qtd:'20'},
  {id:'L04', nome:'Daniel de Brito Silva',                equipe:'Dormentes, Petrolina, KM 25', qtd:'20'},
  {id:'L05', nome:'Denilson Moises Luz de Oliveira',      equipe:'Petrolina — Qualidade / Operação Interna', qtd:'12'},
  {id:'L06', nome:'Francisco Dias Galvao',                equipe:'Petrolina', qtd:'15'},
  {id:'L07', nome:'Isaias Dias Ferreira',                 equipe:'Petrolina — Eventos', qtd:'7'},
  {id:'L08', nome:'Leonidas Batista da Costa',            equipe:'Petrolina — SEM técnicos vinculados no cadastro (verificar)', qtd:'0'}
];
/* Avaliação mensal histórica — extraída da planilha "Técnicos de Monitoramento" (guia de acompanhamento). */
const IMPORT_AVAL = [
{lid:'L05',mes:'2025-01',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.84,proc:100.0,pont:98.71}},
{lid:'L07',mes:'2025-01',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:66.67,vist:66.67,equi:98.6,proc:96.43,pont:97.43}},
{lid:'L05',mes:'2025-02',notas:{rela:98.57,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.46,proc:100.0,pont:97.86}},
{lid:'L07',mes:'2025-02',notas:{rela:100.0,orga:100.0,comp:99.29,comu:97.5,prod:100.0,vist:100.0,equi:99.45,proc:97.14,pont:96.57}},
{lid:'L05',mes:'2025-03',notas:{rela:99.35,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.35,proc:100.0,pont:93.29}},
{lid:'L07',mes:'2025-03',notas:{rela:98.71,orga:100.0,comp:100.0,comu:98.39,prod:80.0,vist:80.0,equi:99.17,proc:95.81,pont:97.81}},
{lid:'L01',mes:'2025-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:87.5,vist:100.0,equi:98.85,proc:100.0,pont:99.6}},
{lid:'L05',mes:'2025-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.49,proc:98.33,pont:97.6}},
{lid:'L07',mes:'2025-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,pont:97.6}},
{lid:'L01',mes:'2025-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.07,proc:99.03,pont:99.61}},
{lid:'L05',mes:'2025-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.49,proc:100.0,pont:96.45}},
{lid:'L07',mes:'2025-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.35,proc:94.52,pont:99.54}},
{lid:'L01',mes:'2025-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.55,proc:100.0,pont:98.0}},
{lid:'L05',mes:'2025-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.59,proc:98.06,pont:93.6}},
{lid:'L07',mes:'2025-06',notas:{rela:96.67,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:97.81,proc:100.0,pont:92.8}},
{lid:'L01',mes:'2025-07',notas:{rela:100.0,orga:100.0,comp:100.0,comu:98.39,prod:100.0,vist:100.0,equi:99.48,proc:100.0,pont:99.23}},
{lid:'L05',mes:'2025-07',notas:{rela:95.16,orga:99.03,comp:100.0,comu:98.39,prod:100.0,vist:100.0,equi:99.51,proc:98.39,pont:91.87}},
{lid:'L07',mes:'2025-07',notas:{rela:95.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.54,proc:99.35,pont:73.94}},
{lid:'L01',mes:'2025-08',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.7,proc:100.0,pont:100.0}},
{lid:'L05',mes:'2025-08',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.66,proc:100.0,pont:47.74}},
{lid:'L07',mes:'2025-08',notas:{rela:98.33,orga:100.0,comp:100.0,comu:100.0,prod:80.0,vist:62.5,equi:99.31,proc:99.35,pont:90.71}},
{lid:'L01',mes:'2025-09',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.92,proc:99.03,pont:99.6}},
{lid:'L05',mes:'2025-09',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.16,proc:100.0,pont:86.8}},
{lid:'L07',mes:'2025-09',notas:{rela:96.77,orga:100.0,comp:100.0,comu:97.74,prod:100.0,vist:100.0,equi:99.2,proc:99.35,pont:90.0}},
{lid:'L01',mes:'2025-10',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.35,proc:100.0,pont:100.0}},
{lid:'L05',mes:'2025-10',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,proc:99.38,pont:99.29}},
{lid:'L07',mes:'2025-10',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,proc:99.35,pont:94.0}},
{lid:'L01',mes:'2025-11',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.31,proc:95.33,pont:100.0}},
{lid:'L03',mes:'2025-11',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.61,proc:100.0,pont:100.0}},
{lid:'L05',mes:'2025-11',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.37,proc:100.0,pont:97.42}},
{lid:'L07',mes:'2025-11',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:93.6}},
{lid:'L01',mes:'2025-12',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.14,proc:100.0,pont:100.0}},
{lid:'L03',mes:'2025-12',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:42.86,vist:76.92,equi:99.48,proc:100.0,pont:99.23}},
{lid:'L05',mes:'2025-12',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.3,proc:96.77,pont:99.23}},
{lid:'L07',mes:'2025-12',notas:{rela:90.32,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:93.42}},
{lid:'L01',mes:'2026-01',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,equi:96.23,proc:100.0,pont:100.0}},
{lid:'L03',mes:'2026-01',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:97.86,proc:100.0,pont:99.23}},
{lid:'L05',mes:'2026-01',notas:{rela:95.16,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:93.1,proc:100.0,pont:89.94}},
{lid:'L07',mes:'2026-01',notas:{rela:83.87,orga:100.0,comp:100.0,comu:100.0,proc:100.0,pont:93.03}},
{lid:'L01',mes:'2026-02',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.3,proc:99.0,pont:87.5}},
{lid:'L03',mes:'2026-02',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.69,proc:100.0,pont:99.57}},
{lid:'L05',mes:'2026-02',notas:{rela:78.57,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.56,proc:98.21,pont:99.57}},
{lid:'L07',mes:'2026-02',notas:{rela:96.43,orga:100.0,comp:100.0,comu:100.0,proc:100.0,pont:98.29}},
{lid:'L01',mes:'2026-03',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.4,proc:99.03,pont:99.6}},
{lid:'L02',mes:'2026-03',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.81,proc:100.0,pont:97.18}},
{lid:'L03',mes:'2026-03',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:80.0,equi:98.21,proc:100.0,pont:97.18}},
{lid:'L05',mes:'2026-03',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.76,proc:100.0,pont:98.78}},
{lid:'L07',mes:'2026-03',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:91.56}},
{lid:'L01',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:98.3,prod:100.0,vist:100.0,equi:98.64,proc:100.0,pont:99.6}},
{lid:'L02',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:99.7,vist:99.3,equi:99.16,proc:100.0,pont:97.18}},
{lid:'L03',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:99.26}},
{lid:'L04',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:92.34}},
{lid:'L05',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.84,proc:100.0,pont:97.98}},
{lid:'L06',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:99.7,vist:99.3,equi:98.26,proc:100.0,pont:92.34}},
{lid:'L07',mes:'2026-04',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:40.0}},
{lid:'L08',mes:'2026-04',notas:{rela:100.0,orga:95.0,comp:100.0,comu:95.0,prod:100.0,vist:100.0,equi:97.39,proc:98.3,pont:93.15}},
{lid:'L01',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.37,proc:99.33,pont:99.6}},
{lid:'L02',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.07,proc:98.92,pont:100.0}},
{lid:'L03',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.55,proc:98.18,pont:82.61}},
{lid:'L04',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.99,proc:99.33,pont:98.79}},
{lid:'L05',mes:'2026-05',notas:{rela:96.67,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.84,proc:100.0,pont:98.79}},
{lid:'L06',mes:'2026-05',notas:{rela:97.65,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:98.39}},
{lid:'L07',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:99.67,comu:100.0,prod:100.0,vist:96.67,equi:100.0,proc:100.0,pont:97.28}},
{lid:'L08',mes:'2026-05',notas:{rela:100.0,orga:100.0,comp:100.0,comu:96.67,prod:100.0,vist:98.33,equi:100.0,proc:96.67,pont:98.39}},
{lid:'L01',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.62,proc:100.0,pont:99.17}},
{lid:'L02',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:98.48}},
{lid:'L03',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.42,proc:100.0,pont:84.2}},
{lid:'L04',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.75,proc:100.0,pont:99.17}},
{lid:'L05',mes:'2026-06',notas:{rela:98.33,orga:100.0,comp:99.31,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:100.0}},
{lid:'L06',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:97.5}},
{lid:'L07',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:99.33,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:98.75}},
{lid:'L08',mes:'2026-06',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:99.17}},
{lid:'L01',mes:'2026-07',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.26,proc:100.0,pont:99.6}},
{lid:'L02',mes:'2026-07',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:96.77,equi:99.39,proc:98.06,pont:96.77}},
{lid:'L03',mes:'2026-07',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:98.26,proc:98.39,pont:98.79}},
{lid:'L04',mes:'2026-07',notas:{rela:100.0,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.2,proc:98.39,pont:99.6}},
{lid:'L05',mes:'2026-07',notas:{rela:97.74,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:100.0,proc:100.0,pont:94.35}},
{lid:'L06',mes:'2026-07',notas:{rela:98.71,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.14,proc:96.77,pont:98.39}},
{lid:'L07',mes:'2026-07',notas:{rela:97.74,orga:100.0,comp:100.0,comu:100.0,prod:100.0,vist:100.0,equi:99.89,proc:98.39,pont:97.58}},
{lid:'L08',mes:'2026-07',notas:{rela:99.35,orga:100.0,comp:100.0,comu:100.0,prod:96.77,vist:100.0,equi:100.0,proc:100.0,pont:99.19}}
];

/* ---------------- VALIDAÇÃO DE ENTRADA ---------------- */
const RE_ID = /^[A-Za-z0-9_-]{1,40}$/;
const RE_MES = /^\d{4}-(0[1-9]|1[0-2])$/;
const RE_CHAVE = /^[A-Za-z0-9_-]{1,40}\|\d{4}-(0[1-9]|1[0-2])$/;
const RE_DATA = /^(\d{4}-\d{2}-\d{2})?$/;
const ehObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const txtOk = (v, max) => v == null || (typeof v === 'string' && v.length <= (max || 5000));
const numOk = (v, max) => v == null || (typeof v === 'number' && isFinite(v) && v >= 0 && v <= max);
function validarMapaNotas(m, max){
  if(m == null) return true;
  if(!ehObj(m)) return false;
  return Object.entries(m).every(([k, v]) => /^[A-Za-z0-9_]{1,30}$/.test(k) && numOk(v, max));
}
/* Devolve uma mensagem de erro (string) ou null se o estado é válido. */
function validarEstado(d){
  if(!ehObj(d)) return 'corpo inválido';
  if(!Array.isArray(d.lideres) || d.lideres.length === 0 || d.lideres.length > 200) return 'lista de líderes inválida';
  const ids = new Set();
  for(const l of d.lideres){
    if(!ehObj(l) || !RE_ID.test(String(l.id))) return 'id de líder inválido';
    if(ids.has(l.id)) return 'id de líder duplicado';
    ids.add(l.id);
    if(typeof l.nome !== 'string' || !l.nome.trim() || l.nome.length > 200) return 'nome de líder inválido';
    if(!txtOk(l.equipe, 500) || !txtOk(l.funcao, 200)) return 'texto de líder inválido';
    if(l.foto != null && !/^uploads\/fotos\/[A-Za-z0-9_.-]{1,120}$/.test(l.foto)) return 'foto inválida';
    if(l.qtd != null && !/^[0-9]{0,6}(\.[0-9]+)?$/.test(String(l.qtd))) return 'quantidade inválida';
  }
  const aval = d.aval == null ? {} : d.aval, pdi = d.pdi == null ? {} : d.pdi, sem = d.sem == null ? {} : d.sem;
  if(!ehObj(aval) || !ehObj(pdi) || !ehObj(sem)) return 'estrutura inválida';
  if(Object.keys(aval).length > 5000 || Object.keys(pdi).length > 2000 || Object.keys(sem).length > 5000) return 'volume de dados acima do limite';
  for(const [k, v] of Object.entries(aval)){
    if(!RE_CHAVE.test(k) || !ids.has(k.split('|')[0]) || !ehObj(v)) return 'avaliação inválida ('+k.slice(0,50)+')';
    if(!validarMapaNotas(v.notas, 100) || !validarMapaNotas(v.auto, 100)) return 'nota de avaliação inválida ('+k+')';
    if(!txtOk(v.forte) || !txtOk(v.melhorar) || !txtOk(v.meta) || !txtOk(v.obs)) return 'texto de avaliação inválido ('+k+')';
  }
  for(const [k, v] of Object.entries(pdi)){
    if(!RE_CHAVE.test(k) || !ids.has(k.split('|')[0]) || !ehObj(v)) return 'PDI inválido ('+k.slice(0,50)+')';
    if(!validarMapaNotas(v.notas, 10) || !validarMapaNotas(v.auto, 10)) return 'nota de PDI inválida ('+k+')';
    if(!txtOk(v.fortes) || !txtOk(v.desenvolver) || !txtOk(v.compromisso, 1000) || !RE_DATA.test(v.revisao || '')) return 'texto de PDI inválido ('+k+')';
    if(v.acoes != null){
      if(!Array.isArray(v.acoes) || v.acoes.length > 3) return 'ações de PDI inválidas ('+k+')';
      for(const a of v.acoes){
        if(!ehObj(a) || !txtOk(a.oque, 1000) || !txtOk(a.como, 1000) || !txtOk(a.resp, 300) || !RE_DATA.test(a.prazo || '')) return 'ação de PDI inválida ('+k+')';
      }
    }
  }
  for(const [k, v] of Object.entries(sem)){
    if(!RE_CHAVE.test(k) || !ids.has(k.split('|')[0]) || !ehObj(v)) return 'check-in inválido ('+k.slice(0,50)+')';
    for(const [sk, w] of Object.entries(v)){
      if(!/^s[1-5]$/.test(sk) || !ehObj(w)) return 'semana inválida ('+k+')';
      if(!txtOk(w.travou) || !txtOk(w.decisao) || !txtOk(w.compromisso) || (w.ok != null && typeof w.ok !== 'boolean')) return 'texto de check-in inválido ('+k+')';
    }
  }
  return null;
}

/* ---------------- SINCRONIZAÇÃO AO VIVO COM A PLANILHA GOOGLE (aba "Técnicos de Monitoramento") ----------------
   Lida via API Sheets v4 com Service Account (escopo readonly) — a planilha NÃO precisa ser pública,
   só compartilhada como "Leitor" com o client_email de GOOGLE_SERVICE_ACCOUNT_JSON. */
const PLANILHA_MONITORAMENTO_ID = '1szO-QkDju6DGtFSgLwvHoioO5hbN93uowlc0lu4ZqcM';
const PLANILHA_MONITORAMENTO_ABA = 'Técnicos de Monitoramento';
const MAPA_COLUNAS_PLANILHA = {
  'ENTREGA RELATÓRIOS': 'rela',
  'ORGANIZAÇÃO': 'orga',
  'COMPORTAMENTO': 'comp',
  'COMUNICAÇÃO': 'comu',
  'MONITORAMENTO': 'prod',
  'VISTORIA': 'vist',
  'DESEMPENHO EQUIPE': 'equi',
  'ERROS PROCEDIMENTO': 'proc',
  'PONTUALIDADE': 'pont'
};
function normalizarNome(s){
  return (s||'').normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/\s+/g,' ').trim().toUpperCase();
}
function parsePercentualBR(v){
  const s = String(v||'').trim();
  if(!s) return null;
  const n = parseFloat(s.replace('%','').replace(',','.'));
  return isNaN(n) ? null : Math.round(n*100)/100;
}
function credenciaisServiceAccount(){
  const bruto = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if(!bruto) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON não configurado — sem credencial não dá pra ler a planilha.');
  const credenciais = JSON.parse(bruto);
  if(credenciais.private_key) credenciais.private_key = credenciais.private_key.replace(/\\n/g, '\n');
  return credenciais;
}
async function tokenLeituraPlanilha(){
  const credenciais = credenciaisServiceAccount();
  const auth = new GoogleAuth({ credentials: credenciais, scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'] });
  const cliente = await auth.getClient();
  const { token } = await cliente.getAccessToken();
  return token;
}
async function buscarLinhasPlanilhaMonitoramento(){
  const token = await tokenLeituraPlanilha();
  const range = encodeURIComponent(PLANILHA_MONITORAMENTO_ABA);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${PLANILHA_MONITORAMENTO_ID}/values/${range}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if(resp.status === 403){
    const email = credenciaisServiceAccount().client_email;
    throw new Error('Sem permissão para ler a planilha. Compartilhe-a (botão "Compartilhar") com '+email+' como Leitor.');
  }
  if(!resp.ok){
    const corpo = await resp.text().catch(()=>'');
    throw new Error('Erro ao ler a planilha (HTTP '+resp.status+'). '+corpo.slice(0,200));
  }
  const dados = await resp.json();
  const linhasBrutas = dados.values || [];
  if(!linhasBrutas.length) return [];
  const cabecalho = linhasBrutas[0];
  return linhasBrutas.slice(1).map(linha=>{
    const obj = {};
    cabecalho.forEach((nome,i)=> obj[nome]=linha[i]);
    return obj;
  });
}
async function sincronizarPlanilhaMonitoramento(){
  const linhas = await buscarLinhasPlanilhaMonitoramento();
  const { data: lideresAtuais, error: erroLideres } = await supabase.from('lideres').select('id,nome');
  if(erroLideres) throw erroLideres;
  const mapaPorNome = new Map((lideresAtuais||[]).map(l => [normalizarNome(l.nome), l.id]));
  /* Em memória: a última linha da planilha vence (mesmo comportamento de antes). Depois vai tudo numa
     única chamada ao banco (função aplicar_sync_planilha) — só grava o que de fato mudou. */
  const notas = new Map(), funcoes = new Map(), mesesLideresAtingidos = new Set();
  let linhasAplicadas = 0, ignoradas = 0;
  for(const row of linhas){
    const nomeCel = row['TEC DE MONITORAMENTO'];
    const dataCel = row['DATA'];
    if(!nomeCel || !dataCel) continue;
    const lid = mapaPorNome.get(normalizarNome(nomeCel));
    if(!lid){ ignoradas++; continue; }
    const partes = dataCel.split('/');
    if(partes.length !== 3) continue;
    const mes = partes[2] + '-' + partes[1].padStart(2,'0');
    if(!RE_MES.test(mes)) continue;
    let mudou = false;
    for(const [coluna,indicador] of Object.entries(MAPA_COLUNAS_PLANILHA)){
      const valor = parsePercentualBR(row[coluna]);
      if(valor==null || valor < 0 || valor > 100) continue;
      notas.set(lid+'|'+mes+'|'+indicador, { lider_id: lid, mes, indicador, gestor: valor });
      mudou = true;
    }
    if(row['FUNÇÃO'] && row['FUNÇÃO'].trim()) funcoes.set(lid, { lider_id: lid, funcao: row['FUNÇÃO'].trim().slice(0,200) });
    if(mudou){ mesesLideresAtingidos.add(lid+'|'+mes); linhasAplicadas++; }
  }
  const { data, error } = await supabase.rpc('aplicar_sync_planilha', { p_notas: [...notas.values()], p_funcoes: [...funcoes.values()] });
  if(error) throw error;
  return { linhasAplicadas, mesesAtingidos: mesesLideresAtingidos.size, ignoradas, alteracoes: data };
}

/* Preenche só o que estiver vazio (não sobrescreve nota já lançada manualmente) — mesmo comportamento
   da versão anterior (SQLite). Só roda no seed inicial (banco vazio) ou pelo botão "Importar histórico". */
async function aplicarHistoricoMonitoramento(){
  const { data: lideresAtuais } = await supabase.from('lideres').select('id');
  const idsExistentes = new Set((lideresAtuais||[]).map(r=>r.id));
  let novos=0, atualizados=0;
  for(const rec of IMPORT_AVAL){
    if(!idsExistentes.has(rec.lid)) continue;
    let mudouEsteMes=false;
    const { data: metaExistente } = await supabase.from('avaliacoes_meta').select('lider_id').eq('lider_id',rec.lid).eq('mes',rec.mes).maybeSingle();
    for(const [ind,val] of Object.entries(rec.notas)){
      const { data: atual } = await supabase.from('avaliacoes_notas').select('gestor').eq('lider_id',rec.lid).eq('mes',rec.mes).eq('indicador',ind).maybeSingle();
      if(!atual){
        await supabase.from('avaliacoes_notas').insert({ lider_id:rec.lid, mes:rec.mes, indicador:ind, gestor:val, auto:null });
        mudouEsteMes=true;
      } else if(atual.gestor==null){
        await supabase.from('avaliacoes_notas').update({ gestor:val }).eq('lider_id',rec.lid).eq('mes',rec.mes).eq('indicador',ind);
        mudouEsteMes=true;
      }
    }
    if(!metaExistente){
      await supabase.from('avaliacoes_meta').insert({ lider_id:rec.lid, mes:rec.mes, forte:'', melhorar:'', meta:'', obs:'' });
    }
    if(mudouEsteMes){ if(metaExistente) atualizados++; else novos++; }
  }
  return {novos, atualizados};
}

async function rodarSeedInicial(){
  const { error } = await supabase.from('lideres').insert(SEED_LIDERES.map(l=>({ id:l.id, nome:l.nome, equipe:l.equipe, qtd:l.qtd })));
  if(error) throw error;
  await aplicarHistoricoMonitoramento();
  await supabase.from('meta').upsert([{ chave:'avalImportado', valor:'1' }, { chave:'seed_aplicado', valor:'1' }]);
}

/* ---------------- ESTADO: monta/desmonta o objeto que o front-end usa ---------------- */
async function montarEstado(){
  const [lideresR, notasAvalR, metaAvalR, notasPdiR, metaPdiR, semanalR, metaR] = await Promise.all([
    supabase.from('lideres').select('*').order('nome'),
    supabase.from('avaliacoes_notas').select('*'),
    supabase.from('avaliacoes_meta').select('*'),
    supabase.from('pdi_notas').select('*'),
    supabase.from('pdi_meta').select('*'),
    supabase.from('semanal').select('*'),
    supabase.from('meta').select('*'),
  ]);
  for(const r of [lideresR, notasAvalR, metaAvalR, notasPdiR, metaPdiR, semanalR, metaR]){
    if(r.error) throw r.error;
  }
  const aval = {};
  (notasAvalR.data||[]).forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    aval[k] = aval[k] || {notas:{}, auto:{}, forte:'', melhorar:'', meta:'', obs:''};
    if(row.gestor!=null) aval[k].notas[row.indicador]=row.gestor;
    if(row.auto!=null) aval[k].auto[row.indicador]=row.auto;
  });
  (metaAvalR.data||[]).forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    aval[k] = aval[k] || {notas:{}, auto:{}};
    aval[k].forte=row.forte||''; aval[k].melhorar=row.melhorar||''; aval[k].meta=row.meta||''; aval[k].obs=row.obs||'';
  });
  const pdi = {};
  (notasPdiR.data||[]).forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    pdi[k] = pdi[k] || {notas:{}, auto:{}, acoes:[{},{},{}]};
    if(row.gestor!=null) pdi[k].notas[row.criterio]=row.gestor;
    if(row.auto!=null) pdi[k].auto[row.criterio]=row.auto;
  });
  (metaPdiR.data||[]).forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    pdi[k] = pdi[k] || {notas:{}, auto:{}};
    pdi[k].fortes=row.fortes||''; pdi[k].desenvolver=row.desenvolver||'';
    pdi[k].acoes = row.acoes || [{},{},{}];
    pdi[k].revisao=row.revisao||''; pdi[k].compromisso=row.compromisso||'';
  });
  const sem = {};
  (semanalR.data||[]).forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    sem[k] = sem[k] || {};
    sem[k]['s'+row.semana] = {travou:row.travou||'', decisao:row.decisao||'', compromisso:row.compromisso||'', ok: !!row.ok};
  });
  const metaMap = {};
  (metaR.data||[]).forEach(r=> metaMap[r.chave]=r.valor);
  return { lideres: lideresR.data||[], aval, sem, pdi, avalImportado: metaMap.avalImportado==='1', pctV2:true, versao: parseInt(metaMap.estado_versao||'0', 10) || 0 };
}

/* ---------------- FOTO DO LÍDER (Supabase Storage) ---------------- */
const MIME_PARA_EXT = { 'image/jpeg':'jpg', 'image/png':'png', 'image/webp':'webp', 'image/gif':'gif' };
/* Confere os bytes iniciais do arquivo — não confia no tipo declarado pelo navegador. */
function tipoRealDaImagem(b){
  if(b.length < 12) return null;
  if(b[0]===0xFF && b[1]===0xD8 && b[2]===0xFF) return 'image/jpeg';
  if(b.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]))) return 'image/png';
  if(b.subarray(0,4).toString('latin1') === 'GIF8') return 'image/gif';
  if(b.subarray(0,4).toString('latin1') === 'RIFF' && b.subarray(8,12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}
async function removerFotosAntigas(liderId){
  const { data } = await supabase.storage.from(BUCKET_FOTOS).list('', { search: liderId+'-' });
  const nomes = (data||[]).filter(f=>f.name.startsWith(liderId+'-')).map(f=>f.name);
  if(nomes.length) await supabase.storage.from(BUCKET_FOTOS).remove(nomes);
}

/* ---------------- SERVIDOR HTTP ---------------- */
const app = express();
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { useDefaults: false, directives: {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],   // a interface usa handlers inline (onclick); o resto do CSP segue restrito
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'blob:'],
    'connect-src': ["'self'"],
    'font-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"]
  } },
  referrerPolicy: { policy: 'no-referrer' },
  frameguard: { action: 'deny' },
  crossOriginEmbedderPolicy: false,
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use('/api/login', express.json({ limit: '2kb' }));
app.use(express.json({ limit: '6mb' }));

app.post('/api/login', async (req, res) => {
  const ip = ipDoRequest(req);
  const chave = 'ip:'+ip;
  const bloqueadoAte = ate => {
    const seg = Math.max(1, Math.ceil((new Date(ate).getTime() - Date.now())/1000));
    res.setHeader('Retry-After', String(seg));
    return res.status(429).json({ erro: 'Muitas tentativas. Aguarde alguns minutos e tente de novo.', segundos: seg });
  };
  try{
    const { data: bloqueio, error: erroBloqueio } = await supabase.rpc('checar_bloqueio_login', { p_chave: chave });
    if(erroBloqueio) throw erroBloqueio;
    if(bloqueio) return bloqueadoAte(bloqueio);

    const { usuario, senha } = req.body || {};
    const okUsuario = verificarUsuario(usuario), okSenha = await verificarSenha(senha);   // sempre os dois
    if(okUsuario && okSenha){
      const token = await criarSessao(ip);
      await supabase.rpc('limpar_falhas_login', { p_chave: chave });
      await auditar('login_ok', ip);
      res.setHeader('Set-Cookie', montarSetCookie('sel_auth', token, SESSAO_MAX_MIN*60));
      return res.json({ ok:true });
    }
    const { data: ate, error: erroFalha } = await supabase.rpc('registrar_falha_login', { p_chave: chave, p_max: 5, p_janela_min: 15, p_bloqueio_min: 15 });
    if(erroFalha) throw erroFalha;
    await auditar('login_falha', ip, ate ? 'bloqueado' : '');
    if(ate) return bloqueadoAte(ate);
    res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
  }catch(e){
    console.error('Erro no login:', e.message);
    res.status(503).json({ erro: 'Serviço temporariamente indisponível. Tente novamente.' });
  }
});
app.post('/api/logout', async (req, res) => {
  try{
    const sid = sidDoToken(lerCookies(req).sel_auth);
    if(sid){
      await supabase.rpc('revogar_sessao', { p_sid: sid });
      await auditar('logout', ipDoRequest(req));
    }
  }catch(e){ console.error('Erro no logout:', e.message); }
  res.setHeader('Set-Cookie', montarSetCookie('sel_auth', '', 0));
  res.json({ ok:true });
});
app.get('/api/me', async (req, res) => {
  try{
    res.json({ autenticado: !!(await sessaoValida(req)) });
  }catch(e){
    console.error('Erro ao validar sessão:', e.message);
    res.status(503).json({ erro: 'Serviço temporariamente indisponível.' });
  }
});

/* Lista padrão dos líderes (botão "Restaurar lista de líderes"). Fica aqui, atrás do login — antes estava embutida
   no HTML público e expunha nomes e equipes de funcionários a qualquer visitante. */
app.get('/api/lideres-padrao', exigirLogin, (req, res) => {
  res.json(SEED_LIDERES.map(l => ({ id: l.id, nome: l.nome, equipe: l.equipe, qtd: l.qtd })));
});

app.get('/api/estado', exigirLogin, async (req, res) => {
  try{
    res.json(await montarEstado());
  }catch(e){
    console.error('Erro ao ler estado:', e);
    res.status(500).json({ erro:'Erro ao ler dados do banco.' });
  }
});
/* Salvamento: valida a forma dos dados, exige a versão em que o cliente se baseou (evita que uma aba/aparelho
   desatualizado sobrescreva dados mais novos) e recusa reduções de registros sem confirmação explícita.
   O banco tira um snapshot antes de qualquer redução e a cada 10 min de uso. */
app.post('/api/estado', exigirLogin, async (req, res) => {
  const ip = ipDoRequest(req);
  const d = req.body;
  const erroValidacao = validarEstado(d);
  if(erroValidacao){
    await auditar('salvar_rejeitado', ip, erroValidacao);
    return res.status(400).json({ erro: 'Dados inválidos: '+erroValidacao, codigo: 'payload_invalido' });
  }
  if(!Number.isInteger(d.baseVersao)){
    return res.status(400).json({ erro: 'Sua página está desatualizada. Recarregue com Ctrl+F5 e tente de novo.', codigo: 'sem_versao' });
  }
  const permitirReducao = d.permitirReducao === true;
  try{
    const payload = { lideres: d.lideres, aval: d.aval || {}, sem: d.sem || {}, pdi: d.pdi || {}, avalImportado: !!d.avalImportado };
    const { data, error } = await supabase.rpc('salvar_estado_v2', { payload, p_base_versao: d.baseVersao, p_permitir_reducao: permitirReducao });
    if(error){
      const msg = error.message || '';
      if(msg.includes('conflito_versao')){
        await auditar('salvar_conflito', ip);
        return res.status(409).json({ erro: 'Os dados foram alterados em outro lugar. Recarregue a página para ver a versão mais recente.', codigo: 'conflito_versao' });
      }
      if(msg.includes('reducao_suspeita')){
        await auditar('salvar_bloqueado_reducao', ip);
        return res.status(422).json({ erro: 'Salvamento bloqueado: ele apagaria registros sem confirmação. Recarregue a página.', codigo: 'reducao_suspeita' });
      }
      if(msg.includes('payload_invalido')) return res.status(400).json({ erro: 'Dados inválidos.', codigo: 'payload_invalido' });
      throw error;
    }
    if(permitirReducao) await auditar('salvar_reducao_autorizada', ip, 'lideres='+d.lideres.length);
    res.json({ ok:true, versao: data });
  }catch(e){
    console.error('Erro ao salvar estado:', e);
    res.status(500).json({ erro:'Erro ao salvar no banco de dados.' });
  }
});
app.post('/api/importar-historico', exigirLogin, async (req, res) => {
  try{
    res.json(await aplicarHistoricoMonitoramento());
  }catch(e){
    console.error('Erro ao importar histórico:', e);
    res.status(500).json({ erro:'Erro ao importar histórico.' });
  }
});
app.post('/api/sincronizar-planilha', exigirLogin, async (req, res) => {
  try{
    const r = await sincronizarPlanilhaMonitoramento();
    await supabase.from('meta').upsert({ chave:'ultima_sync', valor: new Date().toISOString() });
    await auditar('sincronizar_planilha', ipDoRequest(req), JSON.stringify(r.alteracoes||{}));
    res.json({ ok:true, ...r });
  }catch(e){
    console.error('Erro ao sincronizar com a planilha:', e.message);
    const conhecido = /^(Sem permissão|GOOGLE_SERVICE_ACCOUNT_JSON|Erro ao ler a planilha)/.test(e.message || '');
    res.status(502).json({ erro: conhecido ? e.message : 'Erro ao sincronizar com a planilha.' });
  }
});

app.post('/api/lideres/:id/foto', exigirLogin, async (req, res) => {
  const { id } = req.params;
  if(!RE_ID.test(id)) return res.status(400).json({ erro: 'Identificador inválido.' });
  const { data: lider } = await supabase.from('lideres').select('id').eq('id', id).maybeSingle();
  if(!lider) return res.status(404).json({ erro: 'Líder não encontrado.' });
  const m = /^data:(image\/[a-zA-Z+]+);base64,([A-Za-z0-9+/=]+)$/.exec(req.body && req.body.dataUrl || '');
  if(!m) return res.status(400).json({ erro: 'Imagem inválida.' });
  if(!MIME_PARA_EXT[m[1]]) return res.status(400).json({ erro: 'Formato de imagem não suportado. Use JPG, PNG, WEBP ou GIF.' });
  const buffer = Buffer.from(m[2], 'base64');
  if(buffer.length > 3*1024*1024) return res.status(400).json({ erro: 'Imagem maior que 3MB.' });
  const tipoReal = tipoRealDaImagem(buffer);
  if(!tipoReal) return res.status(400).json({ erro: 'O arquivo não é uma imagem válida.' });
  try{
    await removerFotosAntigas(id);
    const nomeArquivo = id+'-'+Date.now()+'.'+MIME_PARA_EXT[tipoReal];
    const { error: erroUpload } = await supabase.storage.from(BUCKET_FOTOS).upload(nomeArquivo, buffer, { contentType: tipoReal });
    if(erroUpload) throw erroUpload;
    const caminho = 'uploads/fotos/'+nomeArquivo;
    const { error: erroUpdate } = await supabase.from('lideres').update({ foto: caminho }).eq('id', id);
    if(erroUpdate) throw erroUpdate;
    await supabase.rpc('bump_versao');
    res.json({ ok:true, foto: caminho });
  }catch(e){
    console.error('Erro ao salvar foto:', e);
    res.status(500).json({ erro:'Erro ao salvar a foto.' });
  }
});
app.delete('/api/lideres/:id/foto', exigirLogin, async (req, res) => {
  const { id } = req.params;
  if(!RE_ID.test(id)) return res.status(400).json({ erro: 'Identificador inválido.' });
  try{
    await removerFotosAntigas(id);
    await supabase.from('lideres').update({ foto: null }).eq('id', id);
    await supabase.rpc('bump_versao');
    res.json({ ok:true });
  }catch(e){
    console.error('Erro ao remover foto:', e);
    res.status(500).json({ erro:'Erro ao remover a foto.' });
  }
});

/* Serve a foto a partir do Storage privado do Supabase, exigindo login — mantém a mesma URL
   (/uploads/fotos/<arquivo>) que o front-end já usa, só troca o disco local pelo bucket. */
app.get('/uploads/fotos/:nome', exigirLogin, async (req, res) => {
  if(!/^[A-Za-z0-9_-]{1,60}\.(jpg|png|webp|gif)$/.test(req.params.nome)) return res.status(404).end();
  const { data, error } = await supabase.storage.from(BUCKET_FOTOS).download(req.params.nome);
  if(error || !data) return res.status(404).end();
  const buffer = Buffer.from(await data.arrayBuffer());
  res.setHeader('Content-Type', data.type || 'application/octet-stream');
  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.send(buffer);
});

app.use(express.static(FRONTEND_DIR));

app.use((err, req, res, next) => {
  if(err && err.type === 'entity.too.large') return res.status(413).json({ erro: 'Requisição grande demais.' });
  if(err instanceof SyntaxError && err.status === 400) return res.status(400).json({ erro: 'Requisição inválida.' });
  console.error('Erro não tratado:', err && err.message);
  res.status(500).json({ erro: 'Erro interno.' });
});

async function lerMeta(chaves){
  const { data, error } = await supabase.from('meta').select('chave,valor').in('chave', chaves);
  if(error) throw error;
  const m = {};
  (data||[]).forEach(r => { m[r.chave] = r.valor; });
  return m;
}
async function iniciar(){
  const { count, error } = await supabase.from('lideres').select('*', { count:'exact', head:true });
  if(error){
    console.error('Não foi possível conectar ao Supabase:', error.message);
    if(require.main === module) process.exit(1);
    return;
  }
  const meta = await lerMeta(['seed_aplicado', 'ultima_sync']);
  if(count === 0){
    if(meta.seed_aplicado === '1'){
      /* Nunca recria os dados sozinho: um banco vazio DEPOIS de já ter tido dados é sinal de perda,
         e o cadastro inicial esconderia isso. Restaurar: select public.restaurar_snapshot(<id>). */
      console.error('ALERTA: a tabela de líderes está VAZIA mas o cadastro inicial já foi aplicado antes — possível perda de dados. Nada foi recriado. Restaure um snapshot (tabela estado_snapshots).');
      await auditar('alerta_banco_vazio');
      return;
    }
    console.log('Banco novo — aplicando cadastro inicial dos 8 líderes e histórico da planilha de Monitoramento...');
    await rodarSeedInicial();
  }
  /* Sincroniza com a planilha no máximo 1 vez por hora (cada partida a frio na Vercel chamaria isso). */
  const ultima = Date.parse(meta.ultima_sync || '') || 0;
  if(Date.now() - ultima < 60*60*1000){
    console.log('Sincronização com a planilha pulada (a última foi há menos de 1h).');
    return;
  }
  await supabase.from('meta').upsert({ chave:'ultima_sync', valor: new Date().toISOString() });
  sincronizarPlanilhaMonitoramento()
    .then(r => console.log('Sincronização com a planilha de Monitoramento: '+r.linhasAplicadas+' lançamento(s) lido(s), '+r.ignoradas+' linha(s) ignorada(s); alterações no banco: '+JSON.stringify(r.alteracoes)))
    .catch(e => console.error('Sincronização com a planilha falhou (o sistema segue funcionando com os dados que já tem):', e.message));
}

if(require.main === module){
  iniciar().then(()=>{
    app.listen(PORTA, '127.0.0.1', () => {
      console.log('=======================================================');
      console.log(' Sistema de Evolução de Líderes — JR Telecom');
      console.log(' Banco de dados: Supabase ('+SUPABASE_URL+')');
      console.log(' Acesse em:      http://localhost:'+PORTA);
      console.log('=======================================================');
    });
  });
}else{
  iniciar().catch(e=>console.error('Erro na inicialização (serverless):', e.message));
}

module.exports = app;
