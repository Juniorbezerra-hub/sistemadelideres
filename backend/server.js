/* Sistema de Evolução de Líderes — JR Telecom
 * Backend: Express + Supabase (Postgres via PostgREST + Storage) — funciona local e em serverless (Vercel).
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const { GoogleAuth } = require('google-auth-library');

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
const SENHA = process.env.ADMIN_SENHA;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
[
  ['ADMIN_USUARIO', USUARIO], ['ADMIN_SENHA', SENHA], ['SESSION_SECRET', SESSION_SECRET],
  ['SUPABASE_URL', SUPABASE_URL], ['SUPABASE_SERVICE_ROLE_KEY', SUPABASE_SERVICE_ROLE_KEY]
].forEach(([nome,valor])=>{
  if(!valor){
    console.error('ERRO: defina '+nome+' no backend/.env (local) ou nas variáveis de ambiente da plataforma (produção) antes de iniciar o servidor.');
    process.exit(1);
  }
});

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession:false } });

/* ---------------- AUTENTICAÇÃO: cookie assinado, sem estado no servidor ----------------
   Substitui express-session (MemoryStore) porque serverless (Vercel) não tem processo
   contínuo nem memória compartilhada entre instâncias — um cookie assinado (HMAC) resolve
   isso sem precisar de tabela de sessão nem de outro serviço. */
const DURACAO_SESSAO_MS = 1000*60*60*12; // 12h
function assinar(valor){
  return crypto.createHmac('sha256', SESSION_SECRET).update(valor).digest('base64url');
}
function criarTokenAuth(){
  const payload = Buffer.from(JSON.stringify({ autenticado:true, exp: Date.now()+DURACAO_SESSAO_MS })).toString('base64url');
  return payload+'.'+assinar(payload);
}
function tokenValido(token){
  if(!token) return false;
  const [payload, assinatura] = token.split('.');
  if(!payload || !assinatura) return false;
  const esperada = assinar(payload);
  if(assinatura.length !== esperada.length) return false;
  if(!crypto.timingSafeEqual(Buffer.from(assinatura), Buffer.from(esperada))) return false;
  try{
    const dados = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return !!dados.autenticado && dados.exp > Date.now();
  }catch(e){ return false; }
}
function lerCookies(req){
  const cabecalho = req.headers.cookie || '';
  const mapa = {};
  cabecalho.split(';').forEach(par=>{
    const idx = par.indexOf('=');
    if(idx===-1) return;
    mapa[par.slice(0,idx).trim()] = decodeURIComponent(par.slice(idx+1).trim());
  });
  return mapa;
}
function montarSetCookie(nome, valor, maxAgeSeg){
  const PRODUCAO = process.env.NODE_ENV === 'production';
  let s = nome+'='+encodeURIComponent(valor)+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+maxAgeSeg;
  if(PRODUCAO) s += '; Secure';
  return s;
}
function exigirLogin(req, res, next){
  const cookies = lerCookies(req);
  if(tokenValido(cookies.sel_auth)) return next();
  res.status(401).json({ erro: 'Não autenticado.' });
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
  let linhasAplicadas=0, ignoradas=0;
  const mesesLideresAtingidos = new Set();
  for(const row of linhas){
    const nomeCel = row['TEC DE MONITORAMENTO'];
    const dataCel = row['DATA'];
    if(!nomeCel || !dataCel) continue;
    const lid = mapaPorNome.get(normalizarNome(nomeCel));
    if(!lid){ ignoradas++; continue; }
    const partes = dataCel.split('/');
    if(partes.length !== 3) continue;
    const mes = partes[2] + '-' + partes[1].padStart(2,'0');
    let mudou = false;
    for(const [coluna,indicador] of Object.entries(MAPA_COLUNAS_PLANILHA)){
      const valor = parsePercentualBR(row[coluna]);
      if(valor==null) continue;
      const { error } = await supabase.rpc('upsert_nota_gestor', { p_lider_id: lid, p_mes: mes, p_indicador: indicador, p_gestor: valor });
      if(error) throw error;
      mudou = true;
    }
    if(row['FUNÇÃO'] && row['FUNÇÃO'].trim()){
      await supabase.from('lideres').update({ funcao: row['FUNÇÃO'].trim() }).eq('id', lid);
    }
    if(mudou){
      const { data: metaExistente } = await supabase.from('avaliacoes_meta').select('lider_id').eq('lider_id',lid).eq('mes',mes).maybeSingle();
      if(!metaExistente){
        await supabase.from('avaliacoes_meta').insert({ lider_id:lid, mes, forte:'', melhorar:'', meta:'', obs:'' });
      }
      mesesLideresAtingidos.add(lid+'|'+mes);
      linhasAplicadas++;
    }
  }
  return { linhasAplicadas, mesesAtingidos: mesesLideresAtingidos.size, ignoradas };
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
  await supabase.rpc('upsert_meta_valor', { p_chave:'avalImportado', p_valor:'1' });
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
  return { lideres: lideresR.data||[], aval, sem, pdi, avalImportado: metaMap.avalImportado==='1', pctV2:true };
}

/* Delete-all + insert-all de tudo, numa única transação de banco (função Postgres `salvar_estado`)
   — garante que nunca fica um estado "pela metade" mesmo se a requisição cair no meio. */
async function salvarEstado(d){
  const { error } = await supabase.rpc('salvar_estado', { payload: d });
  if(error) throw error;
}

/* ---------------- FOTO DO LÍDER (Supabase Storage) ---------------- */
const MIME_PARA_EXT = { 'image/jpeg':'jpg', 'image/png':'png', 'image/webp':'webp', 'image/gif':'gif' };
async function removerFotosAntigas(liderId){
  const { data } = await supabase.storage.from(BUCKET_FOTOS).list('', { search: liderId+'-' });
  const nomes = (data||[]).filter(f=>f.name.startsWith(liderId+'-')).map(f=>f.name);
  if(nomes.length) await supabase.storage.from(BUCKET_FOTOS).remove(nomes);
}

/* ---------------- SERVIDOR HTTP ---------------- */
const app = express();
app.use(express.json({ limit: '10mb' }));

app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if(usuario===USUARIO && senha===SENHA){
    res.setHeader('Set-Cookie', montarSetCookie('sel_auth', criarTokenAuth(), DURACAO_SESSAO_MS/1000));
    return res.json({ ok:true });
  }
  res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', montarSetCookie('sel_auth', '', 0));
  res.json({ ok:true });
});
app.get('/api/me', (req, res) => {
  res.json({ autenticado: tokenValido(lerCookies(req).sel_auth) });
});

app.get('/api/estado', exigirLogin, async (req, res) => {
  try{
    res.json(await montarEstado());
  }catch(e){
    console.error('Erro ao ler estado:', e);
    res.status(500).json({ erro:'Erro ao ler dados do banco.' });
  }
});
app.post('/api/estado', exigirLogin, async (req, res) => {
  try{
    await salvarEstado(req.body || {});
    res.json({ ok:true });
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
    res.json({ ok:true, ...r });
  }catch(e){
    console.error('Erro ao sincronizar com a planilha:', e.message);
    res.status(502).json({ erro: e.message || 'Erro ao sincronizar com a planilha.' });
  }
});

app.post('/api/lideres/:id/foto', exigirLogin, async (req, res) => {
  const { id } = req.params;
  const { data: lider } = await supabase.from('lideres').select('id').eq('id', id).maybeSingle();
  if(!lider) return res.status(404).json({ erro: 'Líder não encontrado.' });
  const m = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(req.body && req.body.dataUrl || '');
  if(!m) return res.status(400).json({ erro: 'Imagem inválida.' });
  const ext = MIME_PARA_EXT[m[1]];
  if(!ext) return res.status(400).json({ erro: 'Formato de imagem não suportado. Use JPG, PNG, WEBP ou GIF.' });
  const buffer = Buffer.from(m[2], 'base64');
  if(buffer.length > 8*1024*1024) return res.status(400).json({ erro: 'Imagem maior que 8MB.' });
  try{
    await removerFotosAntigas(id);
    const nomeArquivo = id+'-'+Date.now()+'.'+ext;
    const { error: erroUpload } = await supabase.storage.from(BUCKET_FOTOS).upload(nomeArquivo, buffer, { contentType: m[1] });
    if(erroUpload) throw erroUpload;
    const caminho = 'uploads/fotos/'+nomeArquivo;
    const { error: erroUpdate } = await supabase.from('lideres').update({ foto: caminho }).eq('id', id);
    if(erroUpdate) throw erroUpdate;
    res.json({ ok:true, foto: caminho });
  }catch(e){
    console.error('Erro ao salvar foto:', e);
    res.status(500).json({ erro:'Erro ao salvar a foto.' });
  }
});
app.delete('/api/lideres/:id/foto', exigirLogin, async (req, res) => {
  const { id } = req.params;
  try{
    await removerFotosAntigas(id);
    await supabase.from('lideres').update({ foto: null }).eq('id', id);
    res.json({ ok:true });
  }catch(e){
    console.error('Erro ao remover foto:', e);
    res.status(500).json({ erro:'Erro ao remover a foto.' });
  }
});

/* Serve a foto a partir do Storage privado do Supabase, exigindo login — mantém a mesma URL
   (/uploads/fotos/<arquivo>) que o front-end já usa, só troca o disco local pelo bucket. */
app.get('/uploads/fotos/:nome', exigirLogin, async (req, res) => {
  const { data, error } = await supabase.storage.from(BUCKET_FOTOS).download(req.params.nome);
  if(error || !data) return res.status(404).end();
  const buffer = Buffer.from(await data.arrayBuffer());
  res.setHeader('Content-Type', data.type || 'application/octet-stream');
  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.send(buffer);
});

app.use(express.static(FRONTEND_DIR));

async function iniciar(){
  const { count, error } = await supabase.from('lideres').select('*', { count:'exact', head:true });
  if(error){
    console.error('Não foi possível conectar ao Supabase:', error.message);
    process.exit(1);
  }
  if(count===0){
    console.log('Banco novo — aplicando cadastro inicial dos 8 líderes e histórico da planilha de Monitoramento...');
    await rodarSeedInicial();
  }
  sincronizarPlanilhaMonitoramento()
    .then(r => console.log('Sincronização com a planilha de Monitoramento: '+r.linhasAplicadas+' lançamento(s) aplicado(s) em '+r.mesesAtingidos+' mês(es)/líder(es), '+r.ignoradas+' linha(s) ignorada(s) (nome não é líder cadastrado).'))
    .catch(e => console.error('Sincronização inicial com a planilha falhou (o sistema segue funcionando com os dados que já tem):', e.message));
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
