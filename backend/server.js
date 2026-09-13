/* Sistema de Evolução de Líderes — JR Telecom
 * Backend: Express + SQLite (node:sqlite, nativo do Node, sem dependência externa de banco).
 * Banco de dados físico: ..\dados.db (pasta "E:\sistema evolução de lideres", ao lado desta pasta backend).
 */
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const { DatabaseSync } = require('node:sqlite');
const { GoogleAuth } = require('google-auth-library');

/* Carregador mínimo de .env (sem dependência de pacote "dotenv") — lê backend/.env se existir. */
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

const PORTA = 3800;
const DB_PATH = path.join(__dirname, '..', 'dados.db');
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const FOTOS_DIR = path.join(UPLOADS_DIR, 'fotos');
fs.mkdirSync(FOTOS_DIR, { recursive: true });

const USUARIO = 'admin';
const SENHA = 'bezerra01';

/* ---------------- BANCO DE DADOS ---------------- */
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
CREATE TABLE IF NOT EXISTS lideres (
  id TEXT PRIMARY KEY,
  nome TEXT NOT NULL,
  equipe TEXT,
  qtd TEXT,
  foto TEXT,
  funcao TEXT
);
CREATE TABLE IF NOT EXISTS avaliacoes_notas (
  lider_id TEXT NOT NULL,
  mes TEXT NOT NULL,
  indicador TEXT NOT NULL,
  gestor REAL,
  auto REAL,
  PRIMARY KEY (lider_id, mes, indicador)
);
CREATE TABLE IF NOT EXISTS avaliacoes_meta (
  lider_id TEXT NOT NULL,
  mes TEXT NOT NULL,
  forte TEXT, melhorar TEXT, meta TEXT, obs TEXT,
  PRIMARY KEY (lider_id, mes)
);
CREATE TABLE IF NOT EXISTS pdi_notas (
  lider_id TEXT NOT NULL,
  mes TEXT NOT NULL,
  criterio TEXT NOT NULL,
  gestor REAL,
  auto REAL,
  PRIMARY KEY (lider_id, mes, criterio)
);
CREATE TABLE IF NOT EXISTS pdi_meta (
  lider_id TEXT NOT NULL,
  mes TEXT NOT NULL,
  fortes TEXT, desenvolver TEXT, acoes TEXT, revisao TEXT, compromisso TEXT,
  PRIMARY KEY (lider_id, mes)
);
CREATE TABLE IF NOT EXISTS semanal (
  lider_id TEXT NOT NULL,
  mes TEXT NOT NULL,
  semana INTEGER NOT NULL,
  travou TEXT, decisao TEXT, compromisso TEXT, ok INTEGER,
  PRIMARY KEY (lider_id, mes, semana)
);
CREATE TABLE IF NOT EXISTS meta (
  chave TEXT PRIMARY KEY,
  valor TEXT
);
`);

/* ---------------- SEED (só roda uma vez, se o banco nascer vazio) ---------------- */
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

/* Migração leve: adiciona colunas em bancos criados antes delas existirem. */
(function migrarColunasLideres(){
  const colunas = db.prepare("PRAGMA table_info(lideres)").all().map(c => c.name);
  if(!colunas.includes('foto')){
    db.exec('ALTER TABLE lideres ADD COLUMN foto TEXT');
  }
  if(!colunas.includes('funcao')){
    db.exec('ALTER TABLE lideres ADD COLUMN funcao TEXT');
  }
})();

function contarLideres(){
  return db.prepare('SELECT COUNT(*) AS n FROM lideres').get().n;
}
function rodarSeedInicial(){
  const insLider = db.prepare('INSERT INTO lideres (id,nome,equipe,qtd) VALUES (?,?,?,?)');
  db.exec('BEGIN');
  try{
    SEED_LIDERES.forEach(l => insLider.run(l.id, l.nome, l.equipe, l.qtd));
    db.exec('COMMIT');
  }catch(e){ db.exec('ROLLBACK'); throw e; }
  aplicarHistoricoMonitoramento();
  setMetaValor('avalImportado', '1');
}

/* Preenche só o que estiver vazio (não sobrescreve nota já lançada manualmente) — mesmo comportamento
   da função importarAvalHistorico() que existia no front antigo. */
function aplicarHistoricoMonitoramento(){
  const lideresExistentes = new Set(db.prepare('SELECT id FROM lideres').all().map(r=>r.id));
  const getNota = db.prepare('SELECT gestor FROM avaliacoes_notas WHERE lider_id=? AND mes=? AND indicador=?');
  const insNota = db.prepare('INSERT INTO avaliacoes_notas (lider_id,mes,indicador,gestor,auto) VALUES (?,?,?,?,NULL)');
  const updNota = db.prepare('UPDATE avaliacoes_notas SET gestor=? WHERE lider_id=? AND mes=? AND indicador=?');
  const garantirMeta = db.prepare(`INSERT INTO avaliacoes_meta (lider_id,mes,forte,melhorar,meta,obs)
    SELECT ?,?,'','','','' WHERE NOT EXISTS (SELECT 1 FROM avaliacoes_meta WHERE lider_id=? AND mes=?)`);
  let novos=0, atualizados=0;
  db.exec('BEGIN');
  try{
    IMPORT_AVAL.forEach(rec=>{
      if(!lideresExistentes.has(rec.lid)) return;
      let mudouEsteMes=false;
      const existiaMeta = db.prepare('SELECT 1 FROM avaliacoes_meta WHERE lider_id=? AND mes=?').get(rec.lid, rec.mes);
      Object.entries(rec.notas).forEach(([ind,val])=>{
        const atual = getNota.get(rec.lid, rec.mes, ind);
        if(!atual){ insNota.run(rec.lid, rec.mes, ind, val); mudouEsteMes=true; }
        else if(atual.gestor==null){ updNota.run(val, rec.lid, rec.mes, ind); mudouEsteMes=true; }
      });
      garantirMeta.run(rec.lid, rec.mes, rec.lid, rec.mes);
      if(mudouEsteMes){ if(existiaMeta) atualizados++; else novos++; }
    });
    db.exec('COMMIT');
  }catch(e){ db.exec('ROLLBACK'); throw e; }
  return {novos, atualizados};
}
function getMetaValor(chave){
  const r = db.prepare('SELECT valor FROM meta WHERE chave=?').get(chave);
  return r ? r.valor : null;
}
function setMetaValor(chave, valor){
  db.prepare(`INSERT INTO meta (chave,valor) VALUES (?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor`).run(chave, valor);
}

if(contarLideres()===0){
  console.log('Banco novo — aplicando cadastro inicial dos 8 líderes e histórico da planilha de Monitoramento...');
  rodarSeedInicial();
}

/* ---------------- INTEGRAÇÃO AO VIVO COM A PLANILHA GOOGLE (aba "Técnicos de Monitoramento") ----------------
   Lida via API Sheets v4 com Service Account (escopo readonly) — a planilha NÃO precisa ser pública,
   só compartilhada como "Leitor" com o client_email de GOOGLE_SERVICE_ACCOUNT_JSON (backend/.env).
   https://docs.google.com/spreadsheets/d/1szO-QkDju6DGtFSgLwvHoioO5hbN93uowlc0lu4ZqcM/edit?gid=1442813401 */
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
  if(!bruto) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON não configurado em backend/.env — sem credencial não dá pra ler a planilha.');
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
  const mapaPorNome = new Map(db.prepare('SELECT id,nome FROM lideres').all().map(l => [normalizarNome(l.nome), l.id]));
  const upsertNota = db.prepare(`INSERT INTO avaliacoes_notas (lider_id,mes,indicador,gestor,auto) VALUES (?,?,?,?,NULL)
    ON CONFLICT(lider_id,mes,indicador) DO UPDATE SET gestor=excluded.gestor`);
  const garantirMeta = db.prepare(`INSERT INTO avaliacoes_meta (lider_id,mes,forte,melhorar,meta,obs)
    SELECT ?,?,'','','','' WHERE NOT EXISTS (SELECT 1 FROM avaliacoes_meta WHERE lider_id=? AND mes=?)`);
  const atualizarFuncao = db.prepare('UPDATE lideres SET funcao=? WHERE id=?');
  let linhasAplicadas=0, ignoradas=0;
  const mesesLideresAtingidos = new Set();
  db.exec('BEGIN');
  try{
    linhas.forEach(row=>{
      const nomeCel = row['TEC DE MONITORAMENTO'];
      const dataCel = row['DATA'];
      if(!nomeCel || !dataCel){ return; }
      const lid = mapaPorNome.get(normalizarNome(nomeCel));
      if(!lid){ ignoradas++; return; }
      const partes = dataCel.split('/');
      if(partes.length !== 3) return;
      const mes = partes[2] + '-' + partes[1].padStart(2,'0');
      let mudou = false;
      Object.entries(MAPA_COLUNAS_PLANILHA).forEach(([coluna,indicador])=>{
        const valor = parsePercentualBR(row[coluna]);
        if(valor==null) return;
        upsertNota.run(lid, mes, indicador, valor);
        mudou = true;
      });
      if(row['FUNÇÃO'] && row['FUNÇÃO'].trim()) atualizarFuncao.run(row['FUNÇÃO'].trim(), lid);
      if(mudou){
        garantirMeta.run(lid, mes, lid, mes);
        mesesLideresAtingidos.add(lid+'|'+mes);
        linhasAplicadas++;
      }
    });
    db.exec('COMMIT');
  }catch(e){ db.exec('ROLLBACK'); throw e; }
  return { linhasAplicadas, mesesAtingidos: mesesLideresAtingidos.size, ignoradas };
}

/* ---------------- ESTADO: monta/desmonta o objeto que o front-end usa ---------------- */
function montarEstado(){
  const lideres = db.prepare('SELECT * FROM lideres ORDER BY nome').all();
  const aval = {};
  db.prepare('SELECT * FROM avaliacoes_notas').all().forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    aval[k] = aval[k] || {notas:{}, auto:{}, forte:'', melhorar:'', meta:'', obs:''};
    if(row.gestor!=null) aval[k].notas[row.indicador]=row.gestor;
    if(row.auto!=null) aval[k].auto[row.indicador]=row.auto;
  });
  db.prepare('SELECT * FROM avaliacoes_meta').all().forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    aval[k] = aval[k] || {notas:{}, auto:{}};
    aval[k].forte=row.forte||''; aval[k].melhorar=row.melhorar||''; aval[k].meta=row.meta||''; aval[k].obs=row.obs||'';
  });
  const pdi = {};
  db.prepare('SELECT * FROM pdi_notas').all().forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    pdi[k] = pdi[k] || {notas:{}, auto:{}, acoes:[{},{},{}]};
    if(row.gestor!=null) pdi[k].notas[row.criterio]=row.gestor;
    if(row.auto!=null) pdi[k].auto[row.criterio]=row.auto;
  });
  db.prepare('SELECT * FROM pdi_meta').all().forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    pdi[k] = pdi[k] || {notas:{}, auto:{}};
    pdi[k].fortes=row.fortes||''; pdi[k].desenvolver=row.desenvolver||'';
    pdi[k].acoes = row.acoes ? JSON.parse(row.acoes) : [{},{},{}];
    pdi[k].revisao=row.revisao||''; pdi[k].compromisso=row.compromisso||'';
  });
  const sem = {};
  db.prepare('SELECT * FROM semanal').all().forEach(row=>{
    const k = row.lider_id+'|'+row.mes;
    sem[k] = sem[k] || {};
    sem[k]['s'+row.semana] = {travou:row.travou||'', decisao:row.decisao||'', compromisso:row.compromisso||'', ok: !!row.ok};
  });
  return { lideres, aval, sem, pdi, avalImportado: getMetaValor('avalImportado')==='1', pctV2:true };
}

function salvarEstado(d){
  const idsAntigos = db.prepare('SELECT id FROM lideres').all().map(r=>r.id);
  const idsNovos = new Set((d.lideres||[]).map(l=>l.id));
  idsAntigos.filter(id => !idsNovos.has(id)).forEach(id => removerFotosAntigas(id));
  db.exec('BEGIN');
  try{
    db.exec('DELETE FROM lideres'); db.exec('DELETE FROM avaliacoes_notas'); db.exec('DELETE FROM avaliacoes_meta');
    db.exec('DELETE FROM pdi_notas'); db.exec('DELETE FROM pdi_meta'); db.exec('DELETE FROM semanal');

    const insLider = db.prepare('INSERT INTO lideres (id,nome,equipe,qtd,foto,funcao) VALUES (?,?,?,?,?,?)');
    (d.lideres||[]).forEach(l => insLider.run(l.id, l.nome, l.equipe||'', String(l.qtd??''), l.foto||null, l.funcao||null));

    const insNota = db.prepare('INSERT INTO avaliacoes_notas (lider_id,mes,indicador,gestor,auto) VALUES (?,?,?,?,?)');
    const insAvalMeta = db.prepare('INSERT INTO avaliacoes_meta (lider_id,mes,forte,melhorar,meta,obs) VALUES (?,?,?,?,?,?)');
    Object.entries(d.aval||{}).forEach(([k,v])=>{
      const [lid,mes]=k.split('|');
      const inds = new Set([...Object.keys(v.notas||{}), ...Object.keys(v.auto||{})]);
      inds.forEach(ind => insNota.run(lid,mes,ind, (v.notas||{})[ind] ?? null, (v.auto||{})[ind] ?? null));
      insAvalMeta.run(lid, mes, v.forte||'', v.melhorar||'', v.meta||'', v.obs||'');
    });

    const insPdiNota = db.prepare('INSERT INTO pdi_notas (lider_id,mes,criterio,gestor,auto) VALUES (?,?,?,?,?)');
    const insPdiMeta = db.prepare('INSERT INTO pdi_meta (lider_id,mes,fortes,desenvolver,acoes,revisao,compromisso) VALUES (?,?,?,?,?,?,?)');
    Object.entries(d.pdi||{}).forEach(([k,v])=>{
      const [lid,mes]=k.split('|');
      const crits = new Set([...Object.keys(v.notas||{}), ...Object.keys(v.auto||{})]);
      crits.forEach(c => insPdiNota.run(lid,mes,c, (v.notas||{})[c] ?? null, (v.auto||{})[c] ?? null));
      insPdiMeta.run(lid, mes, v.fortes||'', v.desenvolver||'', JSON.stringify(v.acoes||[{},{},{}]), v.revisao||'', v.compromisso||'');
    });

    const insSem = db.prepare('INSERT INTO semanal (lider_id,mes,semana,travou,decisao,compromisso,ok) VALUES (?,?,?,?,?,?,?)');
    Object.entries(d.sem||{}).forEach(([k,v])=>{
      const [lid,mes]=k.split('|');
      for(let s=1;s<=5;s++){
        const w = v['s'+s];
        if(!w) continue;
        insSem.run(lid, mes, s, w.travou||'', w.decisao||'', w.compromisso||'', w.ok?1:0);
      }
    });

    setMetaValor('avalImportado', d.avalImportado ? '1' : '0');
    db.exec('COMMIT');
  }catch(e){
    db.exec('ROLLBACK');
    throw e;
  }
}

/* ---------------- SERVIDOR HTTP ---------------- */
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(session({
  name: 'sel.sid',
  secret: 'jrtelecom-sistema-evolucao-lideres-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000*60*60*12 }
}));

function exigirLogin(req, res, next){
  if(req.session && req.session.autenticado) return next();
  res.status(401).json({ erro: 'Não autenticado.' });
}

app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if(usuario===USUARIO && senha===SENHA){
    req.session.autenticado = true;
    return res.json({ ok:true });
  }
  res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(()=> res.json({ ok:true }));
});
app.get('/api/me', (req, res) => {
  res.json({ autenticado: !!(req.session && req.session.autenticado) });
});

app.get('/api/estado', exigirLogin, (req, res) => {
  res.json(montarEstado());
});
app.post('/api/estado', exigirLogin, (req, res) => {
  try{
    salvarEstado(req.body || {});
    res.json({ ok:true });
  }catch(e){
    console.error('Erro ao salvar estado:', e);
    res.status(500).json({ erro:'Erro ao salvar no banco de dados.' });
  }
});
app.post('/api/importar-historico', exigirLogin, (req, res) => {
  const r = aplicarHistoricoMonitoramento();
  res.json(r);
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

const MIME_PARA_EXT = { 'image/jpeg':'jpg', 'image/png':'png', 'image/webp':'webp', 'image/gif':'gif' };
function removerFotosAntigas(liderId){
  fs.readdirSync(FOTOS_DIR)
    .filter(nome => nome.startsWith(liderId+'-'))
    .forEach(nome => { try{ fs.unlinkSync(path.join(FOTOS_DIR, nome)); }catch(e){} });
}
app.post('/api/lideres/:id/foto', exigirLogin, (req, res) => {
  const { id } = req.params;
  const lider = db.prepare('SELECT id FROM lideres WHERE id=?').get(id);
  if(!lider) return res.status(404).json({ erro: 'Líder não encontrado.' });
  const m = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(req.body && req.body.dataUrl || '');
  if(!m) return res.status(400).json({ erro: 'Imagem inválida.' });
  const ext = MIME_PARA_EXT[m[1]];
  if(!ext) return res.status(400).json({ erro: 'Formato de imagem não suportado. Use JPG, PNG, WEBP ou GIF.' });
  const buffer = Buffer.from(m[2], 'base64');
  if(buffer.length > 8*1024*1024) return res.status(400).json({ erro: 'Imagem maior que 8MB.' });
  removerFotosAntigas(id);
  const nomeArquivo = id+'-'+Date.now()+'.'+ext;
  fs.writeFileSync(path.join(FOTOS_DIR, nomeArquivo), buffer);
  const caminho = 'uploads/fotos/'+nomeArquivo;
  db.prepare('UPDATE lideres SET foto=? WHERE id=?').run(caminho, id);
  res.json({ ok:true, foto: caminho });
});
app.delete('/api/lideres/:id/foto', exigirLogin, (req, res) => {
  const { id } = req.params;
  removerFotosAntigas(id);
  db.prepare('UPDATE lideres SET foto=NULL WHERE id=?').run(id);
  res.json({ ok:true });
});

app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(FRONTEND_DIR));

app.listen(PORTA, '127.0.0.1', () => {
  console.log('=======================================================');
  console.log(' Sistema de Evolução de Líderes — JR Telecom');
  console.log(' Banco de dados: ' + DB_PATH);
  console.log(' Acesse em:      http://localhost:' + PORTA);
  console.log('=======================================================');
  sincronizarPlanilhaMonitoramento()
    .then(r => console.log('Sincronização com a planilha de Monitoramento: '+r.linhasAplicadas+' lançamento(s) aplicado(s) em '+r.mesesAtingidos+' mês(es)/líder(es), '+r.ignoradas+' linha(s) ignorada(s) (nome não é líder cadastrado).'))
    .catch(e => console.error('Sincronização inicial com a planilha falhou (o sistema segue funcionando com os dados que já tem):', e.message));
});
