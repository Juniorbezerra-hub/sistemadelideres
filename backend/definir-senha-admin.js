/* Troca a senha do admin SEM redeploy: grava o hash (scrypt) na tabela admin_credenciais do Supabase e revoga
   todas as sessões abertas.  Uso:  node backend/definir-senha-admin.js "nova senha longa"
   Lê SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY e ADMIN_USUARIO de backend/.env (ou do ambiente). */
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { gerarHash } = require('./gerar-hash-senha');

const envPath = path.join(__dirname, '.env');
if(fs.existsSync(envPath)){
  fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(l => {
    const i = l.indexOf('=');
    if(i > 0 && !l.trim().startsWith('#')){ const k = l.slice(0,i).trim(); if(!(k in process.env)) process.env[k] = l.slice(i+1); }
  });
}
const senha = process.argv[2];
if(!senha || senha.length < 12){ console.error('Informe a nova senha (mínimo 12 caracteres): node backend/definir-senha-admin.js "nova senha"'); process.exit(1); }
const usuario = process.env.ADMIN_USUARIO || 'admin';
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession:false } });

(async () => {
  const { error } = await supabase.from('admin_credenciais').upsert({ usuario, senha_hash: gerarHash(senha), atualizado_em: new Date().toISOString() });
  if(error){ console.error('Erro ao gravar a senha:', error.message); process.exit(1); }
  const { data: n, error: e2 } = await supabase.rpc('revogar_todas_sessoes');
  console.log('Senha do usuário "'+usuario+'" atualizada. Sessões revogadas: '+(e2 ? '(erro: '+e2.message+')' : n));
})();
