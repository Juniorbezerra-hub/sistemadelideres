/* Gera o valor de ADMIN_SENHA_HASH (scrypt) a partir de uma senha.
   Uso:  node gerar-hash-senha.js "minha senha forte"   (ou sem argumento: lê da entrada padrão)
   Cole o resultado na variável ADMIN_SENHA_HASH (backend/.env e variáveis da Vercel). */
const crypto = require('crypto');

function gerarHash(senha){
  const sal = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(senha, sal, 64, { N, r, p });
  return ['scrypt', N, r, p, sal.toString('base64'), hash.toString('base64')].join('$');
}

if(require.main === module){
  const arg = process.argv[2];
  if(arg){
    console.log(gerarHash(arg));
  }else{
    let dados = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { dados += c; });
    process.stdin.on('end', () => { console.log(gerarHash(dados.replace(/\r?\n$/, ''))); });
  }
}
module.exports = { gerarHash };
