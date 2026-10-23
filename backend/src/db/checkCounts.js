const mysql = require('mysql2/promise');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(process.cwd(), '.env') });

async function checkCounts() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'cyberguard_grid'
  });

  const [total] = await conn.query('SELECT COUNT(*) as cnt FROM vulnerabilities');
  const [uniq] = await conn.query('SELECT COUNT(DISTINCT cve_id) as cnt FROM vulnerabilities');
  const [nvd] = await conn.query("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE source LIKE '%NVD%' OR source LIKE '%NIST%'");
  const [cisa] = await conn.query("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE source LIKE '%CISA%' OR source LIKE '%KEV%' OR known_exploited = 1");
  const [knownExp] = await conn.query('SELECT COUNT(*) as cnt FROM vulnerabilities WHERE known_exploited = 1');
  const [osv] = await conn.query("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE source LIKE '%OSV%'");
  const [github] = await conn.query("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE source LIKE '%GitHub%'");

  console.log('--- MYSQL STATS REPORT ---');
  console.log('Total vulnerability records:', total[0].cnt);
  console.log('Unique CVEs:', uniq[0].cnt);
  console.log('NVD records:', nvd[0].cnt);
  console.log('CISA KEV records:', cisa[0].cnt);
  console.log('Known exploited records:', knownExp[0].cnt);
  console.log('OSV records:', osv[0].cnt);
  console.log('GitHub Advisory records:', github[0].cnt);

  await conn.end();
}

checkCounts().catch(console.error);
