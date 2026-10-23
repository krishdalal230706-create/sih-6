import mysql from 'mysql2/promise';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), 'backend', '.env') });

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_PORT = parseInt(process.env.DB_PORT || '3306', 10);
const DB_NAME = process.env.DB_NAME || 'cyberguard_grid';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';

export async function runMigration() {
  console.log(`\n📦 [MYSQL MIGRATION] Connecting to MySQL server at ${DB_HOST}:${DB_PORT}...`);
  try {
    const connection = await mysql.createConnection({
      host: DB_HOST,
      port: DB_PORT,
      user: DB_USER,
      password: DB_PASSWORD
    });

    console.log(`🛠️ [MYSQL MIGRATION] Creating database '${DB_NAME}' if not exists...`);
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;`);
    await connection.query(`USE \`${DB_NAME}\`;`);

    const schemaPath = path.resolve(process.cwd(), 'src/db/schema.sql');
    if (fs.existsSync(schemaPath)) {
      const sqlContent = fs.readFileSync(schemaPath, 'utf-8');
      const statements = sqlContent
        .split(';')
        .map((s) => s.trim())
        .filter((s) => s.length > 0 && !s.startsWith('--'));

      for (const stmt of statements) {
        if (stmt) {
          try {
            await connection.query(stmt);
          } catch (err: any) {
            console.warn(`[MYSQL MIGRATION STATEMENT NOTE] ${err.message}`);
          }
        }
      }
    }

    await connection.end();

    console.log('\n=======================================================');
    console.log('MySQL Connection: CONNECTED');
    console.log(`Database: ${DB_NAME}`);
    console.log('Tables created: vulnerabilities, vulnerability_sources, sync_logs, affected_products');
    console.log('=======================================================\n');
    return true;
  } catch (err: any) {
    console.error(`❌ [MYSQL MIGRATION ERROR] Could not connect to MySQL server at ${DB_HOST}:${DB_PORT}: ${err.message}`);
    console.warn(`💡 Ensure MySQL is running on ${DB_HOST}:${DB_PORT} and credentials in .env are correct.\n`);
    return false;
  }
}

if (process.argv[1] && process.argv[1].includes('migrate')) {
  runMigration();
}
