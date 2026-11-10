// Offline owner operation; never exposed as a public HTTP endpoint.
import {DatabaseSync} from 'node:sqlite';
import {resolve} from 'node:path';
const email=process.argv[2];
if(!email){console.error('Usage: node server/admin.mjs owner@example.com');process.exit(1)}
const db=new DatabaseSync(resolve(process.env.DATA_DIR||'data','tawasol.sqlite'));
const row=db.prepare('SELECT * FROM accounts WHERE email=?').get(email.toLowerCase());
if(!row)throw Error('Register the owner account first');
const user=JSON.parse(row.profile);user.role='super';user.permissions=['users','content','reports'];
db.prepare('UPDATE accounts SET profile=? WHERE id=?').run(JSON.stringify(user),user.id);
db.prepare('DELETE FROM sessions WHERE uid=?').run(user.id);
console.log('Owner role assigned. Sign in again.');db.close();
