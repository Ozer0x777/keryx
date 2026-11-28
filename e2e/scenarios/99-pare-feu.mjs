import { request } from 'node:http'

// Chemin envoyé tel quel (fetch normaliserait « ../ » avant l'envoi).
const brut = (base, path) => new Promise((resolve, reject) => {
  const u = new URL(base)
  const r = request({ host: u.hostname, port: u.port, path, method: 'GET' }, (res) => { res.resume(); resolve(res.statusCode) })
  r.on('error', reject); r.end()
})

// Pare-feu applicatif (ADR-0035) : seulement quand la suite passe par Coraza en mode blocage (E2E_WAF=blocage).
// Le reste de la suite, joué au travers, vérifie qu'aucun usage normal n'est bloqué.
export default async ({ BASE, check, stack }) => {
  if (stack.waf !== 'blocage') { console.log('  (pare-feu non actif : E2E_WAF=blocage pour ce scénario)'); return }
  const post = (path, body) => fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  check((await post('/api/v1/auth/login', { username: "admin' OR 1=1 --", password: 'x' })).status === 403, 'pare-feu : injection SQL dans la connexion bloquée (403)')
  check((await post('/api/v1/auth/login', { username: '<script>alert(1)</script>', password: 'x' })).status === 403, 'pare-feu : script dans la connexion bloqué (403)')
  check(await brut(BASE, '/api/v1/../../etc/passwd') === 403, 'pare-feu : traversée de répertoire bloquée (403)')
  check((await fetch(`${BASE}/`, { headers: { 'User-Agent': 'Nikto/2.5.0' } })).status === 403, 'pare-feu : scanner connu bloqué (403)')
  check((await fetch(`${BASE}/api/v1/tickets?status=${encodeURIComponent('<script>alert(1)</script>')}`)).status === 403, 'pare-feu : paramètre piégé bloqué (403)')
  // Usages légitimes : indicateurs cherchés, alerte qui contient une attaque, connexion normale (refusée par Keryx, pas par le pare-feu).
  const q = encodeURIComponent('powershell -enc <script> ../../etc/passwd UNION SELECT')
  check((await fetch(`${BASE}/api/v1/tickets?q=${q}`)).status === 401, 'pare-feu : recherche d\'un indicateur transmise à Keryx (401 sans session, pas 403)')
  const ingest = await fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ timestamp: new Date().toISOString(), id: 'waf1', rule: { id: '31106', level: 12, description: 'Web attack: SQL injection', groups: ['web', 'attack'] }, agent: { id: '095', name: 'srv-waf', ip: '10.20.9.5' },
      full_log: "GET /index.php?id=1' UNION SELECT password FROM users-- HTTP/1.1 ; cat /etc/passwd ; <script>alert(1)</script>" }) })
  check(ingest.status === 200 || ingest.status === 201, `pare-feu : alerte Wazuh contenant une attaque reçue par Keryx (${ingest.status})`)
  check((await post('/api/v1/auth/login', { username: 'jean.dupont', password: 'Un mot de passe solide !' })).status === 401, 'pare-feu : connexion ordinaire transmise à Keryx (401, pas 403)')
}
