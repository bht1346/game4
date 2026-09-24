// 物资申请系统 —— 后端 API（Cloudflare Pages Functions）
// 存储：D1（主数据） + KV（登录会话 / 统计缓存，可选但推荐）
// 绑定名随意：DB / DBp / game_db、APP_KV / KVp 都认，代码按对象能力自动识别，不用改名字

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-allow-headers': 'content-type',
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });

const norm = (s) => String(s == null ? '' : s).trim().toLowerCase();

function uid() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// ---------------- 管理密码：PBKDF2-SHA256 哈希（不存明文） ----------------
// 新密码用这个迭代次数；旧密码按库里记录的 iterations 验证，所以以后改这个常数不会让旧密码失效
// 取 2 万次：本地实测约 5ms CPU，留足余量给 Cloudflare Workers 免费计划的 10ms/请求 CPU 上限
// 配合"隐藏入口 + 10次错误锁定15分钟 + 强密码"，防暴力破解强度足够
const PBKDF2_ITER = 20000;
const LOGIN_MAX_FAIL = 10;      // 连续错误几次后锁定
const LOGIN_LOCK_TTL = 900;     // 锁定 15 分钟
const SESSION_TTL = 604800;     // 登录会话 7 天

function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function randomHex(bytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}
async function hashPwd(pwd, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pwd), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: iter || PBKDF2_ITER, hash: 'SHA-256' },
    key, 256);
  return bytesToHex(new Uint8Array(bits));
}
// 恒定时间比较，避免时序侧信道
function safeEq(a, b) {
  const A = String(a), B = String(b);
  if (A.length !== B.length) return false;
  let d = 0;
  for (let i = 0; i < A.length; i++) d |= A.charCodeAt(i) ^ B.charCodeAt(i);
  return d === 0;
}

// 全部表：没在 D1 控制台执行 schema 时，后端自动补建（每个 Worker 实例只跑一次）
// 这样部署完直接打开页面就能用，不必再碰 D1 控制台的执行框
const SCHEMA_SQL = [
  `CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stock INTEGER DEFAULT -1,
    per_limit INTEGER DEFAULT 0,
    enchant TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    game_name TEXT NOT NULL,
    client_id TEXT,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    decided_at INTEGER DEFAULT 0,
    cooldown_until INTEGER DEFAULT 0,
    cooldown_text TEXT DEFAULT '',
    note TEXT DEFAULT ''
  )`,
  `CREATE TABLE IF NOT EXISTS app_items (
    app_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_name TEXT NOT NULL,
    qty INTEGER DEFAULT 1,
    PRIMARY KEY (app_id, item_id)
  )`,
  `CREATE TABLE IF NOT EXISTS admin (
    id TEXT PRIMARY KEY,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  )`,
  // 受限管理（协管）的新增/删除物资额度记录：3 小时内最多 3 次
  `CREATE TABLE IF NOT EXISTS sub_quota (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    item_name TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  // 玩家账号：游戏名 + 密码注册，登录后才能申请（防止乱填别人的名字）
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    game_name TEXT NOT NULL,
    name_key TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    team_id TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  // 团队：人数越多，单次上限越高（具体加成在后台设置）
  `CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  // 入队邀请：必须对方同意才生效
  `CREATE TABLE IF NOT EXISTS team_invites (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL,
    inviter_id TEXT NOT NULL,
    invitee_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  // 抽奖奖品：独立的一套奖池，跟物资清单互不影响
  `CREATE TABLE IF NOT EXISTS lottery_prizes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    weight INTEGER DEFAULT 1,
    stock INTEGER DEFAULT -1,
    created_at INTEGER NOT NULL
  )`,
  // 抽奖记录：谁在什么时候抽到了什么，对应生成了哪条申请
  `CREATE TABLE IF NOT EXISTS lottery_log (
    id TEXT PRIMARY KEY,
    user_id TEXT DEFAULT '',
    game_name TEXT DEFAULT '',
    prize_id TEXT DEFAULT '',
    prize_name TEXT DEFAULT '',
    app_id TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_app_game ON applications(game_name)`,
  `CREATE INDEX IF NOT EXISTS idx_app_client ON applications(client_id)`,
  `CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status)`,
  `CREATE INDEX IF NOT EXISTS idx_app_time ON applications(created_at DESC)`,
  // 射击游戏战绩：按账号累加（UPSERT，不存逐局明细，省空间省读次数）
  `CREATE TABLE IF NOT EXISTS game_stats (
user_id TEXT PRIMARY KEY,
game_name TEXT DEFAULT '',
wins INTEGER DEFAULT 0,
losses INTEGER DEFAULT 0,
kills INTEGER DEFAULT 0,
games INTEGER DEFAULT 0,
updated_at INTEGER DEFAULT 0
)`,
  `CREATE INDEX IF NOT EXISTS idx_game_rank ON game_stats(kills DESC)`,
];
// 旧库升级：你之前已经部署过一版，表里没有库存/上限/数量这三列。
// SQLite 的 ALTER TABLE ADD COLUMN 会重复报错，所以先查 PRAGMA 再决定加不加。
const COLUMN_MIGRATIONS = [
  ['items', 'stock', 'INTEGER DEFAULT -1'],      // -1 = 不限（充足）
  ['items', 'per_limit', 'INTEGER DEFAULT 0'],   // 0 = 不限
  ['items', 'enchant', "TEXT DEFAULT ''"],       // 附魔说明（点感叹号弹出）
  ['app_items', 'qty', 'INTEGER DEFAULT 1'],     // 本条申请里该物资的数量
  ['applications', 'user_note', "TEXT DEFAULT ''"], // 玩家提交时自己填的留言（给审核看，只读）
  ['admin', 'must_change', 'INTEGER DEFAULT 0'], // 1 = 用初始密码登录后必须先改一个新密码
  ['applications', 'user_id', "TEXT DEFAULT ''"], // 归属的玩家账号（登录后申请）
  ['applications', 'team_size', 'INTEGER DEFAULT 0'], // 提交时团队人数，便于后台追溯
  ['applications', 'source', "TEXT DEFAULT ''"], // 'lottery' = 抽奖中出来的申请，其余为普通申请
];
async function ensureColumns(env) {
  for (const [table, col, def] of COLUMN_MIGRATIONS) {
    try {
      const cols = await dbAll(env, `PRAGMA table_info(${table})`);
      const has = cols.some((c) => String(c.name).toLowerCase() === col);
      if (!has) await dbRun(env, `ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
    } catch (e) { /* 老库/权限问题就跳过，接口里有默认值兜底 */ }
  }
}

let __schemaReady = false;
async function ensureSchema(env) {
  if (__schemaReady) return;
  try {
    for (const s of SCHEMA_SQL) await dbRun(env, s);
    await ensureColumns(env);
    __schemaReady = true;
  } catch (e) {
    // 建表失败不阻断请求，让后续 SQL 自己报错，便于排查
  }
}
// 兼容旧调用名
const ensureAdminTable = ensureSchema;
async function getAdminRow(env, id) {
  return await dbGet(env, 'SELECT * FROM admin WHERE id = ?', id);
}
// 主管理 id 固定 'admin'，受限管理（协管）id 固定 'subadmin'
async function getAdmin(env) { return await getAdminRow(env, 'admin'); }
async function getSub(env) { return await getAdminRow(env, 'subadmin'); }

// ---------------- 角色：主管理 admin / 受限管理 subadmin ----------------
// KV 里 token:<token> 存角色；旧版存的是 '1'，一律当作主管理，兼容已登录的会话
async function getRole(env, token) {
  if (!token || !env.APP_KV) return null;
  const v = await env.APP_KV.get('token:' + token);
  if (v === 'admin' || v === '1') return 'admin';
  if (v === 'subadmin') return 'subadmin';
  return null;
}
async function isStaff(env, token) { return !!(await getRole(env, token)); }
async function isAdmin(env, token) { return (await getRole(env, token)) === 'admin'; }
async function isSub(env, token) { return (await getRole(env, token)) === 'subadmin'; }

// ---------------- 副管理额度：默认每 3 小时内最多新增/删除 3 个物资（主管理可改） ----------------
const SUB_WINDOW_HOURS_DEFAULT = 3;
const SUB_QUOTA_DEFAULT = 3;
// 额度配置：主管理可在后台改「次数上限」和「间隔小时数」，0 次 = 不允许增删
async function subQuotaConfig(env) {
  const rawLimit = Number(await getSetting(env, 'sub_quota_limit', SUB_QUOTA_DEFAULT));
  const rawHours = Number(await getSetting(env, 'sub_quota_hours', SUB_WINDOW_HOURS_DEFAULT));
  const limit = Number.isFinite(rawLimit) ? Math.min(999, Math.max(0, Math.floor(rawLimit))) : SUB_QUOTA_DEFAULT;
  const hours = Number.isFinite(rawHours) && rawHours > 0 ? Math.min(9999, rawHours) : SUB_WINDOW_HOURS_DEFAULT;
  return { limit, hours, windowMs: Math.round(hours * 3600 * 1000) };
}
async function subQuotaLeft(env) {
  const cfg = await subQuotaConfig(env);
  const windowMs = cfg.windowMs;
  const since = Date.now() - windowMs;
  let rows = [];
  try {
    rows = await dbAll(env,
      'SELECT created_at FROM sub_quota WHERE actor = ? AND created_at > ? ORDER BY created_at ASC',
      'subadmin', since);
  } catch (e) { rows = []; }
  const used = rows.length;
  const left = Math.max(0, cfg.limit - used);
  // 用满时，最早那一条过期的时间 = 恢复时间
  const resetAt = rows.length ? Number(rows[0].created_at) + windowMs : 0;
  return { used, left, limit: cfg.limit, hours: cfg.hours, resetAt, resetText: fmtTime(resetAt) };
}
async function subConsume(env, action, itemName) {
  try {
    await dbRun(env,
      'INSERT INTO sub_quota (id, actor, action, item_name, created_at) VALUES (?,?,?,?,?)',
      uid(), 'subadmin', String(action || ''), String(itemName || '').slice(0, 60), Date.now());
    // 顺手清掉 24 小时前的老记录，表不会无限膨胀
    await dbRun(env, 'DELETE FROM sub_quota WHERE created_at < ?', Date.now() - 24 * 3600 * 1000);
  } catch (e) { /* 记录失败不影响主流程，但额度以记录为准 */ }
}

// ---------------- 全局设置（默认冷却时间） ----------------
const DEFAULT_COOLDOWN = { value: 7, unit: 'days' };
const UNIT_LABEL = { minutes: '分钟', hours: '小时', days: '天' };
function normalizeUnit(u) {
  return u === 'minutes' ? 'minutes' : u === 'hours' ? 'hours' : 'days';
}
function unitToHours(value, unit) {
  const u = normalizeUnit(unit);
  if (u === 'days') return value * 24;
  if (u === 'minutes') return value / 60;
  return value;
}
async function getSetting(env, k, fallback) {
  try {
    const row = await dbGet(env, 'SELECT v FROM settings WHERE k = ?', k);
    if (!row) return fallback;
    return JSON.parse(row.v);
  } catch (e) {
    return fallback;
  }
}
async function setSetting(env, k, val) {
  await dbRun(env,
    'INSERT INTO settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
    k, JSON.stringify(val));
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ---------------- 射击游戏战绩 ----------------
// 单局上报的数值上限：客户端可伪造，但至少挡掉"随手填 99999"这种
const GAME_KILLS_MAX = 200;
function normStats(r) {
  return {
    wins: Math.max(0, Number(r && r.wins) || 0),
    losses: Math.max(0, Number(r && r.losses) || 0),
    kills: Math.max(0, Number(r && r.kills) || 0),
    games: Math.max(0, Number(r && r.games) || 0),
  };
}
async function gameStatsOf(env, userId) {
  if (!userId) return normStats(null);
  const row = await dbGet(env, 'SELECT wins, losses, kills, games FROM game_stats WHERE user_id = ?', userId);
  return normStats(row);
}
// 累加一局：SQLite UPSERT，一次写入搞定，不用先读后写（省一半 D1 读次数）
async function gameAddResult(env, userId, gameName, win, kills) {
  const w = win ? 1 : 0;
  const l = win ? 0 : 1;
  let k = Number(kills);
  if (!Number.isFinite(k) || k < 0) k = 0;
  if (k > GAME_KILLS_MAX) k = GAME_KILLS_MAX;
  k = Math.floor(k);
  await dbRun(env, `
    INSERT INTO game_stats (user_id, game_name, wins, losses, kills, games, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      game_name = excluded.game_name,
      wins   = game_stats.wins   + excluded.wins,
      losses = game_stats.losses + excluded.losses,
      kills  = game_stats.kills  + excluded.kills,
      games  = game_stats.games  + 1,
      updated_at = excluded.updated_at`,
    String(userId), String(gameName || '').slice(0, 40), w, l, k, Date.now());
  return await gameStatsOf(env, userId);
}

// ---------------- 抽奖：设置、权重抽取 ----------------
const LOTTERY_HOURS_DEFAULT = 24;   // 默认每个账号 24 小时只能抽一次
async function lotteryHours(env) {
  const raw = Number(await getSetting(env, 'lottery_hours', LOTTERY_HOURS_DEFAULT));
  if (!Number.isFinite(raw) || raw < 0) return LOTTERY_HOURS_DEFAULT;
  return Math.min(9999, raw);
}
function rowToPrize(r) {
  return {
    id: r.id,
    name: r.name,
    weight: Math.max(0, Number.isFinite(Number(r.weight)) ? Number(r.weight) : 1),
    stock: Number.isFinite(Number(r.stock)) ? Number(r.stock) : -1,   // -1 = 充足
  };
}
// 按权重抽一个：权重越大越容易中；库存为 0 的不参与
function pickPrize(prizes) {
  const pool = prizes.filter((p) => p.stock !== 0 && p.weight > 0);
  if (!pool.length) return null;
  const total = pool.reduce((s, p) => s + p.weight, 0);
  if (total <= 0) return null;
  let r = Math.random() * total;
  for (const p of pool) {
    r -= p.weight;
    if (r <= 0) return p;
  }
  return pool[pool.length - 1];
}
// 这个账号上次抽奖的时间（用来算冷却）
async function lastDrawAt(env, userId) {
  const row = await dbGet(env,
    'SELECT created_at FROM lottery_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
    String(userId || ''));
  return row ? Number(row.created_at) || 0 : 0;
}

// ---------------- 公告：进入页面直接弹出 ----------------
async function getAnnounce(env) {
  const a = await getSetting(env, 'announcement', null);
  if (!a || typeof a !== 'object') return { text: '', updatedAt: 0 };
  return { text: String(a.text == null ? '' : a.text).trim(), updatedAt: Number(a.updatedAt) || 0 };
}

// ---------------- D1 基础操作 ----------------
async function dbAll(env, sql, ...params) {
  const stmt = env.DB.prepare(sql);
  const res = await (params.length ? stmt.bind(...params) : stmt).all();
  return res.results || [];
}

async function dbRun(env, sql, ...params) {
  const stmt = env.DB.prepare(sql);
  return await (params.length ? stmt.bind(...params) : stmt).run();
}

async function dbGet(env, sql, ...params) {
  const rows = await dbAll(env, sql, ...params);
  return rows[0] || null;
}

// ---------------- KV：登录会话 + 统计缓存 ----------------
const CACHE_KEY = 'cache:stats';

async function getStatsCache(env) {
  if (!env.APP_KV) return null;
  try {
    const raw = await env.APP_KV.get(CACHE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

async function setStatsCache(env, data) {
  if (!env.APP_KV) return;
  try {
    await env.APP_KV.put(CACHE_KEY, JSON.stringify(data), { expirationTtl: 30 });
  } catch (e) { /* 缓存失败不影响主流程 */ }
}

async function clearStatsCache(env) {
  if (!env.APP_KV) return;
  try { await env.APP_KV.delete(CACHE_KEY); } catch (e) {}
}

// ---------------- 数据映射 ----------------
// stock: -1 = 充足（不限量）；perLimit: 0 = 不限单次数量
function rowToItem(r, mul) {
  let per = Math.max(0, Number.isFinite(Number(r.per_limit)) ? Number(r.per_limit) : 0);
  // mul = 团队加成后的倍数，只在有团队时传；基础不限（0）的不受加成影响
  // ⚠ 严禁把 rowToItem 裸传给 Array.map：map 的第二个参数是数组下标，
  //   会被当成 mul 传进来，导致 per 被乘爆（历史上出过 2→16、64→448 的事故）。
  //   必须写成 map(r => rowToItem(r))。这里再加一层数值防御。
  const m = Number(mul);
  if (Number.isFinite(m) && m > 1 && m <= 100 && per > 0) per = Math.floor(per * m);
  return {
    id: r.id,
    name: r.name,
    stock: Number.isFinite(Number(r.stock)) ? Number(r.stock) : -1,
    perLimit: per,
    perLimitBase: Math.max(0, Number.isFinite(Number(r.per_limit)) ? Number(r.per_limit) : 0),
    enchant: (r.enchant == null ? '' : String(r.enchant)).trim(),
  };
}
// 某个物资"这一条申请最多能领多少"：受剩余库存和单次上限双重约束
function maxQtyOf(it) {
  let m = Infinity;
  if (it.perLimit > 0) m = it.perLimit;
  if (it.stock >= 0) m = Math.min(m, it.stock);
  return Number.isFinite(m) ? Math.max(0, m) : 999;   // 都不限时封顶 999，和前端一致
}

function rowToApp(r, items) {
  return {
    id: r.id,
    gameName: r.game_name,
    clientId: r.client_id,
    userId: r.user_id || '',
    teamSize: Number(r.team_size) || 0,
    items: items || [],
    status: r.status,
    createdAt: r.created_at,
    createdAtText: fmtTime(r.created_at),
    decidedAt: r.decided_at || 0,
    cooldownUntil: r.cooldown_until || 0,
    cooldownUntilText: r.cooldown_until ? fmtTime(r.cooldown_until) : '',
    cooldownText: r.cooldown_text || '',
    note: r.note || '',
    userNote: r.user_note == null ? '' : String(r.user_note),
    source: r.source == null ? '' : String(r.source),   // 'lottery' = 抽奖中出来的
  };
}

function publicApp(a) {
  return {
    id: a.id,
    gameName: a.gameName,
    teamSize: a.teamSize || 0,
    items: a.items,
    status: a.status,
    createdAt: a.createdAt,
    createdAtText: a.createdAtText,
    decidedAt: a.decidedAt,
    cooldownUntil: a.cooldownUntil,
    cooldownUntilText: a.cooldownUntilText,
    cooldownText: a.cooldownText,
    note: a.note,
    userNote: a.userNote || '',
    source: a.source || '',
  };
}

async function loadApp(env, id) {
  const r = await dbGet(env, 'SELECT * FROM applications WHERE id = ?', id);
  if (!r) return null;
  const its = await dbAll(env, 'SELECT item_id as id, item_name as name, COALESCE(qty,1) as qty FROM app_items WHERE app_id = ?', id);
  return rowToApp(r, its);
}

// ---------------- 玩家账号 ----------------
const USER_SESSION_TTL = 2592000;   // 玩家登录保持 30 天
const USER_PWD_MIN = 4;             // 玩家密码最短长度（别设太严，玩家会忘）

function userPublic(u) {
  return { id: u.id, gameName: u.game_name, teamId: u.team_id || '', createdAt: u.created_at };
}
async function getUserById(env, id) {
  if (!id) return null;
  return await dbGet(env, 'SELECT * FROM users WHERE id = ?', id);
}
async function getUserByName(env, gameName) {
  const k = norm(gameName);
  if (!k) return null;
  return await dbGet(env, 'SELECT * FROM users WHERE name_key = ?', k);
}
// KV: utoken:<token> -> 玩家 id
async function userTokenToId(env, token) {
  if (!token || !env.APP_KV) return null;
  return await env.APP_KV.get('utoken:' + token);
}
async function newUserSession(env, userId) {
  if (!env.APP_KV) return null;
  const token = randomHex(24);
  await env.APP_KV.put('utoken:' + token, userId, { expirationTtl: USER_SESSION_TTL });
  return token;
}

// ---------------- 团队与上限加成 ----------------
// 后台可设：
//   team_bonus    每多一名队员，上限多几份"基础量"（默认 1）
//   team_cap      单人最终上限最多是基础的几倍（0 = 不封顶）
// 例：基础 4、3 人、加成 1 → 4 × (1+2) = 12
async function teamSettings(env) {
  const bonus = await getSetting(env, 'team_bonus', 1);
  const cap = await getSetting(env, 'team_cap', 0);
  const maxSize = await getSetting(env, 'team_max_size', 0);
  return {
    bonus: Number.isFinite(Number(bonus)) ? Number(bonus) : 1,
    cap: Number.isFinite(Number(cap)) ? Math.max(0, Number(cap)) : 0,
    maxSize: Number.isFinite(Number(maxSize)) ? Math.max(0, Math.floor(Number(maxSize))) : 0,
  };
}
async function teamMemberCount(env, teamId) {
  if (!teamId) return 0;
  const r = await dbGet(env, 'SELECT COUNT(*) AS c FROM users WHERE team_id = ?', teamId);
  return r ? Number(r.c) : 0;
}
/* 团队带来的"上限倍数"：1 人=1 倍，N 人=1+(N-1)×加成，再受封顶约束 */
function teamMultiplier(n, ts) {
  const cnt = Math.max(1, Math.min(n || 1, ts.maxSize > 0 ? ts.maxSize : n || 1));
  let m = 1 + (cnt - 1) * ts.bonus;
  if (ts.cap > 0) m = Math.min(m, ts.cap);
  return Math.max(1, m);
}
async function userMultiplier(env, user) {
  if (!user || !user.team_id) return 1;
  const ts = await teamSettings(env);
  const n = await teamMemberCount(env, user.team_id);
  return teamMultiplier(n, ts);
}
/* 组装「我的信息」：账号 + 团队 + 队员 + 待处理邀请 + 当前加成倍数 */
async function buildMePayload(env, u) {
  const ts = await teamSettings(env);
  let team = null, members = [], mul = 1;
  if (u.team_id) {
    const t = await dbGet(env, 'SELECT * FROM teams WHERE id = ?', u.team_id);
    if (t) {
      const ms = await dbAll(env, 'SELECT id, game_name, created_at FROM users WHERE team_id = ? ORDER BY created_at', t.id);
      members = ms.map((m) => ({ id: m.id, gameName: m.game_name, isOwner: m.id === t.owner_id }));
      mul = teamMultiplier(ms.length, ts);
      team = { id: t.id, name: t.name, size: ms.length, isOwner: t.owner_id === u.id, mul };
    } else {
      // 团队被后台解散了，顺手把残留的 team_id 清掉
      await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', '', u.id);
    }
  }
  const inv = await dbAll(env, `
    SELECT i.id, i.team_id, i.created_at, t.name AS team_name, ug.game_name AS inviter_name
    FROM team_invites i
    JOIN teams t ON t.id = i.team_id
    JOIN users ug ON ug.id = i.inviter_id
    WHERE i.invitee_id = ? AND i.status = 'pending'
    ORDER BY i.created_at DESC`, u.id);
  return {
    user: {
      ...userPublic(u),
      teamName: team ? team.name : '',
      teamSize: team ? team.size : 0,
      isOwner: !!(team && team.isOwner),
      mul,
    },
    team, members,
    invites: inv.map((r) => ({ id: r.id, teamId: r.team_id, teamName: r.team_name, inviterName: r.inviter_name })),
    teamSettings: ts,
    // 射击游戏战绩：登录/注册时一并返回，前端不用再多发一次请求
    stats: await gameStatsOf(env, u.id),
  };
}
/* 团队解散：清掉队员的 team_id 和未处理邀请 */
async function disbandTeam(env, teamId) {
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET team_id = ? WHERE team_id = ?').bind('', teamId),
    env.DB.prepare("UPDATE team_invites SET status = 'cancelled' WHERE team_id = ? AND status = 'pending'").bind(teamId),
    env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(teamId),
  ]);
}

// ---------------- 主入口 ----------------
// 绑定名容错：Cloudflare 后台填变量名时可能不小心带上首尾空格或大小写不一致，
// 这里统一归一化，避免 “明明填了 DB / APP_KV 却读不到” 的坑。
function normalizeBindings(env) {
  if (!env || env.__bindingsNormalized) return env;
  try {
    // 1) 去掉首尾空格的别名
    for (const k of Object.keys(env)) {
      const t = k.trim();
      if (t !== k && env[t] === undefined) env[t] = env[k];
    }
    // 2) 大小写不敏感的别名（DB / APP_KV / DBp / KVp ...）
    for (const k of Object.keys(env)) {
      const up = k.trim().toUpperCase().replace(/[\s-]+/g, '_');
      if ((up === 'DB' || up === 'APP_KV') && env[up] === undefined) env[up] = env[k];
    }
    // 3) 按"能力"兜底识别：不管后台把变量名写成 DB / DBp / game_db / KVp，
    //    D1 一定有 prepare()，KV 一定有 get()+put()。按类型认，比按名字猜更稳。
    if (!env.DB) {
      for (const k of Object.keys(env)) {
        const v = env[k];
        if (v && typeof v === 'object' && typeof v.prepare === 'function' && typeof v.batch === 'function') {
          env.DB = v; break;
        }
      }
    }
    if (!env.APP_KV) {
      for (const k of Object.keys(env)) {
        const v = env[k];
        // KV 有 get/put/list；D1 没有 put，ASSETS 只有 fetch，不会误判
        if (v && typeof v === 'object' && typeof v.get === 'function'
            && typeof v.put === 'function' && typeof v.prepare !== 'function') {
          env.APP_KV = v; break;
        }
      }
    }
  } catch (e) { /* env 可能是只读代理，忽略即可 */ }
  try { env.__bindingsNormalized = true; } catch (e) {}
  return env;
}

// 注意：绑定名属于基础设施信息，绝不能回给客户端——那等于把后端的
// 环境变量名 / 绑定清单直接公布出去。这里只写服务端日志（你在 Cloudflare
// 后台的 Logs 里能看到），对外一律返回不含细节的通用提示。
function bindingHint(env) {
  const keys = Object.keys(env || {}).filter(k => !k.startsWith('__'));
  const detail = keys.length ? `可用绑定名：[${keys.join(', ')}]` : '当前没有任何绑定';
  try { console.error('[bindings] ' + detail); } catch (e) {}
  return '';
}

export async function onRequest(context) {
  const { request } = context;
  const env = normalizeBindings(context.env);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: JSON_HEADERS });
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');

  // 探活：前端靠它自动判断"后端在不在"，不用用户手填地址。
  // 放在 DB 检查之前——没绑定 D1 时也要能回话，顺便把原因告诉前端。
  if (path === 'ping' || path === 'game/ping') {
    return json({
      ok: true, pong: true, db: !!env.DB,
      hint: env.DB ? '' : '数据存储未就绪，已降级为离线模式（详细原因见服务端日志）。'
    });
  }

  try {
    if (!env.DB) {
      return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 503);
    }

    // 首次请求自动建表（之后本实例内不再重复）
    await ensureSchema(env);

    // ============ GET ============
    if (request.method === 'GET') {
      if (path === 'items') {
        // 登录玩家带 token 时，把团队加成后的上限一起算好返回
        const uToken = url.searchParams.get('token') || '';
        const u = uToken ? await getUserById(env, await userTokenToId(env, uToken)) : null;
        const mul = u ? await userMultiplier(env, u) : 1;
        const rows = await dbAll(env, 'SELECT id, name, stock, per_limit, enchant FROM items ORDER BY created_at');
        return json({ ok: true, items: rows.map((r) => rowToItem(r, mul)), mul });
      }

      if (path === 'stats') {
        const cached = await getStatsCache(env);
        if (cached) return json({ ok: true, ...cached, cached: true });

        const items = await dbAll(env, 'SELECT id, name, stock, per_limit, enchant FROM items');
        const map = {};
        items.forEach((r) => {
          const i = rowToItem(r);
          map[i.id] = { id: i.id, name: i.name, stock: i.stock, perLimit: i.perLimit, pending: 0, approved: 0, rejected: 0, total: 0 };
        });
        const rows = await dbAll(env, `
          SELECT ai.item_id AS itemId, ai.item_name AS itemName, a.status AS status,
                 COUNT(*) AS cnt, COALESCE(SUM(ai.qty), 0) AS qtySum
          FROM app_items ai JOIN applications a ON a.id = ai.app_id
          GROUP BY ai.item_id, a.status
        `);
        rows.forEach((r) => {
          const key = r.itemId;
          // 物资被删除后不该再出现在"一览"里；抽奖奖品的 id 也不属于物资清单，一并忽略
          if (!map[key]) return;
          if (map[key].approvedQty == null) map[key].approvedQty = 0;
          map[key].total += r.cnt;
          if (map[key][r.status] != null) map[key][r.status] += r.cnt;
          if (r.status === 'approved') map[key].approvedQty += Number(r.qtySum) || 0;
        });
        const totalRow = await dbGet(env, 'SELECT COUNT(*) AS c FROM applications');
        const result = {
          stats: Object.values(map),
          totalApps: totalRow ? totalRow.c : 0,
        };
        await setStatsCache(env, result);
        return json({ ok: true, ...result, cached: false });
      }

      if (path === 'recent') {
        const rows = await dbAll(env, 'SELECT * FROM applications ORDER BY created_at DESC LIMIT 30');
        // 物资被删后，历史记录里仍保留名字，但标注"已下架"，不冒充还能领
        const alive = await dbAll(env, 'SELECT id FROM items');
        const aliveSet = {};
        alive.forEach((r) => { aliveSet[r.id] = 1; });
        const list = [];
        for (const r of rows) {
          const its = await dbAll(env, 'SELECT item_id as id, item_name as name, COALESCE(qty,1) as qty FROM app_items WHERE app_id = ?', r.id);
          const items = its.map((x) => ({ ...x, gone: !aliveSet[x.id] }));
          const p = publicApp(rowToApp(r, items));
          delete p.userNote;   // 玩家留言只给审核看，公开列表不泄露
          list.push(p);
        }
        return json({ ok: true, list });
      }

      // ---- 公告：进入页面直接弹出 ----
      if (path === 'announce') {
        return json({ ok: true, ...(await getAnnounce(env)) });
      }

      // ---- 抽奖：奖池 + 我下次能抽的时间 ----
      if (path === 'lottery/info') {
        const hours = await lotteryHours(env);
        const pRows = await dbAll(env, 'SELECT id, name, weight, stock FROM lottery_prizes ORDER BY created_at');
        const prizes = pRows.map(rowToPrize);
        const uToken = url.searchParams.get('token') || '';
        const u = uToken ? await getUserById(env, await userTokenToId(env, uToken)) : null;
        let nextAt = 0, logged = false;
        if (u) {
          const last = await lastDrawAt(env, u.id);
          if (last && hours > 0) {
            const until = last + hours * 3600 * 1000;
            if (until > Date.now()) nextAt = until;
          }
          logged = true;
        }
        const logRows = await dbAll(env,
          'SELECT game_name, prize_name, created_at FROM lottery_log ORDER BY created_at DESC LIMIT 12');
        return json({
          ok: true, prizes, hours, logged,
          needLogin: !u,
          nextAt, nextText: nextAt ? fmtTime(nextAt) : '',
          log: logRows.map((r) => ({ gameName: r.game_name, prizeName: r.prize_name, at: r.created_at, atText: fmtTime(r.created_at) })),
        });
      }

      if (path === 'status') {
        const gameName = url.searchParams.get('gameName') || '';
        const clientId = url.searchParams.get('clientId') || '';
        const now = Date.now();
        const gn = norm(gameName);
        const conds = [];
        const params = [];
        if (gn) { conds.push('LOWER(TRIM(game_name)) = ?'); params.push(gn); }
        if (clientId) { conds.push('client_id = ?'); params.push(clientId); }
        const _st = url.searchParams.get('token') || '';
        const _su = _st ? await getUserById(env, await userTokenToId(env, _st)) : null;
        if (_su) { conds.push('user_id = ?'); params.push(_su.id); }
        if (!conds.length) {
          return json({ ok: true, locked: false });
        }
        const rows = await dbAll(env, 'SELECT * FROM applications WHERE ' + conds.join(' OR ') + ' ORDER BY created_at DESC', ...params);
        for (const r of rows) {
          const a = rowToApp(r, []);
          if (a.status === 'pending') {
            return json({ ok: true, locked: true, reason: 'pending', until: 0, untilText: '', app: publicApp(a) });
          }
          if (a.status === 'approved' && (a.cooldownUntil || 0) > now) {
            return json({ ok: true, locked: true, reason: 'cooldown', until: a.cooldownUntil, untilText: fmtTime(a.cooldownUntil), app: publicApp(a) });
          }
        }
        return json({ ok: true, locked: false });
      }

      // 管理页初始化：只回"是否还没人设过密码"，不泄露任何数据
      if (path === 'admin/status') {
        await ensureAdminTable(env);
        const a = await getAdmin(env);
        return json({ ok: true, needSetup: !a });
      }

      if (path === 'admin/list') {
        const token = url.searchParams.get('token') || '';
        const role = await getRole(env, token);
        if (!role) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        // 协管若还挂着"必须改初始密码"，除改密码外一律拦住
        if (role === 'subadmin') {
          const s = await getSub(env);
          if (s && Number(s.must_change) === 1) {
            return json({ ok: false, error: '请先修改初始密码', mustChange: true }, 403);
          }
        }
        const itemRows = await dbAll(env, 'SELECT id, name, stock, per_limit, enchant FROM items ORDER BY created_at');
        const items = itemRows.map((r) => rowToItem(r));
        const rows = await dbAll(env, `
          SELECT * FROM applications
          ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 WHEN 'rejected' THEN 2 ELSE 9 END,
                   created_at DESC
        `);
        const list = [];
        for (const r of rows) {
          const its = await dbAll(env, 'SELECT item_id as id, item_name as name, COALESCE(qty,1) as qty FROM app_items WHERE app_id = ?', r.id);
          const app = rowToApp(r, its);
          list.push({ ...publicApp(app), clientId: app.clientId });
        }
        return json({
          ok: true, items, list, role,
          quota: role === 'subadmin' ? await subQuotaLeft(env) : null,
        });
      }

      // ---- 玩家自己的信息：账号 / 团队 / 待处理邀请 ----
      if (path === 'user/me') {
        const token = url.searchParams.get('token') || '';
        const u = await getUserById(env, await userTokenToId(env, token));
        if (!u) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        return json({ ok: true, ...(await buildMePayload(env, u)) });
      }

      // ---- 射击游戏：查自己的战绩 ----
      if (path === 'game/stats') {
        const token = url.searchParams.get('token') || '';
        const u = await getUserById(env, await userTokenToId(env, token));
        if (!u) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        return json({ ok: true, gameName: u.game_name, stats: await gameStatsOf(env, u.id) });
      }

      // ---- 射击游戏：排行榜（按击杀降序，前 N 名）----
      if (path === 'game/rank') {
        let n = Number(url.searchParams.get('limit') || 20);
        if (!Number.isFinite(n) || n < 1) n = 20;
        if (n > 100) n = 100;
        const rows = await dbAll(env,
          'SELECT game_name, wins, losses, kills, games FROM game_stats WHERE games > 0 ORDER BY kills DESC, wins DESC LIMIT ?',
          Math.floor(n));
        return json({ ok: true, list: rows.map((r) => ({
          gameName: r.game_name || '', ...normStats(r),
        })) });
      }

      // ---- 后台：团队一览 ----
      if (path === 'admin/teams') {
        const token = url.searchParams.get('token') || '';
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const ts = await teamSettings(env);
        const teams = await dbAll(env, 'SELECT * FROM teams ORDER BY created_at DESC');
        const out = [];
        for (const t of teams) {
          const ms = await dbAll(env, 'SELECT id, game_name, created_at FROM users WHERE team_id = ? ORDER BY created_at', t.id);
          out.push({
            id: t.id,
            name: t.name,
            ownerId: t.owner_id,
            size: ms.length,
            mul: teamMultiplier(ms.length, ts),
            members: ms.map((m) => ({ id: m.id, gameName: m.game_name, isOwner: m.id === t.owner_id })),
          });
        }
        return json({ ok: true, teams: out, settings: ts });
      }

      // ---- 后台：抽奖机奖品一览（带库存和权重） ----
      if (path === 'admin/lottery') {
        const token = url.searchParams.get('token') || '';
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const pRows = await dbAll(env, 'SELECT id, name, weight, stock FROM lottery_prizes ORDER BY created_at');
        const logRows = await dbAll(env,
          'SELECT game_name, prize_name, created_at FROM lottery_log ORDER BY created_at DESC LIMIT 30');
        return json({
          ok: true,
          prizes: pRows.map(rowToPrize),
          hours: await lotteryHours(env),
          announce: await getAnnounce(env),
          log: logRows.map((r) => ({ gameName: r.game_name, prizeName: r.prize_name, atText: fmtTime(r.created_at) })),
        });
      }
    }

    // ============ POST ============
    if (request.method === 'POST') {
      const body = await request.json().catch(() => ({}));

      // 统一取角色；协管若还挂着"必须改初始密码"，除改密码 / 登录 / 退出外全部拦下
      const _tk = String(body.token || '');
      const _role = _tk ? await getRole(env, _tk) : null;
      const GUARDED = [
        'admin/items', 'admin/approve', 'admin/reject', 'admin/note',
        'admin/delete', 'admin/settings', 'admin/reset-sub-password', 'admin/team',
        'admin/lottery', 'admin/announce',
      ];
      if (_role === 'subadmin' && GUARDED.indexOf(path) >= 0) {
        const s = await getSub(env);
        if (s && Number(s.must_change) === 1) {
          return json({ ok: false, error: '请先修改初始密码（登录后必须换成你自己的新密码）', mustChange: true }, 403);
        }
      }

      // ================= 玩家账号：注册 / 登录 / 退出 =================
      if (path === 'user/register') {
        if (!env.APP_KV) return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 500);
        const gameName = String(body.gameName || '').trim();
        const pwd = String(body.password || '');
        if (gameName.length < 2) return json({ ok: false, error: '游戏名至少 2 个字' }, 400);
        if (gameName.length > 24) return json({ ok: false, error: '游戏名太长（最多 24 字）' }, 400);
        if (pwd.length < USER_PWD_MIN) return json({ ok: false, error: `密码至少 ${USER_PWD_MIN} 位` }, 400);
        const exist = await getUserByName(env, gameName);
        if (exist) return json({ ok: false, error: '这个游戏名已被注册，换一个或直接登录' }, 409);

        const salt = randomHex(16);
        const hash = await hashPwd(pwd, salt, PBKDF2_ITER);
        const id = uid();
        await dbRun(env,
          'INSERT INTO users (id, game_name, name_key, pass_hash, salt, iterations, team_id, created_at) VALUES (?,?,?,?,?,?,?,?)',
          id, gameName, norm(gameName), hash, salt, PBKDF2_ITER, '', Date.now());
        const token = await newUserSession(env, id);
        const u = await getUserById(env, id);
        return json({ ok: true, token, ...(await buildMePayload(env, u)) });
      }

      if (path === 'user/login') {
        if (!env.APP_KV) return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 500);
        const gameName = String(body.gameName || '').trim();
        const pwd = String(body.password || '');
        const u = await getUserByName(env, gameName);
        const okHash = u ? safeEq(await hashPwd(pwd, u.salt, Number(u.iterations) || PBKDF2_ITER), u.pass_hash) : false;
        if (!u || !okHash) return json({ ok: false, error: '游戏名或密码不对' }, 401);
        const token = await newUserSession(env, u.id);
        return json({ ok: true, token, ...(await buildMePayload(env, u)) });
      }

      if (path === 'user/logout') {
        const t = String(body.token || '');
        if (t && env.APP_KV) await env.APP_KV.delete('utoken:' + t);
        return json({ ok: true });
      }

      // ---- 射击游戏：上报一局结果 ----
      if (path === 'game/report') {
        const token = String(body.token || '');
        const u = await getUserById(env, await userTokenToId(env, token));
        if (!u) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const win = body.win === true || body.win === 1 || body.win === '1' || body.win === 'true';
        const stats = await gameAddResult(env, u.id, u.game_name, win, body.kills);
        return json({ ok: true, gameName: u.game_name, stats });
      }

      // ================= 团队 =================
      if (path === 'user/team') {
        const token = String(body.token || '');
        const u = await getUserById(env, await userTokenToId(env, token));
        if (!u) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const op = String(body.op || '');

        // 建队
        if (op === 'create') {
          if (u.team_id) return json({ ok: false, error: '你已经在团队里了，要先退出才能建新队' }, 400);
          const name = String(body.name || '').trim().slice(0, 20);
          if (!name) return json({ ok: false, error: '请填团队名' }, 400);
          const tid = uid();
          await dbRun(env, 'INSERT INTO teams (id, name, owner_id, created_at) VALUES (?,?,?,?)', tid, name, u.id, Date.now());
          await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', tid, u.id);
          return json({ ok: true, msg: '团队已创建', ...(await buildMePayload(env, await getUserById(env, u.id))) });
        }

        // 邀请别人（必须对方同意）
        if (op === 'invite') {
          if (!u.team_id) return json({ ok: false, error: '你还没有团队' }, 400);
          const ts = await teamSettings(env);
          const n = await teamMemberCount(env, u.team_id);
          if (ts.maxSize > 0 && n >= ts.maxSize) return json({ ok: false, error: `团队最多 ${ts.maxSize} 人` }, 400);
          const target = await getUserByName(env, String(body.gameName || ''));
          if (!target) return json({ ok: false, error: '找不到这个游戏名（对方要先注册账号）' }, 404);
          if (target.id === u.id) return json({ ok: false, error: '不能邀请自己' }, 400);
          if (target.team_id) return json({ ok: false, error: '对方已经在团队里了' }, 400);
          const dup = await dbGet(env, "SELECT id FROM team_invites WHERE team_id = ? AND invitee_id = ? AND status = 'pending'", u.team_id, target.id);
          if (dup) return json({ ok: false, error: '已经邀请过了，等对方同意' }, 400);
          await dbRun(env,
            'INSERT INTO team_invites (id, team_id, inviter_id, invitee_id, status, created_at) VALUES (?,?,?,?,?,?)',
            uid(), u.team_id, u.id, target.id, 'pending', Date.now());
          return json({ ok: true, msg: `已向「${target.game_name}」发出邀请，等他同意` });
        }

        // 同意 / 拒绝邀请
        if (op === 'respond') {
          const inv = await dbGet(env, "SELECT * FROM team_invites WHERE id = ? AND invitee_id = ? AND status = 'pending'", String(body.inviteId || ''), u.id);
          if (!inv) return json({ ok: false, error: '邀请不存在或已处理' }, 404);
          const accept = !!body.accept;
          if (accept) {
            if (u.team_id) return json({ ok: false, error: '你已经在别的团队里了' }, 400);
            const ts = await teamSettings(env);
            const n = await teamMemberCount(env, inv.team_id);
            if (ts.maxSize > 0 && n >= ts.maxSize) return json({ ok: false, error: '这个团队已经满员了' }, 400);
            await dbRun(env, "UPDATE team_invites SET status = 'accepted' WHERE id = ?", inv.id);
            await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', inv.team_id, u.id);
            // 其余待处理邀请作废
            await dbRun(env, "UPDATE team_invites SET status = 'declined' WHERE invitee_id = ? AND status = 'pending'", u.id);
          } else {
            await dbRun(env, "UPDATE team_invites SET status = 'declined' WHERE id = ?", inv.id);
          }
          return json({ ok: true, msg: accept ? '已加入团队' : '已拒绝邀请', ...(await buildMePayload(env, await getUserById(env, u.id))) });
        }

        // 退出团队
        if (op === 'leave') {
          if (!u.team_id) return json({ ok: false, error: '你还没有团队' }, 400);
          const t = await dbGet(env, 'SELECT * FROM teams WHERE id = ?', u.team_id);
          if (!t) { await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', '', u.id); return json({ ok: true, msg: '已退出', ...(await buildMePayload(env, u)) }); }
          await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', '', u.id);
          const left = await dbAll(env, 'SELECT id FROM users WHERE team_id = ? ORDER BY created_at', t.id);
          if (!left.length) {
            await disbandTeam(env, t.id);                       // 人走光了就解散
          } else if (t.owner_id === u.id) {
            await dbRun(env, 'UPDATE teams SET owner_id = ? WHERE id = ?', left[0].id, t.id);  // 队长走了，交给最早加入的人
          }
          return json({ ok: true, msg: '已退出团队', ...(await buildMePayload(env, await getUserById(env, u.id))) });
        }

        // 队长踢人
        if (op === 'kick') {
          if (!u.team_id) return json({ ok: false, error: '你还没有团队' }, 400);
          const t = await dbGet(env, 'SELECT * FROM teams WHERE id = ?', u.team_id);
          if (!t || t.owner_id !== u.id) return json({ ok: false, error: '只有队长能踢人' }, 403);
          const targetId = String(body.userId || '');
          if (targetId === u.id) return json({ ok: false, error: '不能踢自己，用「退出团队」' }, 400);
          const tgt = await getUserById(env, targetId);
          if (!tgt || tgt.team_id !== t.id) return json({ ok: false, error: '这个人不在你的团队里' }, 404);
          await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', '', tgt.id);
          await dbRun(env, "UPDATE team_invites SET status = 'cancelled' WHERE team_id = ? AND invitee_id = ? AND status = 'pending'", t.id, tgt.id);
          const left = await dbAll(env, 'SELECT id FROM users WHERE team_id = ?', t.id);
          if (!left.length) await disbandTeam(env, t.id);
          return json({ ok: true, msg: `已把「${tgt.game_name}」移出团队`, ...(await buildMePayload(env, await getUserById(env, u.id))) });
        }

        return json({ ok: false, error: '未知的团队操作' }, 400);
      }

      // ================= 后台：团队管理 =================
      if (path === 'admin/team') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const op = String(body.op || '');
        if (op === 'setSettings') {
          let bonus = Number(body.bonus);
          let cap = Number(body.cap);
          let maxSize = Number(body.maxSize);
          bonus = Number.isFinite(bonus) ? Math.max(0, Math.min(20, bonus)) : 1;
          cap = Number.isFinite(cap) ? Math.max(0, Math.min(999, Math.floor(cap))) : 0;
          maxSize = Number.isFinite(maxSize) ? Math.max(0, Math.min(999, Math.floor(maxSize))) : 0;
          await setSetting(env, 'team_bonus', bonus);
          await setSetting(env, 'team_cap', cap);
          await setSetting(env, 'team_max_size', maxSize);
          return json({ ok: true, settings: await teamSettings(env) });
        }
        if (op === 'disband') {
          const t = await dbGet(env, 'SELECT * FROM teams WHERE id = ?', String(body.teamId || ''));
          if (!t) return json({ ok: false, error: '团队不存在' }, 404);
          await disbandTeam(env, t.id);
          return json({ ok: true, msg: '已解散' });
        }
        if (op === 'removeMember') {
          const uid2 = String(body.userId || '');
          const tgt = await getUserById(env, uid2);
          if (!tgt || !tgt.team_id) return json({ ok: false, error: '这个玩家没有团队' }, 404);
          const tid = tgt.team_id;
          await dbRun(env, 'UPDATE users SET team_id = ? WHERE id = ?', '', uid2);
          const left = await dbAll(env, 'SELECT id FROM users WHERE team_id = ? ORDER BY created_at', tid);
          if (!left.length) await disbandTeam(env, tid);
          else {
            const t = await dbGet(env, 'SELECT * FROM teams WHERE id = ?', tid);
            if (t && t.owner_id === uid2) await dbRun(env, 'UPDATE teams SET owner_id = ? WHERE id = ?', left[0].id, tid);
          }
          return json({ ok: true, msg: '已移出团队' });
        }
        return json({ ok: false, error: '未知的团队管理操作' }, 400);
      }

      // ---- 提交申请 ----
      // ---- 抽奖：按权重抽，中了的奖品变成一条待审核申请 ----
      if (path === 'lottery/draw') {
        const uToken = String(body.token || '');
        const u = await getUserById(env, await userTokenToId(env, uToken));
        if (!u) return json({ ok: false, error: '请先注册并登录后再抽奖', needLogin: true }, 401);

        const hours = await lotteryHours(env);
        const last = await lastDrawAt(env, u.id);
        if (last && hours > 0) {
          const until = last + hours * 3600 * 1000;
          if (until > Date.now()) {
            return json({
              ok: false, locked: true, until, untilText: fmtTime(until),
              error: `每 ${hours} 小时只能抽一次，下次可抽：${fmtTime(until)}`,
            }, 403);
          }
        }

        const pRows = await dbAll(env, 'SELECT id, name, weight, stock FROM lottery_prizes ORDER BY created_at');
        const prizes = pRows.map(rowToPrize);
        const hit = pickPrize(prizes);
        if (!hit) return json({ ok: false, error: '奖池为空或已全部抽完' }, 400);

        // 库存扣减：只有设了具体数量（>=0）的才扣，"充足"(-1) 不扣
        if (hit.stock > 0) {
          await dbRun(env, 'UPDATE lottery_prizes SET stock = ? WHERE id = ?', hit.stock - 1, hit.id);
        }

        // 中奖结果生成一条待审核申请，由管理发放
        const nowMs = Date.now();
        const appId = uid();
        const teamSize = u.team_id ? await teamMemberCount(env, u.team_id) : 0;
        await dbRun(env,
          'INSERT INTO applications (id, game_name, client_id, user_id, team_size, status, created_at, decided_at, cooldown_until, cooldown_text, note, user_note, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
          appId, u.game_name, '', u.id, teamSize, 'pending', nowMs, 0, 0, '', '', '抽奖中奖', 'lottery');
        await dbRun(env, 'INSERT INTO app_items (app_id, item_id, item_name, qty) VALUES (?,?,?,?)',
          appId, hit.id, hit.name, 1);
        await dbRun(env,
          'INSERT INTO lottery_log (id, user_id, game_name, prize_id, prize_name, app_id, created_at) VALUES (?,?,?,?,?,?,?)',
          uid(), u.id, u.game_name, hit.id, hit.name, appId, nowMs);

        await clearStatsCache(env);
        const app = rowToApp({
          id: appId, game_name: u.game_name, client_id: '', status: 'pending',
          created_at: nowMs, decided_at: 0, cooldown_until: 0, cooldown_text: '',
          note: '', user_note: '抽奖中奖', source: 'lottery',
        }, [{ id: hit.id, name: hit.name, qty: 1 }]);
        const nextAt = hours > 0 ? nowMs + hours * 3600 * 1000 : 0;
        return json({
          ok: true, prize: { id: hit.id, name: hit.name },
          app: publicApp(app),
          nextAt, nextText: nextAt ? fmtTime(nextAt) : '',
        });
      }

      // ---- 后台：抽奖机设置（加 / 改 / 删奖品、设抽奖间隔） ----
      if (path === 'admin/lottery') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);

        if (body.op === 'hours') {
          let v = Number(body.hours);
          if (!Number.isFinite(v) || v < 0) v = 0;
          await setSetting(env, 'lottery_hours', Math.min(9999, v));
        } else if (body.op === 'add') {
          const name = String(body.name || '').trim();
          if (!name) return json({ ok: false, error: '奖品名不能为空' }, 400);
          let w = Math.floor(Number(body.weight));
          if (!Number.isFinite(w) || w < 1) w = 1;
          if (w > 9999) w = 9999;
          const stock = body.stock == null || body.stock === '' ? -1 : Math.max(-1, Math.floor(Number(body.stock) || 0));
          await dbRun(env,
            'INSERT INTO lottery_prizes (id, name, weight, stock, created_at) VALUES (?,?,?,?,?)',
            uid(), name, w, stock, Date.now());
        } else if (body.op === 'update') {
          const id = String(body.id || '');
          const row = await dbGet(env, 'SELECT id FROM lottery_prizes WHERE id = ?', id);
          if (!row) return json({ ok: false, error: '奖品不存在' }, 404);
          const sets = [], args = [];
          if (body.name != null) { const n = String(body.name).trim(); if (n) { sets.push('name = ?'); args.push(n); } }
          if (body.weight != null) {
            let w = Math.floor(Number(body.weight));
            if (!Number.isFinite(w) || w < 1) w = 1;
            sets.push('weight = ?'); args.push(Math.min(9999, w));
          }
          if (body.stock != null) {
            const v = body.stock === '' ? -1 : Math.max(-1, Math.floor(Number(body.stock) || 0));
            sets.push('stock = ?'); args.push(v);
          }
          if (!sets.length) return json({ ok: false, error: '没有要改的内容' }, 400);
          args.push(id);
          await dbRun(env, `UPDATE lottery_prizes SET ${sets.join(', ')} WHERE id = ?`, ...args);
        } else if (body.op === 'delete') {
          await dbRun(env, 'DELETE FROM lottery_prizes WHERE id = ?', String(body.id || ''));
        } else if (body.op === 'clearLog') {
          await dbRun(env, 'DELETE FROM lottery_log');
        } else {
          return json({ ok: false, error: '未知操作' }, 400);
        }

        const pRows = await dbAll(env, 'SELECT id, name, weight, stock FROM lottery_prizes ORDER BY created_at');
        return json({ ok: true, prizes: pRows.map(rowToPrize), hours: await lotteryHours(env) });
      }

      // ---- 后台：公告（玩家进入页面直接弹出） ----
      if (path === 'admin/announce') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const text = String(body.text == null ? '' : body.text).slice(0, 1000);
        const updatedAt = Date.now();
        await setSetting(env, 'announcement', { text: text.trim(), updatedAt });
        return json({ ok: true, text: text.trim(), updatedAt });
      }

      if (path === 'apply' || path === 'me/apply') {
        // 必须登录：游戏名直接用账号里的，防止乱填别人的名字
        const uToken = String(body.token || '');
        const u = await getUserById(env, await userTokenToId(env, uToken));
        if (!u) return json({ ok: false, error: '请先注册并登录后再申请', needLogin: true }, 401);
        const mul = await userMultiplier(env, u);
        const teamSize = u.team_id ? await teamMemberCount(env, u.team_id) : 0;

        const gameName = u.game_name;
        const clientId = String(body.clientId || '').trim();
        const itemIds = Array.isArray(body.itemIds) ? body.itemIds : [];
        const wantList = Array.isArray(body.items) ? body.items : null;

        if (!wantList && !itemIds.length) return json({ ok: false, error: '请至少勾选一项物资' }, 400);

        const rows = await dbAll(env, 'SELECT id, name, stock, per_limit, enchant FROM items');
        if (!rows.length) return json({ ok: false, error: '物资清单为空，请联系管理' }, 400);
        const itemMap = {};
        rows.forEach((r) => { const it = rowToItem(r, mul); itemMap[it.id] = it; });

        // 组装本次申请的物资 + 数量（兼容旧版只传 itemIds 的情况，那时默认 1 个）
        const wanted = [];
        if (wantList) {
          for (const w of wantList) {
            const it = itemMap[w && w.id];
            if (it) wanted.push({ it, qty: Number(w && w.qty) || 1 });
          }
        } else {
          itemIds.forEach((id) => { if (itemMap[id]) wanted.push({ it: itemMap[id], qty: 1 }); });
        }
        if (!wanted.length) return json({ ok: false, error: '所选物资无效' }, 400);

        // 数量校验：既不能超过后台设的"单次上限"，也不能超过现存库存
        for (const w of wanted) {
          const max = maxQtyOf(w.it);
          if (!Number.isFinite(w.qty) || w.qty < 1) {
            return json({ ok: false, error: `「${w.it.name}」的数量无效` }, 400);
          }
          if (w.qty > max) {
            // 谁的约束更紧，就报谁的原因，提示才准确
            const byStock = w.it.stock >= 0 && w.it.stock <= max;
            const msg = byStock
              ? `「${w.it.name}」库存不足，现存 ${w.it.stock} 个`
              : (w.it.perLimit > 0 ? `「${w.it.name}」单次最多 ${w.it.perLimit} 个` : `「${w.it.name}」单次最多 ${max} 个`);
            return json({ ok: false, error: msg }, 400);
          }
          w.qty = Math.floor(w.qty);
        }

        // 重复 / 冷却检查
        const now = Date.now();
        const gn = norm(gameName);
        const conds = [];
        const params = [];
        if (gn) { conds.push('LOWER(TRIM(game_name)) = ?'); params.push(gn); }
        if (clientId) { conds.push('client_id = ?'); params.push(clientId); }
        conds.push('user_id = ?'); params.push(u.id);   // 登录后才可能重复，按账号查
        if (conds.length) {
          const rows = await dbAll(env, 'SELECT * FROM applications WHERE ' + conds.join(' OR '), ...params);
          for (const r of rows) {
            const a = rowToApp(r, []);
            if (a.status === 'pending') {
              return json({ ok: false, error: '你已有待审核的申请，请等待处理', locked: true }, 403);
            }
            if (a.status === 'approved' && (a.cooldownUntil || 0) > now) {
              return json({ ok: false, error: `已通过审核，需等到 ${fmtTime(a.cooldownUntil)} 才能再次申请`, locked: true, until: a.cooldownUntil }, 403);
            }
          }
        }

        // 玩家留言：给审核看的说明，最长 200 字，超出自动截断（防灌水）
        const userNote = String(body.userNote == null ? '' : body.userNote).trim().slice(0, 200);

        const id = uid();
        const nowMs = Date.now();
        await dbRun(env,
          'INSERT INTO applications (id, game_name, client_id, user_id, team_size, status, created_at, decided_at, cooldown_until, cooldown_text, note, user_note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
          id, gameName, clientId, u.id, teamSize, 'pending', nowMs, 0, 0, '', '', userNote);
        const stmts = wanted.map((w) =>
          env.DB.prepare('INSERT INTO app_items (app_id, item_id, item_name, qty) VALUES (?,?,?,?)').bind(id, w.it.id, w.it.name, w.qty));
        await env.DB.batch(stmts);

        await clearStatsCache(env);
        const app = rowToApp({ id, game_name: gameName, client_id: clientId, status: 'pending', created_at: nowMs, decided_at: 0, cooldown_until: 0, cooldown_text: '', note: '', user_note: userNote },
          wanted.map((w) => ({ id: w.it.id, name: w.it.name, qty: w.qty })));
        return json({ ok: true, app: publicApp(app) });
      }

      // ---- 首次进入：设置管理密码（只在从未设置过时可用，之后永久关闭） ----
      if (path === 'admin/setup') {
        if (!env.APP_KV) return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 500);
        await ensureAdminTable(env);
        const exist = await getAdmin(env);
        if (exist) return json({ ok: false, error: '管理密码已设置过，无法再次注册', needSetup: false }, 403);

        const pwd = String(body.password || '');
        const pwd2 = String(body.password2 || '');
        if (pwd.length < 8) return json({ ok: false, error: '密码至少 8 位（建议 12 位以上，字母+数字+符号混合）' }, 400);
        if (pwd !== pwd2) return json({ ok: false, error: '两次输入的密码不一致' }, 400);

        const salt = randomHex(16);
        const hash = await hashPwd(pwd, salt, PBKDF2_ITER);
        try {
          await dbRun(env,
            'INSERT INTO admin (id, pass_hash, salt, iterations, created_at, updated_at) VALUES (?,?,?,?,?,?)',
            'admin', hash, salt, PBKDF2_ITER, Date.now(), 0);
        } catch (e) {
          // 主键冲突 = 有人抢先设置了
          return json({ ok: false, error: '管理密码已存在（可能已被他人抢先设置）', needSetup: false }, 409);
        }
        const token = uid();
        await env.APP_KV.put('token:' + token, '1', { expirationTtl: SESSION_TTL });
        return json({ ok: true, token, firstSetup: true });
      }

      // ---- 管理登录（PBKDF2 校验 + IP 限流防爆破） ----
      if (path === 'admin/login') {
        if (!env.APP_KV) return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 500);
        await ensureAdminTable(env);
        const admin = await getAdmin(env);
        if (!admin) return json({ ok: false, error: '尚未设置管理密码，请先设置', needSetup: true }, 400);

        const ip = request.headers.get('cf-connecting-ip') || 'unknown';
        const failKey = 'loginfail:' + ip;
        const lockKey = 'loginlock:' + ip;

        if (await env.APP_KV.get(lockKey)) {
          return json({ ok: false, error: '密码错误次数过多，已锁定 15 分钟', locked: true }, 429);
        }

        const pwd = String(body.password || '');
        const hash = await hashPwd(pwd, admin.salt, admin.iterations || PBKDF2_ITER);
        if (!safeEq(hash, admin.pass_hash)) {
          const n = Number((await env.APP_KV.get(failKey)) || 0) + 1;
          await env.APP_KV.put(failKey, String(n), { expirationTtl: LOGIN_LOCK_TTL });
          if (n >= LOGIN_MAX_FAIL) await env.APP_KV.put(lockKey, '1', { expirationTtl: LOGIN_LOCK_TTL });
          const left = Math.max(0, LOGIN_MAX_FAIL - n);
          return json({ ok: false, error: `密码错误，还可尝试 ${left} 次（超出锁定 15 分钟）`, left }, 401);
        }

        await env.APP_KV.delete(failKey);
        await env.APP_KV.delete(lockKey);
        const token = uid();
        await env.APP_KV.put('token:' + token, '1', { expirationTtl: SESSION_TTL });
        return json({ ok: true, token });
      }

      // ---- 修改自己这个账号的密码（需已登录，验证旧密码 + 新密码 + 确认新密码） ----
      if (path === 'admin/change-password') {
        const token = String(body.token || '');
        const role = await getRole(env, token);
        if (!role) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const who = role === 'subadmin' ? 'subadmin' : 'admin';
        const row = await getAdminRow(env, who);
        if (!row) return json({ ok: false, error: '账号不存在' }, 400);
        const oldPwd = String(body.oldPassword || '');
        const newPwd = String(body.newPassword || '');
        const newPwd2 = String(body.newPassword2 == null ? '' : body.newPassword2);
        if (newPwd.length < 8) return json({ ok: false, error: '新密码至少 8 位' }, 400);
        if (newPwd2 && newPwd !== newPwd2) return json({ ok: false, error: '两次输入的新密码不一致' }, 400);
        if (oldPwd === newPwd) return json({ ok: false, error: '新密码不能和旧密码一样' }, 400);
        const oldHash = await hashPwd(oldPwd, row.salt, row.iterations || PBKDF2_ITER);
        if (!safeEq(oldHash, row.pass_hash)) return json({ ok: false, error: '旧密码错误' }, 401);
        const salt = randomHex(16);
        const hash = await hashPwd(newPwd, salt, PBKDF2_ITER);
        // 改完必须清掉"强制改密码"标记，否则协管会一直被拦在改密码这一步
        await dbRun(env,
          'UPDATE admin SET pass_hash = ?, salt = ?, iterations = ?, must_change = 0, updated_at = ? WHERE id = ?',
          hash, salt, PBKDF2_ITER, Date.now(), who);
        return json({ ok: true });
      }

      // ---- 受限管理（协管）登录 ----
      if (path === 'sub/login') {
        if (!env.APP_KV) return json({ ok: false, error: '服务暂不可用，请稍后再试。' + bindingHint(env) }, 500);
        await ensureAdminTable(env);
        const sub = await getSub(env);
        if (!sub) return json({ ok: false, error: '副管理账号尚未开通，请让主管理先在后台「副管理」卡片里点「开通副管理」' }, 400);

        const ip = request.headers.get('cf-connecting-ip') || 'unknown';
        const failKey = 'subfail:' + ip;
        const lockKey = 'sublock:' + ip;
        if (await env.APP_KV.get(lockKey)) {
          return json({ ok: false, error: '密码错误次数过多，已锁定 15 分钟', locked: true }, 429);
        }

        const pwd = String(body.password || '');
        const hash = await hashPwd(pwd, sub.salt, sub.iterations || PBKDF2_ITER);
        if (!safeEq(hash, sub.pass_hash)) {
          const n = Number((await env.APP_KV.get(failKey)) || 0) + 1;
          await env.APP_KV.put(failKey, String(n), { expirationTtl: LOGIN_LOCK_TTL });
          if (n >= LOGIN_MAX_FAIL) await env.APP_KV.put(lockKey, '1', { expirationTtl: LOGIN_LOCK_TTL });
          const left = Math.max(0, LOGIN_MAX_FAIL - n);
          return json({ ok: false, error: `密码错误，还可尝试 ${left} 次（超出锁定 15 分钟）`, left }, 401);
        }

        await env.APP_KV.delete(failKey);
        await env.APP_KV.delete(lockKey);
        const token = uid();
        await env.APP_KV.put('token:' + token, 'subadmin', { expirationTtl: SESSION_TTL });
        // mustChange=1：用初始密码登进来的，必须先换一个新密码才能干别的
        return json({ ok: true, token, mustChange: Number(sub.must_change) === 1 });
      }

      // ---- 主管理：查看副管理状态 ----
      if (path === 'admin/sub-status') {
        const token = String(body.token || '');
        if (!(await isAdmin(env, token))) return json({ ok: false, error: '只有主管理可以操作副管理' }, 403);
        await ensureAdminTable(env);
        const s = await getSub(env);
        return json({
          ok: true,
          enabled: !!s,
          createdAt: s ? Number(s.created_at || 0) : 0,
          updatedAt: s ? Number(s.updated_at || 0) : 0,
          mustChange: s ? Number(s.must_change) === 1 : false,
          defaultPassword: '12345678',
          quota: await subQuotaConfig(env),
        });
      }

      // ---- 主管理：设置副管理的增删额度（次数上限 + 间隔小时数） ----
      if (path === 'admin/sub-quota') {
        const token = String(body.token || '');
        if (!(await isAdmin(env, token))) return json({ ok: false, error: '只有主管理可以操作' }, 403);
        if (body.op === 'set') {
          let limit = Number(body.limit);
          if (!Number.isFinite(limit)) limit = SUB_QUOTA_DEFAULT;
          limit = Math.min(999, Math.max(0, Math.floor(limit)));
          let hours = Number(body.hours);
          if (!Number.isFinite(hours) || hours <= 0) hours = SUB_WINDOW_HOURS_DEFAULT;
          hours = Math.min(9999, hours);
          await setSetting(env, 'sub_quota_limit', limit);
          await setSetting(env, 'sub_quota_hours', hours);
          return json({ ok: true, quota: { limit, hours } });
        }
        return json({ ok: true, quota: await subQuotaConfig(env) });
      }

      // ---- 主管理：停用副管理（删账号并踢掉其登录） ----
      if (path === 'admin/disable-sub') {
        const token = String(body.token || '');
        if (!(await isAdmin(env, token))) return json({ ok: false, error: '只有主管理可以操作副管理' }, 403);
        await ensureAdminTable(env);
        await dbRun(env, 'DELETE FROM admin WHERE id = ?', 'subadmin');
        try {
          const lst = await env.APP_KV.list({ prefix: 'token:' });
          for (const k of (lst.keys || [])) {
            if (await env.APP_KV.get(k.name) === 'subadmin') await env.APP_KV.delete(k.name);
          }
        } catch (e) { /* KV list 不可用时忽略 */ }
        return json({ ok: true });
      }

      // ---- 主管理：把协管密码重置成 12345678，并强制其下次登录改密码 ----
      if (path === 'admin/reset-sub-password') {
        const token = String(body.token || '');
        if (!(await isAdmin(env, token))) return json({ ok: false, error: '只有主管理可以重置协管密码' }, 403);
        const DEFAULT_SUB_PWD = '12345678';
        const salt = randomHex(16);
        const hash = await hashPwd(DEFAULT_SUB_PWD, salt, PBKDF2_ITER);
        const exist = await getSub(env);
        if (exist) {
          await dbRun(env,
            'UPDATE admin SET pass_hash = ?, salt = ?, iterations = ?, must_change = 1, updated_at = ? WHERE id = ?',
            hash, salt, PBKDF2_ITER, Date.now(), 'subadmin');
        } else {
          await dbRun(env,
            'INSERT INTO admin (id, pass_hash, salt, iterations, must_change, created_at, updated_at) VALUES (?,?,?,?,?,?,?)',
            'subadmin', hash, salt, PBKDF2_ITER, 1, Date.now(), 0);
        }
        // 把协管已登录的会话踢掉，逼他用初始密码重新登录
        try {
          const lst = await env.APP_KV.list({ prefix: 'token:' });
          for (const k of (lst.keys || [])) {
            if (await env.APP_KV.get(k.name) === 'subadmin') await env.APP_KV.delete(k.name);
          }
        } catch (e) { /* KV list 不可用时忽略：协管的旧会话会被"请先改初始密码"拦住，一样安全 */ }
        return json({ ok: true, defaultPassword: DEFAULT_SUB_PWD });
      }

      // ---- 物资管理（协管也能改，但新增/删除受 3 小时 3 次的额度限制） ----
      if (path === 'admin/items') {
        const token = String(body.token || '');
        const role = await getRole(env, token);
        if (!role) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const action = body.action;
        const quotaHit = (action === 'add' || action === 'delete');

        // 额度检查：只对协管生效，主管理不限
        let quota = null;
        if (role === 'subadmin' && quotaHit) {
          quota = await subQuotaLeft(env);
          if (quota.left <= 0) {
            return json({
              ok: false, quota,
              error: `新增/删除额度已用完：3 小时内最多 ${quota.limit} 次，${quota.resetText || '稍后'} 之后恢复`,
            }, 429);
          }
        }

        if (action === 'add') {
          const name = String(body.name || '').trim();
          if (!name) return json({ ok: false, error: '物资名不能为空' }, 400);
          const exist = await dbGet(env, 'SELECT id FROM items WHERE name = ?', name);
          if (exist) return json({ ok: false, error: '已存在同名物资' }, 400);
          const stock = body.stock == null || body.stock === '' ? -1 : Math.max(-1, Math.floor(Number(body.stock) || 0));
          const perLimit = body.perLimit == null || body.perLimit === '' ? 0 : Math.max(0, Math.floor(Number(body.perLimit) || 0));
          const enchant = String(body.enchant == null ? '' : body.enchant).trim().slice(0, 200);
          await dbRun(env, 'INSERT INTO items (id, name, stock, per_limit, enchant, created_at) VALUES (?,?,?,?,?,?)',
            uid(), name, stock, perLimit, enchant, Date.now());
          if (role === 'subadmin') await subConsume(env, 'add', name);
        } else if (action === 'update') {
          // 改库存 / 改单次上限 / 改名（三选一或一起改）
          const id = String(body.id || '');
          const row = await dbGet(env, 'SELECT id FROM items WHERE id = ?', id);
          if (!row) return json({ ok: false, error: '物资不存在' }, 404);
          const sets = [], args = [];
          if (body.name != null) { const n = String(body.name).trim(); if (n) { sets.push('name = ?'); args.push(n); } }
          if (body.stock != null) {
            const v = body.stock === '' ? -1 : Math.max(-1, Math.floor(Number(body.stock) || 0));
            sets.push('stock = ?'); args.push(v);
          }
          if (body.perLimit != null) {
            const v = body.perLimit === '' ? 0 : Math.max(0, Math.floor(Number(body.perLimit) || 0));
            sets.push('per_limit = ?'); args.push(v);
          }
          if (body.enchant != null) {
            sets.push('enchant = ?'); args.push(String(body.enchant).trim().slice(0, 200));
          }
          if (!sets.length) return json({ ok: false, error: '没有要改的内容' }, 400);
          args.push(id);
          await dbRun(env, `UPDATE items SET ${sets.join(', ')} WHERE id = ?`, ...args);
        } else if (action === 'rename') {
          const name = String(body.name || '').trim();
          if (!name) return json({ ok: false, error: '物资名不能为空' }, 400);
          await dbRun(env, 'UPDATE items SET name = ? WHERE id = ?', name, body.id);
          await dbRun(env, 'UPDATE app_items SET item_name = ? WHERE item_id = ?', name, body.id);
        } else if (action === 'delete') {
          const g = await dbGet(env, 'SELECT name FROM items WHERE id = ?', body.id);
          await dbRun(env, 'DELETE FROM items WHERE id = ?', body.id);
          if (role === 'subadmin') await subConsume(env, 'delete', g ? g.name : '');
          // 历史申请里的 item_name 保留，旧记录不丢（app_items 不删）
        } else {
          return json({ ok: false, error: '未知操作' }, 400);
        }

        await clearStatsCache(env);
        const itemRows = await dbAll(env, 'SELECT id, name, stock, per_limit, enchant FROM items ORDER BY created_at');
        return json({
          ok: true,
          items: itemRows.map((r) => rowToItem(r)),
          quota: role === 'subadmin' ? await subQuotaLeft(env) : null,
        });
      }

      // ---- 全局设置：默认冷却时间 ----
      if (path === 'admin/settings') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);

        if (body.op === 'set') {
          let value = Number(body.value);
          if (!Number.isFinite(value) || value < 0) value = 0;
          if (value > 9999) value = 9999;
          const unit = normalizeUnit(body.unit);
          await setSetting(env, 'default_cooldown', { value, unit });
          let autoDeduct = await getSetting(env, 'auto_deduct', true);
          if (body.autoDeduct != null) {
            autoDeduct = !!body.autoDeduct;
            await setSetting(env, 'auto_deduct', autoDeduct);
          }
          return json({ ok: true, cooldown: { value, unit }, autoDeduct: autoDeduct !== false });
        }

        const def = await getSetting(env, 'default_cooldown', DEFAULT_COOLDOWN);
        const autoDeduct = await getSetting(env, 'auto_deduct', true);
        return json({
          ok: true,
          cooldown: {
            value: Number.isFinite(Number(def && def.value)) ? Number(def.value) : DEFAULT_COOLDOWN.value,
            unit: normalizeUnit(def && def.unit),
          },
          autoDeduct: autoDeduct !== false,
          team: await teamSettings(env),
        });
      }

      // ---- 审核通过（带恢复时间） ----
      if (path === 'admin/approve') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const row = await dbGet(env, 'SELECT * FROM applications WHERE id = ?', body.id);
        if (!row) return json({ ok: false, error: '申请不存在' }, 404);

        // 冷却时长：优先用弹窗里填的；若前端请求"用默认值"或没填，则套用后台设置的默认冷却
        let value = Number(body.value);
        let unit = normalizeUnit(body.unit);
        if (body.useDefault || !Number.isFinite(value) || value < 0) {
          const def = await getSetting(env, 'default_cooldown', DEFAULT_COOLDOWN);
          value = Number(def && def.value);
          unit = normalizeUnit(def && def.unit);
          if (!Number.isFinite(value) || value < 0) value = DEFAULT_COOLDOWN.value;
        }
        if (!Number.isFinite(value) || value < 0) value = 0;
        const hours = unitToHours(value, unit);
        const now = Date.now();
        const cooldownUntil = hours > 0 ? now + hours * 3600 * 1000 : 0;
        const cooldownText = hours > 0 ? `${value}${UNIT_LABEL[unit]}` : '无冷却';
        const note = body.note != null ? String(body.note) : row.note;

        await dbRun(env,
          'UPDATE applications SET status = ?, decided_at = ?, cooldown_until = ?, cooldown_text = ?, note = ? WHERE id = ?',
          'approved', now, cooldownUntil, cooldownText, note, body.id);

        // 通过后自动扣库存（默认开；只有原本不是"已通过"时才扣，避免重复通过导致重复扣）
        let deducted = false;
        const autoDeduct = await getSetting(env, 'auto_deduct', true);
        if (autoDeduct !== false && row.status !== 'approved') {
          const its = await dbAll(env, 'SELECT item_id AS id, COALESCE(qty,1) AS qty FROM app_items WHERE app_id = ?', body.id);
          for (const it of its) {
            const q = Math.floor(Number(it.qty) || 1);
            if (q <= 0) continue;
            await dbRun(env, 'UPDATE items SET stock = MAX(0, stock - ?) WHERE id = ? AND stock >= 0', q, it.id);
          }
          deducted = its.length > 0;
        }

        await clearStatsCache(env);
        const app = await loadApp(env, body.id);
        return json({ ok: true, app: publicApp(app), deducted });
      }

      // ---- 拒绝 ----
      if (path === 'admin/reject') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const row = await dbGet(env, 'SELECT * FROM applications WHERE id = ?', body.id);
        if (!row) return json({ ok: false, error: '申请不存在' }, 404);
        const note = body.note != null ? String(body.note) : row.note;
        await dbRun(env,
          'UPDATE applications SET status = ?, decided_at = ?, cooldown_until = ?, cooldown_text = ?, note = ? WHERE id = ?',
          'rejected', Date.now(), 0, '', note, body.id);
        await clearStatsCache(env);
        const app = await loadApp(env, body.id);
        return json({ ok: true, app: publicApp(app) });
      }

      // ---- 备注 ----
      if (path === 'admin/note') {
        const token = String(body.token || '');
        if (!(await isStaff(env, token))) return json({ ok: false, error: '未登录或登录已过期' }, 401);
        const row = await dbGet(env, 'SELECT * FROM applications WHERE id = ?', body.id);
        if (!row) return json({ ok: false, error: '申请不存在' }, 404);
        await dbRun(env, 'UPDATE applications SET note = ? WHERE id = ?', String(body.note || ''), body.id);
        await clearStatsCache(env);
        const app = await loadApp(env, body.id);
        return json({ ok: true, app: publicApp(app) });
      }

      // ---- 删除申请（只有主管理能删，协管不行） ----
      if (path === 'admin/delete') {
        const token = String(body.token || '');
        const rmRole = await getRole(env, token);
        if (rmRole !== 'admin') {
          return json({
            ok: false,
            error: rmRole === 'subadmin' ? '受限管理不能删除申请记录' : '未登录或登录已过期',
          }, rmRole ? 403 : 401);
        }
        await env.DB.batch([
          env.DB.prepare('DELETE FROM app_items WHERE app_id = ?').bind(body.id),
          env.DB.prepare('DELETE FROM applications WHERE id = ?').bind(body.id),
        ]);
        await clearStatsCache(env);
        return json({ ok: true });
      }

      // ---- 退出 ----
      if (path === 'admin/logout') {
        const token = String(body.token || '');
        if (token && env.APP_KV) await env.APP_KV.delete('token:' + token);
        return json({ ok: true });
      }
    }

    return json({ ok: false, error: '未知接口：' + path }, 404);
  } catch (e) {
    return json({ ok: false, error: String((e && e.message) || e) }, 500);
  }
}

// ================= Pages Advanced Mode（_worker.js 入口）=================
// Cloudflare 官方限制：Dashboard 拖拽上传「不认」functions/ 目录，但「认」_worker.js。
// 所以把后端合并进这个文件：一次拖拽就能把前端+后端一起部署，不用 GitHub、不用终端。
// 请求分流：/api/* 走下面的 API 逻辑，其余（HTML/robots.txt）交给 env.ASSETS 静态资源。
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return onRequest({ request, env });
    }
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not Found', { status: 404 });
  },
};
