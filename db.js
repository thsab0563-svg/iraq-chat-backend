/* ============================================================
   db.js — Turso Database Connection & Clean Initialization
   ============================================================ */
'use strict';

require('dotenv').config();
const { createClient } = require('@libsql/client');

const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

if (!TURSO_URL || !TURSO_TOKEN) {
    console.error('❌ TURSO_DATABASE_URL or TURSO_AUTH_TOKEN is missing');
    process.exit(1);
}

const db = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN,
});

async function initDb() {
    // 1. فحص ما إذا كان المخطط قديماً (لا يحتوي على عمود deleted)
    let needsReset = false;
    try {
        await db.execute('SELECT deleted FROM users LIMIT 1');
    } catch (e) {
        if (e.message && (e.message.includes('no such column') || e.message.includes('no such table'))) {
            needsReset = true;
        }
    }

    // 2. إذا كان المخطط قديماً، احذف الجداول القديمة
    if (needsReset) {
        console.log('🔄 Old schema detected in Turso. Dropping old tables to recreate...');
        const tablesToDrop = ['reports', 'push_subs', 'dms', 'blocks', 'friendships', 'users', 'admin_logs'];
        for (const t of tablesToDrop) {
            try { await db.execute(`DROP TABLE IF EXISTS ${t}`); } catch(e) {}
        }
        console.log('✅ Old tables dropped successfully');
    }

    // 3. إنشاء الجداول بالمخطط الصحيح
    const schemaQueries = [
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            color TEXT DEFAULT '#e8b567',
            bio_enc TEXT, location_enc TEXT, avatar TEXT, avatar_id TEXT, cover TEXT,
            qr_id TEXT UNIQUE, token_hash TEXT NOT NULL, password_hash TEXT,
            security_q INTEGER, security_a_hash TEXT,
            theme TEXT DEFAULT 'light', sound INTEGER DEFAULT 1,
            created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
            public_key TEXT, is_admin INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
            banned INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
            verification_expiry DATETIME, has_used_trial BOOLEAN DEFAULT 0
        )`,
        `CREATE INDEX IF NOT EXISTS idx_users_qr ON users(qr_id)`,
        `CREATE INDEX IF NOT EXISTS idx_users_token ON users(token_hash)`,
        `CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, friend_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'accepted', time INTEGER NOT NULL,
            UNIQUE(user_id, friend_id)
        )`,
        `CREATE TABLE IF NOT EXISTS blocks (
            blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, time INTEGER NOT NULL,
            PRIMARY KEY (blocker_id, blocked_id)
        )`,
        `CREATE TABLE IF NOT EXISTS dms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, text TEXT NOT NULL,
            time INTEGER NOT NULL, delivered INTEGER DEFAULT 0, read INTEGER DEFAULT 0,
            edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
        )`,
        `CREATE INDEX IF NOT EXISTS idx_dms_from_to ON dms(from_id, to_id, time)`,
        `CREATE INDEX IF NOT EXISTS idx_dms_to ON dms(to_id, read)`,
        `CREATE TABLE IF NOT EXISTS push_subs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL, auth TEXT NOT NULL, time INTEGER NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL, reported_user_id INTEGER, reported_msg_id INTEGER,
            reason TEXT NOT NULL, note TEXT, msg_snapshot TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL, reviewed_at INTEGER, reviewed_by INTEGER, action TEXT
        )`,
        `CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)`,
        `CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT, details TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`
    ];

    for (const query of schemaQueries) {
        try {
            await db.execute(query);
        } catch (e) {
            console.error('Schema error:', e.message);
        }
    }

    // 4. التحقق النهائي: تأكد من وجود عمود deleted
    try {
        await db.execute('SELECT deleted FROM users LIMIT 1');
        console.log('✅ Database initialized successfully with Turso');
    } catch (e) {
        console.error('❌ Critical error: deleted column still missing!');
        console.error(e.message);
    }
}

module.exports = { db, initDb };
