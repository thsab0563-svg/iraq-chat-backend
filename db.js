// db.js
require('dotenv').config();
const { createClient } = require('@libsql/client');

// إنشاء الاتصال بقاعدة بيانات Turso
const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
});

// دالة لإنشاء الجداول إذا لم تكن موجودة (يجب استدعاؤها عند بدء السيرفر)
async function initDatabase() {
    try {
        // 1. جدول المستخدمين
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_hash TEXT,
                public_key TEXT,
                is_admin INTEGER DEFAULT 0,
                verified INTEGER DEFAULT 0,
                banned INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0,
                verification_expiry DATETIME,
                has_used_trial BOOLEAN DEFAULT 0,
                created_at INTEGER NOT NULL
            )
        `);

        // 2. جدول الرسائل
        await db.execute(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                text TEXT,
                created_at INTEGER NOT NULL,
                is_admin_message BOOLEAN DEFAULT 0,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
        `);

        // 3. جدول الأصدقاء
        await db.execute(`
            CREATE TABLE IF NOT EXISTS friendships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                friend_id INTEGER,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(friend_id) REFERENCES users(id)
            )
        `);

        // 4. جدول البلاغات
        await db.execute(`
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER,
                reported_user_id INTEGER,
                message_id INTEGER,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 5. جدول سجل الإدارة
        await db.execute(`
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ Database initialized successfully with Turso');
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
    }
}

// تصدير الاتصال والدالة
module.exports = { db, initDatabase };
