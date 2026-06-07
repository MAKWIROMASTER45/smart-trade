const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./smarttrade.db');

// Kuunda meza za database kwa usalama wetu
db.serialize(() => {
    // 1. Table ya Watumiaji (Users) - Inazuia Fake Accounts
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // 2. Table ya Alama ya Kidole (Biometrics) - WebAuthn
    db.run(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // 3. Table ya Bidhaa (Products)
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        image_url TEXT
    )`);

    // 4. Table ya Malipo (Transactions) - Inasaidia kuleta uaminifu wa malipo
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL,
        reference TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // 5. Table ya Urejeshaji Nenosiri (Password Resets)
    db.run(`CREATE TABLE IF NOT EXISTS password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Tuweke bidhaa chache za majaribio kama kampuni ya Smart Trade Africa
    db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
        if (row.count === 0) {
            db.run(`INSERT INTO products (name, description, price, image_url) VALUES 
                ('Premium Coffee', 'Kahawa safi kutoka milima ya Kilimanjaro', 15000, 'coffee.jpg'),
                ('Smart Phone X', 'Simu ya kisasa yenye ulinzi wa juu', 450000, 'phone.jpg')`);
            console.log("Bidhaa za majaribio zimeongezwa kwa mafanikio!");
        }
    });
});

console.log("Database ya smarttrade.db imetengenezwa na ipo tayari!");
module.exports = db;