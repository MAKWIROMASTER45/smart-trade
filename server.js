const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(session({
    secret: 'smart_trade_africa_secret_key_2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1800000, sameSite: 'lax' }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe na nenosiri.' });
    }
    const userId = 'USR-' + Math.floor(Math.random() * 1000000);
    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    const query = `INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)`;
    db.run(query, [userId, username, passwordHash], (err) => {
        if (err) {
            return res.status(400).json({ success: false, message: 'Mtumiaji tayari yupo au imekosea.' });
        }
        res.json({ success: true, message: 'Akaunti imesajiliwa kwa usalama!' });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe na nenosiri.' });
    }
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: 'Mtumiaji hapatikani!' });
        }
        const passwordIsValid = bcrypt.compareSync(password, user.password_hash);
        if (!passwordIsValid) {
            return res.status(401).json({ success: false, message: 'Nenosiri si sahihi!' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true, message: 'Umeingia kwa mafanikio!' });
    });
});

app.post('/api/password-reset-request', (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe.' });
    }
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: 'Mtumiaji hapatikani.' });
        }
        const resetId = 'PR-' + Math.floor(Math.random() * 1000000);
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = Date.now() + 15 * 60 * 1000;

        const insertQuery = `INSERT INTO password_resets (id, user_id, code, expires_at) VALUES (?, ?, ?, ?)`;
        db.run(insertQuery, [resetId, user.id, code, expiresAt], function(insertErr) {
            if (insertErr) {
                return res.status(500).json({ success: false, message: 'Imeshindikana kuomba urejeshaji.' });
            }
            res.json({ success: true, message: 'Msimbo umeandaliwa. Tumia msimbo wako kwa urejeshaji.', code });
        });
    });
});

app.post('/api/password-reset', (req, res) => {
    const { username, code, newPassword } = req.body;
    if (!username || !code || !newPassword) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe, msimbo, na nenosiri jipya.' });
    }
    if (newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'Nenosiri jipya lazima liwe angalau herufi 8.' });
    }
    const userQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(userQuery, [username], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: 'Mtumiaji hapatikani.' });
        }
        const resetQuery = `SELECT * FROM password_resets WHERE user_id = ? AND code = ?`;
        db.get(resetQuery, [user.id, code], (resetErr, resetRow) => {
            if (resetErr || !resetRow) {
                return res.status(400).json({ success: false, message: 'Msimbo sio sahihi au haupatikani.' });
            }
            if (Date.now() > resetRow.expires_at) {
                return res.status(400).json({ success: false, message: 'Msimbo umeisha muda.' });
            }
            const passwordHash = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
            const updateQuery = `UPDATE users SET password_hash = ? WHERE id = ?`;
            db.run(updateQuery, [passwordHash, user.id], function(updateErr) {
                if (updateErr) {
                    return res.status(500).json({ success: false, message: 'Imeshindikana kubadilisha nenosiri.' });
                }
                const deleteQuery = `DELETE FROM password_resets WHERE user_id = ?`;
                db.run(deleteQuery, [user.id], () => {
                    res.json({ success: true, message: 'Nenosiri jipya limehifadhiwa kwa usalama.' });
                });
            });
        });
    });
});

app.post('/api/biometric-auth', (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe.' });
    }
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: 'Mtumiaji hapatikani.' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true, message: 'Biometric login imekamilika kwa usalama.' });
    });
});

app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kupata bidhaa.' });
        }
        res.json(rows);
    });
});

app.post('/api/products', (req, res) => {
    const { name, price, description, image_url } = req.body;
    if (!name || !price || price <= 0) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa jina na bei sahihi.' });
    }
    const query = `INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)`;
    db.run(query, [name, description, price, image_url], function(err) {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kuhifadhi bidhaa.' });
        }
        res.json({ success: true, message: 'Bidhaa imehifadhiwa.' });
    });
});

app.post('/api/checkout', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unaanza login kwanza.' });
    }
    const amount = parseFloat(req.body.amount);
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ success: false, message: 'Kiasi batili.' });
    }
    const transactionId = 'TXN-' + Math.floor(Math.random() * 1000000);
    const referenceToken = 'MOCK-' + Math.floor(Math.random() * 1000000);
    const status = 'SUCCESSFUL';

    const query = `INSERT INTO transactions (id, user_id, amount, status, reference) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [transactionId, req.session.userId, amount, status, referenceToken], (err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kuhifadhi malipo.' });
        }
        res.json({ success: true, status, token: referenceToken, message: 'Malipo yamefanikiwa.' });
    });
});

app.get('/api/payment-status/:reference', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unaanza login kwanza.' });
    }
    const { reference } = req.params;
    const query = `SELECT id, amount, status, reference, created_at FROM transactions WHERE reference = ? AND user_id = ?`;
    db.get(query, [reference, req.session.userId], (err, transaction) => {
        if (err || !transaction) {
            return res.status(404).json({ success: false, message: 'Malipo hayajapatikana.' });
        }
        res.json({ success: true, transaction });
    });
});

app.get('/api/transactions', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unaanza login kwanza.' });
    }
    const query = `SELECT id, amount, status, reference, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC`;
    db.all(query, [req.session.userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kupata historia ya malipo.' });
        }
        res.json({ success: true, transactions: rows });
    });
});

app.use('/api', (req, res) => {
    res.status(404).json({ success: false, message: 'API route not found.' });
});

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Mfumo umerun tena kwa mafanikio kwenye: http://localhost:${PORT}`);
});
