// require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const helmet = require('helmet');
const multer = require('multer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '-');
        cb(null, `${Date.now()}-${safeName}`);
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extension = path.extname(file.originalname).toLowerCase();
        const allowedExt = ['.jpeg', '.jpg', '.png', '.gif'];
        const isValid = allowedTypes.test(file.mimetype) && allowedExt.includes(extension);
        cb(null, isValid);
    },
    limits: { fileSize: 5 * 1024 * 1024 }
});

if (isProduction) {
    app.set('trust proxy', 1);
}
app.use(helmet());
app.use(session({
    secret: process.env.SESSION_SECRET || 'smart_trade_africa_secret_key_2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 1800000,
        sameSite: 'lax'
    }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@smarttrade.africa';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'STA_Admin#2026!Secure';

const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unaanza login kwanza.' });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.userId || !req.session.isAdmin) {
        return res.status(401).json({ success: false, message: 'Admin access required.' });
    }
    next();
};

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 8) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa barua pepe na nenosiri lenye urefu wa angalau herufi 8.' });
    }
    const userId = `USR-${crypto.randomUUID()}`;
    const passwordHash = bcrypt.hashSync(password, bcrypt.genSaltSync(12));

    const query = `INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)`;
    db.run(query, [userId, username.trim(), passwordHash], (err) => {
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
        req.session.isAdmin = false;
        res.json({ success: true, message: 'Umeingia kwa mafanikio!' });
    });
});

app.post('/api/admin-login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa jina la msimamizi na nenosiri.' });
    }
    if (username !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'Admin credentials invalid.' });
    }
    req.session.userId = 'ADMIN';
    req.session.username = 'admin';
    req.session.isAdmin = true;
    res.json({ success: true, message: 'Admin imeingia kwa mafanikio.' });
});

app.get('/api/admin-status', requireAdmin, (req, res) => {
    res.json({ success: true, message: 'Admin session active.' });
});

app.post('/api/logout', requireAuth, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kutoka.' });
        }
        res.json({ success: true, message: 'Umetoka kwa mafanikio.' });
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
        const resetId = `PR-${crypto.randomUUID()}`;
        const code = crypto.randomInt(100000, 1000000).toString();
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

app.post('/api/products', requireAdmin, (req, res) => {
    const { name, price, description, image_url } = req.body;
    const numericPrice = parseFloat(price);
    if (!name || isNaN(numericPrice) || numericPrice <= 0) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa jina na bei sahihi.' });
    }
    const query = `INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)`;
    db.run(query, [name.trim(), description || '', numericPrice, image_url || null], function(err) {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kuhifadhi bidhaa.' });
        }
        res.json({ success: true, message: 'Bidhaa imehifadhiwa.' });
    });
});

app.post('/api/products/upload', requireAdmin, upload.single('image'), (req, res) => {
    const { name, price, description } = req.body;
    const numericPrice = parseFloat(price);
    if (!name || isNaN(numericPrice) || numericPrice <= 0) {
        return res.status(400).json({ success: false, message: 'Tafadhali toa jina na bei sahihi.' });
    }
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Picha ya bidhaa inahitajika.' });
    }
    const imagePath = `uploads/${req.file.filename}`;
    const query = `INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)`;
    db.run(query, [name.trim(), description || '', numericPrice, imagePath], function(err) {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kuhifadhi bidhaa.' });
        }
        res.json({ success: true, message: 'Bidhaa imehifadhiwa.' });
    });
});

function processMockPayment(amount, userId) {
    const transactionId = `TXN-${crypto.randomUUID()}`;
    const referenceToken = `MOCK-${crypto.randomBytes(16).toString('hex')}`;
    return {
        success: true,
        transactionId,
        referenceToken,
        status: 'SUCCESSFUL',
        message: 'Mock payment processed successfully.'
    };
}

app.delete('/api/products/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    if (!id) {
        return res.status(400).json({ success: false, message: 'Product ID required.' });
    }
    const query = `DELETE FROM products WHERE id = ?`;
    db.run(query, [id], function(err) {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kufuta bidhaa.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ success: false, message: 'Bidhaa haikuonekana.' });
        }
        res.json({ success: true, message: 'Bidhaa imefutwa.' });
    });
});

app.post('/api/checkout', requireAuth, (req, res) => {
    const amount = parseFloat(req.body.amount);
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ success: false, message: 'Kiasi batili.' });
    }

    const paymentResult = processMockPayment(amount, req.session.userId);
    const query = `INSERT INTO transactions (id, user_id, amount, status, reference) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [paymentResult.transactionId, req.session.userId, amount, paymentResult.status, paymentResult.referenceToken], (err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Imeshindikana kuhifadhi malipo.' });
        }
        res.json({ success: true, status: paymentResult.status, token: paymentResult.referenceToken, message: paymentResult.message });
    });
});

app.get('/api/payment-status/:reference', requireAuth, (req, res) => {
    const { reference } = req.params;
    const query = `SELECT id, amount, status, reference, created_at FROM transactions WHERE reference = ? AND user_id = ?`;
    db.get(query, [reference, req.session.userId], (err, transaction) => {
        if (err || !transaction) {
            return res.status(404).json({ success: false, message: 'Malipo hayajapatikana.' });
        }
        res.json({ success: true, transaction });
    });
});

app.get('/api/transactions', requireAuth, (req, res) => {
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
