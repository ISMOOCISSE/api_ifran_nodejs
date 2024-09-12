require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// Connexion à la base de données MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connecté à la base de données MySQL');
});

// Middleware pour vérifier le token JWT
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Accès refusé' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token invalide' });
        req.user = user;
        next();
    });
};

// Endpoint d'inscription
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Veuillez fournir toutes les informations' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;

        const query = 'INSERT INTO students (name, email, password) VALUES (?, ?, ?)';
        db.query(query, [name, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Email déjà utilisé' });
                }
                throw err;
            }
            res.status(201).json({ message: 'Inscription réussie' });
        });
    });
});

// Endpoint de connexion
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Veuillez fournir un email et un mot de passe' });
    }

    const query = 'SELECT * FROM students WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
        }

        const student = results[0];
        bcrypt.compare(password, student.password, (err, isMatch) => {
            if (err) throw err;
            if (!isMatch) {
                return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
            }

            const token = jwt.sign({ id: student.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });
    });
});



// Endpoint pour récupérer les informations d'un étudiant par son ID
app.get('/api/student/:id', (req, res) => {
    const studentId = req.params.id;

    const query = 'SELECT * FROM etudiants WHERE id = ?';
    db.query(query, [studentId], (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.status(404).json({ message: 'Étudiant non trouvé' });
        }

        res.json(results[0]);
    });
});



// Endpoint pour récupérer l'emploi du temps d'un étudiant
app.get('/api/schedule', authenticateToken, (req, res) => {
    const studentId = req.user.id;

    const query = 'SELECT course_name, course_time FROM schedule WHERE student_id = ?';
    db.query(query, [studentId], (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.status(404).json({ message: 'Aucun emploi du temps trouvé' });
        }

        res.json(results);
    });
});



// Endpoint pour récupérer les données exportées
app.get('/api/export', (req, res) => {
    const queryClasses = 'SELECT * FROM classes';
    const queryEmploiDuTemps = 'SELECT * FROM emploi_du_temps';
    const queryEnseignants = 'SELECT * FROM enseignants';
    const queryEtudiants = 'SELECT * FROM etudiants';
    const queryModules = 'SELECT * FROM modules';
    const queryNotifications = 'SELECT * FROM notifications';
    const queryPresences = 'SELECT * FROM presences';
    const querySeances = 'SELECT * FROM seances';
    const queryTauxPresence = 'SELECT * FROM taux_presence';
    const queryUsersIfran = 'SELECT * FROM users_ifran';
    const queryVolumeCours = 'SELECT * FROM volume_cours';

    // Exécuter les requêtes SQL et renvoyer les résultats
    const promises = [
        db.promise().query(queryClasses),
        db.promise().query(queryEmploiDuTemps),
        db.promise().query(queryEnseignants),
        db.promise().query(queryEtudiants),
        db.promise().query(queryModules),
        db.promise().query(queryNotifications),
        db.promise().query(queryPresences),
        db.promise().query(querySeances),
        db.promise().query(queryTauxPresence),
        db.promise().query(queryUsersIfran),
        db.promise().query(queryVolumeCours),
    ];

    Promise.all(promises)
        .then((results) => {
            res.json({
                "type": "header",
                "version": "5.2.1",
                "comment": "Export to JSON plugin for PHPMyAdmin",
                "data": [
                    {
                        "type": "table",
                        "name": "classes",
                        "database": process.env.DB_DATABASE,
                        "data": results[0][0]
                    },
                    {
                        "type": "table",
                        "name": "emploi_du_temps",
                        "database": process.env.DB_DATABASE,
                        "data": results[1][0]
                    },
                    {
                        "type": "table",
                        "name": "enseignants",
                        "database": process.env.DB_DATABASE,
                        "data": results[2][0]
                    },
                    {
                        "type": "table",
                        "name": "etudiants",
                        "database": process.env.DB_DATABASE,
                        "data": results[3][0]
                    },
                    {
                        "type": "table",
                        "name": "modules",
                        "database": process.env.DB_DATABASE,
                        "data": results[4][0]
                    },
                    {
                        "type": "table",
                        "name": "notifications",
                        "database": process.env.DB_DATABASE,
                        "data": results[5][0]
                    },
                    {
                        "type": "table",
                        "name": "presences",
                        "database": process.env.DB_DATABASE,
                        "data": results[6][0]
                    },
                    {
                        "type": "table",
                        "name": "seances",
                        "database": process.env.DB_DATABASE,
                        "data": results[7][0]
                    },
                    {
                        "type": "table",
                        "name": "taux_presence",
                        "database": process.env.DB_DATABASE,
                        "data": results[8][0]
                    },
                    {
                        "type": "table",
                        "name": "users_ifran",
                        "database": process.env.DB_DATABASE,
                        "data": results[9][0]
                    },
                    {
                        "type": "table",
                        "name": "volume_cours",
                        "database": process.env.DB_DATABASE,
                        "data": results[10][0]
                    },
                ]
            });
        })
        .catch((error) => {
            res.status(500).json({ message: 'Erreur lors de la récupération des données', error });
        });
});



// Lancer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Serveur lancé sur le port ${PORT}`);
});
