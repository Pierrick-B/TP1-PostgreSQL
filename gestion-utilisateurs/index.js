const express = require('express');
const pool = require('./database/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/api/health', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({
            status: 'OK',
            database: 'Connected',
            timestamp: result.rows[0].now
        });
    } catch (error) {
        console.error('Erreur health check:', error);
        res.status(500).json({
            status: 'ERROR',
            database: 'Disconnected',
            error: error.message
        });
    }
});

// Route racine
app.get('/', (req, res) => {
    res.json({
        message: 'API Gestion Utilisateurs',
        version: '1.0.0',
        endpoints: {
            health: 'GET /api/health',
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login',
                logout: 'POST /api/auth/logout',
                profile: 'GET /api/auth/profile',
                logs: 'GET /api/auth/logs'
            },
            users: {
                list: 'GET /api/users',
                get: 'GET /api/users/:id',
                update: 'PUT /api/users/:id',
                delete: 'DELETE /api/users/:id',
                permissions: 'GET /api/users/:id/permissions'
            }
        }
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});
