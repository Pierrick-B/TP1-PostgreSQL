const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');

// GET /api/users - Liste des utilisateurs avec pagination
router.get('/',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;

        try {
            // 1. Compter le total d'utilisateurs
            const countResult = await pool.query('SELECT COUNT(*) FROM utilisateurs');
            const total = parseInt(countResult.rows[0].count);

            // 2. Récupérer les utilisateurs avec leurs rôles
            const usersResult = await pool.query(
                `SELECT 
                    u.id,
                    u.email,
                    u.nom,
                    u.prenom,
                    u.actif,
                    u.date_creation,
                    COALESCE(array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL), ARRAY[]::VARCHAR[]) AS roles
                FROM utilisateurs u
                LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                LEFT JOIN roles r ON ur.role_id = r.id
                GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation
                ORDER BY u.id
                LIMIT $1 OFFSET $2`,
                [limit, offset]
            );

            res.json({
                users: usersResult.rows,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit)
                }
            });

        } catch (error) {
            console.error('Erreur liste utilisateurs:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// GET /api/users/:id - Détails d'un utilisateur
router.get('/:id',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const { id } = req.params;

        try {
            const result = await pool.query(
                `SELECT 
                    u.id,
                    u.email,
                    u.nom,
                    u.prenom,
                    u.actif,
                    u.date_creation,
                    u.date_modification,
                    COALESCE(array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL), ARRAY[]::VARCHAR[]) AS roles
                FROM utilisateurs u
                LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                LEFT JOIN roles r ON ur.role_id = r.id
                WHERE u.id = $1
                GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation, u.date_modification`,
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            res.json({ user: result.rows[0] });

        } catch (error) {
            console.error('Erreur détails utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// PUT /api/users/:id - Mettre à jour un utilisateur
router.put('/:id',
    requireAuth,
    requirePermission('users', 'write'),
    async (req, res) => {
        const { id } = req.params;
        const { nom, prenom, actif } = req.body;

        try {
            const result = await pool.query(
                `UPDATE utilisateurs
                 SET nom = $1, prenom = $2, actif = $3, date_modification = CURRENT_TIMESTAMP
                 WHERE id = $4
                 RETURNING id, email, nom, prenom, actif, date_modification`,
                [nom, prenom, actif, id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            res.json({
                message: 'Utilisateur mis à jour',
                user: result.rows[0]
            });

        } catch (error) {
            console.error('Erreur mise à jour utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// DELETE /api/users/:id - Supprimer un utilisateur
router.delete('/:id',
    requireAuth,
    requirePermission('users', 'delete'),
    async (req, res) => {
        const { id } = req.params;

        // Empêcher l'auto-suppression
        if (parseInt(id) === req.user.utilisateur_id) {
            return res.status(400).json({
                error: 'Vous ne pouvez pas supprimer votre propre compte'
            });
        }

        try {
            const result = await pool.query(
                `DELETE FROM utilisateurs WHERE id = $1 RETURNING id, email, nom, prenom`,
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            res.json({
                message: 'Utilisateur supprimé',
                user: result.rows[0]
            });

        } catch (error) {
            console.error('Erreur suppression utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

// GET /api/users/:id/permissions - Permissions d'un utilisateur
router.get('/:id/permissions',
    requireAuth,
    async (req, res) => {
        const { id } = req.params;

        try {
            // Récupérer toutes les permissions de l'utilisateur
            const result = await pool.query(
                `SELECT DISTINCT 
                    p.nom, 
                    p.ressource, 
                    p.action, 
                    p.description
                FROM utilisateurs u
                INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
                INNER JOIN permissions p ON rp.permission_id = p.id
                WHERE u.id = $1
                ORDER BY p.ressource, p.action`,
                [id]
            );

            res.json({
                utilisateur_id: parseInt(id),
                permissions: result.rows
            });

        } catch (error) {
            console.error('Erreur récupération permissions:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
);

module.exports = router;
