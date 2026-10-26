
'use strict';

require('dotenv').config();

const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Op, ValidationError, UniqueConstraintError,
    ForeignKeyConstraintError } = require('sequelize');
const db = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET ||
    Buffer.byteLength(process.env.JWT_SECRET, 'utf8') < 32) {
    throw new Error('JWT_SECRET must contain at least 32 bytes');
}

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// ---------- HELPERS ----------

function validId(value) {
    if (typeof value !== 'string' && typeof value !== 'number') {
        return false;
    }
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0;
}

function validText(value, maxLength = 255) {
    return typeof value === 'string' &&
        value.trim().length > 0 &&
        value.trim().length <= maxLength;
}

function handleError(res, error) {
    console.error('API error:', error);

    if (error instanceof UniqueConstraintError) {
        return res.status(409).json({ error: 'Record already exists' });
    }

    if (error instanceof ValidationError ||
        error instanceof ForeignKeyConstraintError) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    return res.status(500).json({ error: 'Internal server error' });
}

// ---------- PASSPORT LOCAL ----------

passport.use('local', new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password',
        session: false
    },
    async (email, password, done) => {
        try {
            if (typeof email !== 'string' ||
                typeof password !== 'string') {
                return done(null, false);
            }

            const user = await db.User.findOne({
                where: { email: email.trim().toLowerCase() }
            });

            if (!user) return done(null, false);

            const matches = await bcrypt.compare(
                password,
                user.password
            );

            if (!matches) return done(null, false);

            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
));

// ---------- PASSPORT JWT ----------

passport.use('jwt', new JwtStrategy(
    {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: process.env.JWT_SECRET,
        algorithms: ['HS256']
    },
    async (payload, done) => {
        try {
            if (!validId(payload.id)) {
                return done(null, false);
            }

            const user = await db.User.findByPk(payload.id);
            return done(null, user || false);
        } catch (error) {
            return done(error);
        }
    }
));

app.use(passport.initialize());

const requireAuth = passport.authenticate('jwt', {
    session: false
});

// ---------- HEALTH CHECK ----------

app.get('/', (req, res) => {
    return res.json({
        message: 'Hybridge Blog API',
        status: 'running',
        database: 'PostgreSQL',
        authentication: 'JWT'
    });
});

// ---------- AUTHENTICATION ----------

// Register a user
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body || {};

        if (!validText(name, 255) ||
            typeof email !== 'string' ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
            email.trim().length > 255 ||
            typeof password !== 'string' ||
            password.length < 8 ||
            Buffer.byteLength(password, 'utf8') > 72) {
            return res.status(400).json({
                error: 'Valid name, email and password required'
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const hash = await bcrypt.hash(password, 12);

        const user = await db.User.create({
            name: name.trim(),
            email: normalizedEmail,
            password: hash
        });

        return res.status(201).json({
            id: user.id,
            name: user.name,
            email: user.email
        });
    } catch (error) {
        return handleError(res, error);
    }
});

// Login and issue JWT
app.post('/api/login',
    passport.authenticate('local', { session: false }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user.id },
            process.env.JWT_SECRET,
            {
                algorithm: 'HS256',
                expiresIn: '1h'
            }
        );

        return res.status(200).json({
            token,
            token_type: 'Bearer',
            expires_in: 3600
        });
    }
);

// Protected profile
app.get('/api/profile', requireAuth, (req, res) => {
    return res.status(200).json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
    });
});

// ---------- AUTHORS CRUD ----------

// CREATE - Protected
app.post('/api/authors', requireAuth, async (req, res) => {
    try {
        const { name } = req.body || {};

        if (!validText(name, 255)) {
            return res.status(400).json({
                error: 'Valid author name required'
            });
        }

        const author = await db.Author.create({
            name: name.trim()
        });

        return res.status(201).json(author);
    } catch (error) {
        return handleError(res, error);
    }
});

// READ - All authors
app.get('/api/authors', async (req, res) => {
    try {
        const authors = await db.Author.findAll({
            order: [['id', 'ASC']]
        });

        return res.status(200).json(authors);
    } catch (error) {
        return handleError(res, error);
    }
});

// READ - Author by ID
app.get('/api/authors/:id', async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid author ID' });
        }

        const author = await db.Author.findByPk(
            Number(req.params.id)
        );

        if (!author) {
            return res.status(404).json({ error: 'Author not found' });
        }

        return res.status(200).json(author);
    } catch (error) {
        return handleError(res, error);
    }
});

// UPDATE - Protected
app.patch('/api/authors/:id', requireAuth, async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid author ID' });
        }

        const author = await db.Author.findByPk(
            Number(req.params.id)
        );

        if (!author) {
            return res.status(404).json({ error: 'Author not found' });
        }

        const { name } = req.body || {};

        if (!validText(name, 255)) {
            return res.status(400).json({
                error: 'Valid author name required'
            });
        }

        await author.update({ name: name.trim() });
        return res.status(200).json(author);
    } catch (error) {
        return handleError(res, error);
    }
});

// DELETE - Protected, soft deletion
app.delete('/api/authors/:id', requireAuth, async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid author ID' });
        }

        const author = await db.Author.findByPk(
            Number(req.params.id)
        );

        if (!author) {
            return res.status(404).json({ error: 'Author not found' });
        }

        // Prevent deleting an author with active publications.
        const activePosts = await db.Post.count({
            where: { authorId: author.id }
        });

        if (activePosts > 0) {
            return res.status(409).json({
                error: 'Author has active publications'
            });
        }

        await author.destroy();
        return res.status(204).send();
    } catch (error) {
        return handleError(res, error);
    }
});

// ---------- POSTS CRUD ----------

// CREATE - Protected
app.post('/api/posts', requireAuth, async (req, res) => {
    try {
        const { title, content, authorId } = req.body || {};

        if (!validText(title, 255) ||
            !validText(content, 100000) ||
            !validId(authorId)) {
            return res.status(400).json({
                error: 'Valid title, content and authorId required'
            });
        }

        const author = await db.Author.findByPk(Number(authorId));

        if (!author) {
            return res.status(404).json({ error: 'Author not found' });
        }

        const post = await db.Post.create({
            title: title.trim(),
            content: content.trim(),
            authorId: author.id
        });

        return res.status(201).json(post);
    } catch (error) {
        return handleError(res, error);
    }
});

// READ - All posts
app.get('/api/posts', async (req, res) => {
    try {
        const posts = await db.Post.findAll({
            order: [['id', 'ASC']]
        });

        return res.status(200).json(posts);
    } catch (error) {
        return handleError(res, error);
    }
});

// READ - Post by ID
app.get('/api/posts/:id', async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid post ID' });
        }

        const post = await db.Post.findByPk(
            Number(req.params.id)
        );

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        return res.status(200).json(post);
    } catch (error) {
        return handleError(res, error);
    }
});

// UPDATE - Protected
app.patch('/api/posts/:id', requireAuth, async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid post ID' });
        }

        const post = await db.Post.findByPk(
            Number(req.params.id)
        );

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const { title, content, authorId } = req.body || {};
        const changes = {};

        if (title !== undefined) {
            if (!validText(title, 255)) {
                return res.status(400).json({ error: 'Invalid title' });
            }
            changes.title = title.trim();
        }

        if (content !== undefined) {
            if (!validText(content, 100000)) {
                return res.status(400).json({ error: 'Invalid content' });
            }
            changes.content = content.trim();
        }

        if (authorId !== undefined) {
            if (!validId(authorId)) {
                return res.status(400).json({ error: 'Invalid author ID' });
            }

            const author = await db.Author.findByPk(Number(authorId));

            if (!author) {
                return res.status(404).json({
                    error: 'Author not found'
                });
            }

            changes.authorId = author.id;
        }

        if (Object.keys(changes).length === 0) {
            return res.status(400).json({
                error: 'No valid fields provided'
            });
        }

        await post.update(changes);
        return res.status(200).json(post);
    } catch (error) {
        return handleError(res, error);
    }
});

// DELETE - Protected, soft deletion
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
    try {
        if (!validId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid post ID' });
        }

        const post = await db.Post.findByPk(
            Number(req.params.id)
        );

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        await post.destroy();
        return res.status(204).send();
    } catch (error) {
        return handleError(res, error);
    }
});

// ---------- FALLBACK ----------

app.use((req, res) => {
    return res.status(404).json({
        error: 'Endpoint not found'
    });
});

// ---------- SERVER ----------

async function startServer() {
    try {
        await db.sequelize.authenticate();

        console.log('PostgreSQL connection successful');

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Database connection failed:', error.message);
        process.exitCode = 1;
    }
}

if (require.main === module) {
    startServer();
}

module.exports = app;
