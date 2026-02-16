const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const app = express();
const port = process.env.PORT || 3000;

// --- PASSPORT & SESSION SETUP ---

// Make sure to add SESSION_SECRET, DISCORD_CLIENT_ID, and DISCORD_CLIENT_SECRET to your environment variables on Render.
app.use(session({
    secret: process.env.SESSION_SECRET || 'default_session_secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// The URL must match EXACTLY what you entered in the Discord Developer Portal
const discordCallbackUrl = process.env.RENDER_EXTERNAL_URL ? `${process.env.RENDER_EXTERNAL_URL}/auth/discord/callback` : `http://localhost:${port}/auth/discord/callback`;

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: discordCallbackUrl,
    scope: ['identify']
}, (accessToken, refreshToken, profile, done) => {
    // In a real app, you'd find or create a user in your database here.
    // For now, we'll just pass the Discord profile through.
    return done(null, profile);
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    done(null, obj);
});

// Middleware to check if the user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/'); // Redirect to login page if not authenticated
}

// --- END PASSPORT SETUP ---


app.use(express.json());
app.use(express.static(__dirname));

// Database Paths
const SCRIPT_FILE = path.join(__dirname, 'protected_script.lua');
const DB_FILE = path.join(__dirname, 'database.json');

// Initialize Database if not exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: {}, whitelist: {} }, null, 2));
}
if (!fs.existsSync(SCRIPT_FILE)) {
    fs.writeFileSync(SCRIPT_FILE, 'print("Welcome to Pulse Joiner! No script loaded yet.")');
}

// Helper: Read DB
function getDb() {
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        return { users: {} };
    }
}

// Helper: Write DB
function saveDb(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// --- AUTH ROUTES ---

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', passport.authenticate('discord', {
    failureRedirect: '/'
}), (req, res) => {
    res.redirect('/admin'); // Successful login redirects to the admin panel
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});


// --- API ROUTES ---

// 1. Verify Key (Called by Roblox)
app.get('/api/verify', (req, res) => {
    const { key } = req.query;
    
    if (!key) return res.status(400).send("No key provided");

    const db = getDb();
    let foundUser = null;

    // Find user by key
    const whitelist = db.whitelist || {};
    const users = db.users || {};
    
    // Check Bot Schema (whitelist)
    for (const userId in whitelist) {
        const user = whitelist[userId];
        if ((user.panelKeys && user.panelKeys['default'] === key) || user.scriptKey === key) {
            foundUser = user;
            break;
        }
    }

    // Check Simple Schema (users) - if not found in whitelist
    if (!foundUser) {
        for (const userId in users) {
            if (users[userId].key === key) {
                foundUser = users[userId];
                break;
            }
        }
    }

    if (!foundUser) {
        return res.send("game.Players.LocalPlayer:Kick('Pulse Joiner: Invalid Key')");
    }

    // Check Expiry
    const now = Date.now();
    const expiresAt = new Date(foundUser.expiresAt).getTime();
    
    if (expiresAt < now) { 
        return res.send("game.Players.LocalPlayer:Kick('Pulse Joiner: Key Expired')");
    }

    // Valid! Return the real script
    const scriptContent = fs.readFileSync(SCRIPT_FILE, 'utf8');
    res.send(scriptContent);
});

// 2. Admin: Save Script (Now requires authentication)
app.post('/api/admin/save-script', ensureAuthenticated, (req, res) => {
    const { content } = req.body;

    if (content) {
        fs.writeFileSync(SCRIPT_FILE, content);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: "No script content" });
    }
});

// 3. Admin: Get Script (Now requires authentication)
app.get('/api/admin/get-script', ensureAuthenticated, (req, res) => {
    const script = fs.readFileSync(SCRIPT_FILE, 'utf8');
    res.json({ script });
});

// --- PAGE ROUTES ---

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// The root route is now protected
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'main.html'));
    } else {
        res.redirect('/login');
    }
});

// Route to serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// The admin panel is now on a protected route, for the admin only
app.get('/admin', (req, res) => {
    // We need to check for both authentication and if the user is the admin.
    // The user profile from Discord is in req.user.
    // Make sure to add ADMIN_USER_ID to your environment variables.
    if (!req.isAuthenticated() || req.user.id !== process.env.ADMIN_USER_ID) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
