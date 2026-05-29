// server.js - FG-Studio - Versión Optimizada y Corregida
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Compresión GZIP
app.use(compression({ level: 6, threshold: 1024 }));

// Seguridad
app.use(helmet({
    contentSecurityPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true
}));

// Rate limiting
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Demasiadas solicitudes' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Demasiados intentos de acceso' } });
app.use(globalLimiter);
app.use('/api/verify-admin', authLimiter);

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_KEY || !ADMIN_PASSWORD) {
    console.error('❌ ERROR: Faltan variables de entorno críticas');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });

// ============================================
// MIDDLEWARES PERSONALIZADOS
// ============================================
const ipBlacklist = new Set();
const security = {
    detectBruteForce(ip, endpoint) {
        // Implementación simplificada
        return false;
    },
    validatePhone(phone) {
        const digitsOnly = phone.replace(/\D/g, '');
        return digitsOnly.length >= 7 && digitsOnly.length <= 16;
    },
    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;').substring(0, 500);
    }
};

app.use((req, res, next) => {
    const ip = req.ip;
    if (ipBlacklist.has(ip)) return res.status(403).json({ error: 'Acceso denegado' });
    next();
});

// Archivos estáticos con caché optimizado
app.use(express.static(__dirname, {
    maxAge: '1y',
    immutable: true,
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
        } else if (filePath.match(/\.(css|js)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
        } else if (filePath.match(/\.(jpg|jpeg|png|gif|webp|svg|ico)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
    }
}));

// ============================================
// RUTAS DE API
// ============================================

// Autenticación Admin
app.post('/api/verify-admin', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const token = crypto.randomBytes(48).toString('hex');
        res.json({ success: true, token });
    } else {
        res.status(401).json({ success: false });
    }
});

// Configuración de Supabase para el frontend
app.get('/api/supabase-config', (req, res) => {
    res.json({
        url: process.env.SUPABASE_URL,
        anonKey: process.env.SUPABASE_ANON_KEY
    });
});

// ============================================
// CRUD CATÁLOGOS
// ============================================
app.get('/api/catalogos', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    try {
        const { data, error } = await supabase.from('catalogos').select('*').order('id');
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/catalogos', async (req, res) => {
    const { name, category, link, image, descripcion } = req.body;
    if (!name || !category || !link || !image) {
        return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    try {
        const { data, error } = await supabase.from('catalogos').insert([{
            name: security.sanitizeInput(name),
            category: security.sanitizeInput(category),
            link: security.sanitizeInput(link),
            image: security.sanitizeInput(image),
            descripcion: security.sanitizeInput(descripcion || '')
        }]).select();
        if (error) throw error;
        res.status(201).json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    const { name, category, link, image, descripcion } = req.body;
    try {
        const { error } = await supabase.from('catalogos').update({
            name: security.sanitizeInput(name),
            category: security.sanitizeInput(category),
            link: security.sanitizeInput(link),
            image: security.sanitizeInput(image),
            descripcion: security.sanitizeInput(descripcion || '')
        }).eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const { error } = await supabase.from('catalogos').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API DE CONTACTOS
// ============================================
app.post('/api/contactos', async (req, res) => {
    let { nombre, telefono, email, mensaje } = req.body;
    if (!nombre || !telefono || !mensaje) return res.status(400).json({ error: 'Campos requeridos faltantes' });
    if (!security.validatePhone(telefono)) return res.status(400).json({ error: 'Número inválido' });
    
    try {
        const { error } = await supabase.from('contactos').insert([{
            nombre: security.sanitizeInput(nombre),
            telefono: security.sanitizeInput(telefono),
            email: security.sanitizeInput(email || ''),
            mensaje: security.sanitizeInput(mensaje),
            fecha: new Date().toLocaleString('es-ES'),
            timestamp: Date.now()
        }]);
        if (error) throw error;
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API DE PEDIDOS
// ============================================
app.post('/api/pedidos', async (req, res) => {
    let { cliente, telefono, email, producto, detalles } = req.body;
    if (!cliente || !telefono || !producto) return res.status(400).json({ error: 'Cliente, teléfono y producto requeridos' });
    if (!security.validatePhone(telefono)) return res.status(400).json({ error: 'Número inválido' });
    
    try {
        const { error } = await supabase.from('pedidos').insert([{
            cliente: security.sanitizeInput(cliente),
            telefono: security.sanitizeInput(telefono),
            email: security.sanitizeInput(email || ''),
            producto: security.sanitizeInput(producto),
            detalles: security.sanitizeInput(detalles || ''),
            estado: 'Pendiente',
            fecha: new Date().toLocaleString('es-ES'),
            timestamp: Date.now()
        }]);
        if (error) throw error;
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API DE ACERCA DE (CON JSONB)
// ============================================
app.get('/api/acercade', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=600, stale-while-revalidate=120');
    try {
        const { data, error } = await supabase.from('acercade').select('data').eq('id', 1).single();
        if (error && error.code !== 'PGRST116') throw error;
        res.json(data?.data || {});
    } catch (error) {
        res.json({});
    }
});

app.post('/api/acercade', async (req, res) => {
    try {
        const newData = req.body;
        const { data: existing } = await supabase.from('acercade').select('data').eq('id', 1).single();
        const merged = { ...(existing?.data || {}), ...newData, updated_at: new Date().toISOString() };
        
        const { error } = await supabase.from('acercade').upsert({ id: 1, data: merged, updated_at: new Date().toISOString() });
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API DE DATOS ADMIN (MÚLTIPLES TABLAS)
// ============================================
app.get('/api/admin-data', async (req, res) => {
    try {
        const [contactos, pedidos, catalogos] = await Promise.all([
            supabase.from('contactos').select('*').order('timestamp', { ascending: false }),
            supabase.from('pedidos').select('*').order('timestamp', { ascending: false }),
            supabase.from('catalogos').select('*').order('id')
        ]);
        res.json({
            contactos: contactos.data || [],
            pedidos: pedidos.data || [],
            catalogos: catalogos.data || []
        });
    } catch (error) {
        res.json({ contactos: [], pedidos: [], catalogos: [] });
    }
});

app.delete('/api/contactos/:id', async (req, res) => {
    try {
        await supabase.from('contactos').delete().eq('id', parseInt(req.params.id));
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/pedidos/:id', async (req, res) => {
    try {
        await supabase.from('pedidos').delete().eq('id', parseInt(req.params.id));
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// RUTAS FRONTEND
// ============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/contactar', (req, res) => res.sendFile(path.join(__dirname, 'contactar.html')));
app.get('/hacercade', (req, res) => res.sendFile(path.join(__dirname, 'hacercade.html')));

// Manejo de errores
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'index.html')));
app.use((err, req, res, next) => {
    console.error(err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FG-Studio corriendo en puerto ${PORT}`);
    console.log(`✅ Compresión GZIP: ACTIVADA`);
    console.log(`✅ API de pedidos: ACTIVADA`);
});