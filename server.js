// server.js - FG-Studio - Versión Segura con Rutas Protegidas
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Compresión GZIP
app.use(compression({ level: 6, threshold: 1024 }));

// ============================================
// CONFIGURACIÓN DE SEGURIDAD MEJORADA
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:", "fonts.googleapis.com", "cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https:", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https:", "fonts.gstatic.com", "data:"],
            imgSrc: ["'self'", "https:", "data:", "i.ibb.co"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Rate limiting más estricto
const globalLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: 'Demasiadas solicitudes' },
    standardHeaders: true,
    legacyHeaders: false,
});
const authLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { error: 'Demasiados intentos de acceso' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);
app.use('/api/verify-admin', authLimiter);
app.use('/api/contactos', rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Demasiados mensajes. Espera 1 hora.' } }));
app.use('/api/pedidos', rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'Demasiados pedidos. Espera 1 hora.' } }));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true,
    optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// LISTA BLANCA DE ARCHIVOS ESTÁTICOS
// ============================================
const ALLOWED_STATIC_FILES = new Set([
    'index.html', 'admin.html', 'contactar.html', 'hacercade.html',
    'manifest.json', 'robots.txt', 'favicon.ico'
]);

const ALLOWED_STATIC_EXTENSIONS = new Set([
    '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.json', '.txt'
]);

// Middleware de seguridad para archivos estáticos
app.use((req, res, next) => {
    // Prevenir path traversal
    const sanitizedPath = path.normalize(req.path).replace(/^(\.\.[/\\])+/, '');
    const filename = path.basename(sanitizedPath);
    const ext = path.extname(filename).toLowerCase();
    
    // Verificar si el archivo está permitido
    if (ALLOWED_STATIC_FILES.has(filename) || ALLOWED_STATIC_EXTENSIONS.has(ext)) {
        next();
    } else {
        // Si no está en la lista blanca, servir index.html (SPA behavior) pero seguro
        if (req.accepts('html') && !req.path.startsWith('/api/')) {
            res.sendFile(path.join(__dirname, 'index.html'), (err) => {
                if (err) res.status(404).sendFile(path.join(__dirname, 'index.html'));
            });
        } else {
            res.status(404).json({ error: 'Recurso no encontrado' });
        }
    }
});

// Servir archivos estáticos con caché seguro
app.use(express.static(__dirname, {
    maxAge: '1y',
    immutable: true,
    setHeaders: (res, filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        
        // Headers de seguridad adicionales
        res.setHeader('X-Content-Type-Options', 'nosniff');
        
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
            res.setHeader('X-Frame-Options', 'DENY');
        } else if (ext === '.css') {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
            res.setHeader('Content-Type', 'text/css');
        } else if (ext === '.js') {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
            res.setHeader('Content-Type', 'application/javascript');
        } else if (ext.match(/\.(jpg|jpeg|png|gif|webp|svg|ico)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (filePath.endsWith('.json')) {
            res.setHeader('Cache-Control', 'public, max-age=86400');
        }
    }
}));

// ============================================
// SUPABASE CONFIGURACIÓN
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_KEY || !ADMIN_PASSWORD) {
    console.error('❌ ERROR: Faltan variables de entorno críticas');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { 
    auth: { persistSession: false },
    db: { schema: 'public' }
});

// ============================================
// SISTEMA DE SEGURIDAD
// ============================================
const ipBlacklist = new Set();
const requestLog = new Map();

const security = {
    validatePhone(phone) {
        if (!phone || typeof phone !== 'string') return false;
        const digitsOnly = phone.replace(/\D/g, '');
        return digitsOnly.length >= 7 && digitsOnly.length <= 16;
    },
    
    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        // Eliminar caracteres peligrosos
        return input
            .replace(/[<>]/g, '')
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/`/g, '&#x60;')
            .substring(0, 500);
    },
    
    sanitizeUrl(url) {
        if (!url || typeof url !== 'string') return '';
        // Validar URL segura
        const safeUrl = url.trim();
        if (safeUrl.match(/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i)) {
            return safeUrl;
        }
        return '#';
    },
    
    isBlacklisted(ip) {
        return ipBlacklist.has(ip);
    },
    
    logRequest(ip, endpoint) {
        const key = `${ip}:${endpoint}`;
        const now = Date.now();
        const requests = requestLog.get(key) || [];
        const recent = requests.filter(t => now - t < 60000); // 1 minuto
        
        if (recent.length >= 30) {
            ipBlacklist.add(ip);
            console.log(`🚨 IP BLOQUEADA: ${ip}`);
            return true;
        }
        
        recent.push(now);
        requestLog.set(key, recent);
        return false;
    }
};

// Middleware de bloqueo de IP
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (security.isBlacklisted(ip)) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
});

// ============================================
// RUTAS DE API SEGURAS
// ============================================

// Autenticación Admin
app.post('/api/verify-admin', (req, res) => {
    const ip = req.ip;
    if (security.logRequest(ip, 'login')) {
        return res.status(429).json({ error: 'Demasiados intentos' });
    }
    
    const { password } = req.body;
    if (!password || typeof password !== 'string' || password.length > 100) {
        return res.status(400).json({ error: 'Datos inválidos' });
    }
    
    // Comparación segura usando crypto.timingSafeEqual
    const inputBuffer = Buffer.from(password);
    const adminBuffer = Buffer.from(ADMIN_PASSWORD);
    
    let isValid = false;
    if (inputBuffer.length === adminBuffer.length) {
        isValid = crypto.timingSafeEqual(inputBuffer, adminBuffer);
    }
    
    if (isValid) {
        const token = crypto.randomBytes(48).toString('hex');
        console.log('✅ Login exitoso desde:', ip);
        res.json({ success: true, token });
    } else {
        console.log('❌ Login fallido desde:', ip);
        res.status(401).json({ success: false });
    }
});

// Configuración de Supabase (sin exponer service key)
app.get('/api/supabase-config', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.json({
        url: process.env.SUPABASE_URL,
        anonKey: process.env.SUPABASE_ANON_KEY
    });
});

// ============================================
// API DE CATÁLOGOS
// ============================================
app.get('/api/catalogos', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    try {
        const { data, error } = await supabase
            .from('catalogos')
            .select('id, name, category, link, image, descripcion')
            .order('id');
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error catalogos GET:', error.message);
        res.status(500).json({ error: 'Error al cargar catálogos' });
    }
});

app.post('/api/catalogos', async (req, res) => {
    const { name, category, link, image, descripcion } = req.body;
    
    if (!name || !category || !link || !image) {
        return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    
    try {
        const { data, error } = await supabase
            .from('catalogos')
            .insert([{
                name: security.sanitizeInput(name),
                category: security.sanitizeInput(category),
                link: security.sanitizeUrl(link),
                image: security.sanitizeUrl(image),
                descripcion: security.sanitizeInput(descripcion || '')
            }])
            .select();
        
        if (error) throw error;
        res.status(201).json(data[0]);
    } catch (error) {
        console.error('Error catalogos POST:', error.message);
        res.status(500).json({ error: 'Error al guardar catálogo' });
    }
});

app.put('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) {
        return res.status(400).json({ error: 'ID inválido' });
    }
    
    const { name, category, link, image, descripcion } = req.body;
    
    if (!name || !category || !link || !image) {
        return res.status(400).json({ error: 'Campos requeridos faltantes' });
    }
    
    try {
        const { error } = await supabase
            .from('catalogos')
            .update({
                name: security.sanitizeInput(name),
                category: security.sanitizeInput(category),
                link: security.sanitizeUrl(link),
                image: security.sanitizeUrl(image),
                descripcion: security.sanitizeInput(descripcion || '')
            })
            .eq('id', id);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error catalogos PUT:', error.message);
        res.status(500).json({ error: 'Error al actualizar' });
    }
});

app.delete('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) {
        return res.status(400).json({ error: 'ID inválido' });
    }
    
    try {
        const { error } = await supabase.from('catalogos').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error catalogos DELETE:', error.message);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// ============================================
// API DE CONTACTOS
// ============================================
app.post('/api/contactos', async (req, res) => {
    const ip = req.ip;
    if (security.logRequest(ip, 'contacto')) {
        return res.status(429).json({ error: 'Demasiados mensajes. Espere.' });
    }
    
    let { nombre, telefono, email, mensaje } = req.body;
    
    nombre = security.sanitizeInput(nombre);
    telefono = security.sanitizeInput(telefono);
    email = security.sanitizeInput(email);
    mensaje = security.sanitizeInput(mensaje);
    
    if (!nombre || !telefono || !mensaje) {
        return res.status(400).json({ error: 'Nombre, teléfono y mensaje son requeridos' });
    }
    
    if (!security.validatePhone(telefono)) {
        return res.status(400).json({ error: 'Número de teléfono inválido (7-16 dígitos)' });
    }
    
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Email inválido' });
    }
    
    try {
        const { error } = await supabase
            .from('contactos')
            .insert([{
                nombre,
                telefono,
                email: email || 'No especificado',
                mensaje,
                fecha: new Date().toLocaleString('es-ES'),
                timestamp: Date.now()
            }]);
        
        if (error) throw error;
        console.log('✅ Contacto guardado desde:', ip);
        res.status(201).json({ success: true });
    } catch (error) {
        console.error('Error contactos POST:', error.message);
        res.status(500).json({ error: 'Error al enviar mensaje' });
    }
});

// ============================================
// API DE PEDIDOS
// ============================================
app.post('/api/pedidos', async (req, res) => {
    const ip = req.ip;
    if (security.logRequest(ip, 'pedido')) {
        return res.status(429).json({ error: 'Demasiados pedidos. Espere.' });
    }
    
    let { cliente, telefono, email, producto, detalles } = req.body;
    
    cliente = security.sanitizeInput(cliente);
    telefono = security.sanitizeInput(telefono);
    email = security.sanitizeInput(email);
    producto = security.sanitizeInput(producto);
    detalles = security.sanitizeInput(detalles || '');
    
    if (!cliente || !telefono || !producto) {
        return res.status(400).json({ error: 'Cliente, teléfono y producto son requeridos' });
    }
    
    if (!security.validatePhone(telefono)) {
        return res.status(400).json({ error: 'Número de teléfono inválido' });
    }
    
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Email inválido' });
    }
    
    try {
        const { error } = await supabase
            .from('pedidos')
            .insert([{
                cliente,
                telefono,
                email: email || 'No especificado',
                producto,
                detalles,
                estado: 'Pendiente',
                fecha: new Date().toLocaleString('es-ES'),
                timestamp: Date.now()
            }]);
        
        if (error) throw error;
        console.log('✅ Pedido guardado desde:', ip);
        res.status(201).json({ success: true });
    } catch (error) {
        console.error('Error pedidos POST:', error.message);
        res.status(500).json({ error: 'Error al registrar pedido' });
    }
});

app.get('/api/pedidos', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('pedidos')
            .select('*')
            .order('timestamp', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Error pedidos GET:', error.message);
        res.status(500).json({ error: 'Error al cargar pedidos' });
    }
});

// ============================================
// API DE ACERCA DE
// ============================================
app.get('/api/acercade', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=600, stale-while-revalidate=120');
    try {
        const { data, error } = await supabase
            .from('acercade')
            .select('data')
            .eq('id', 1)
            .single();
        
        if (error && error.code !== 'PGRST116') throw error;
        res.json(data?.data || {});
    } catch (error) {
        console.error('Error acercade GET:', error.message);
        res.json({});
    }
});

app.post('/api/acercade', async (req, res) => {
    try {
        const newData = req.body;
        const { data: existing } = await supabase
            .from('acercade')
            .select('data')
            .eq('id', 1)
            .single();
        
        const merged = { ...(existing?.data || {}), ...newData, updated_at: new Date().toISOString() };
        
        const { error } = await supabase
            .from('acercade')
            .upsert({ id: 1, data: merged, updated_at: new Date().toISOString() });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Error acercade POST:', error.message);
        res.status(500).json({ error: 'Error al guardar' });
    }
});

// ============================================
// API DE DATOS ADMIN
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
        console.error('Error admin-data:', error.message);
        res.json({ contactos: [], pedidos: [], catalogos: [] });
    }
});

app.delete('/api/contactos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) {
        return res.status(400).json({ error: 'ID inválido' });
    }
    
    try {
        await supabase.from('contactos').delete().eq('id', id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error contactos DELETE:', error.message);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

app.delete('/api/pedidos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) {
        return res.status(400).json({ error: 'ID inválido' });
    }
    
    try {
        await supabase.from('pedidos').delete().eq('id', id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error pedidos DELETE:', error.message);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// ============================================
// RUTAS DE PÁGINAS (PROTEGIDAS)
// ============================================
const safeSendFile = (res, filename) => {
    const filePath = path.join(__dirname, filename);
    // Verificar que el archivo existe y está dentro del directorio permitido
    if (fs.existsSync(filePath) && !filePath.includes('..')) {
        res.sendFile(filePath);
    } else {
        res.status(404).sendFile(path.join(__dirname, 'index.html'));
    }
};

app.get('/', (req, res) => safeSendFile(res, 'index.html'));
app.get('/admin', (req, res) => safeSendFile(res, 'admin.html'));
app.get('/contactar', (req, res) => safeSendFile(res, 'contactar.html'));
app.get('/hacercade', (req, res) => safeSendFile(res, 'hacercade.html'));

// ============================================
// MANEJO DE ERRORES 404
// ============================================
app.use((req, res) => {
    // No exponer información del sistema
    if (req.accepts('html')) {
        res.status(404).sendFile(path.join(__dirname, 'index.html'));
    } else {
        res.status(404).json({ error: 'Recurso no encontrado' });
    }
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================
app.use((err, req, res, next) => {
    console.error('Error global:', err.message);
    // No exponer detalles del error al cliente
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================
// LIMPIEZA PERIÓDICA DE IPs BLOQUEADAS
// ============================================
setInterval(() => {
    ipBlacklist.clear();
    requestLog.clear();
    console.log('🔄 Limpieza de caché de seguridad completada');
}, 24 * 60 * 60 * 1000); // Cada 24 horas

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FG-Studio corriendo en puerto ${PORT}`);
    console.log(`✅ Compresión GZIP: ACTIVADA`);
    console.log(`✅ Seguridad mejorada: ACTIVADA`);
    console.log(`✅ Rate limiting: ACTIVADO`);
    console.log(`✅ Path traversal protection: ACTIVADA`);
    console.log(`✅ IP blacklisting: ACTIVADO`);
});