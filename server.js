// server.js - FG-Studio Blindado + Optimizado para SEO y Rendimiento
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

// ============================================
// CONFIGURACIÓN DE PROXY
// ============================================
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// ============================================
// LOGGERS MEJORADOS PARA RENDER
// ============================================
const log = {
    info: (msg, data = null) => {
        console.log(`[INFO] ${new Date().toISOString()} - ${msg}`);
        if (data) console.log(JSON.stringify(data, null, 2));
    },
    error: (msg, error = null) => {
        console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`);
        if (error) console.error(error);
    },
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`)
};

// ============================================
// COMPRESIÓN GZIP
// ============================================
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// ============================================
// SISTEMA ANTI-ATAQUES
// ============================================

const ipBlacklist = new Set();

class SecurityDefender {
    constructor() {
        this.attempts = new Map();
    }

    detectBruteForce(ip, endpoint) {
        const key = `${ip}:${endpoint}`;
        const now = Date.now();
        const attempts = this.attempts.get(key) || [];
        const recent = attempts.filter(t => now - t < 300000);

        if (recent.length >= 10) {
            ipBlacklist.add(ip);
            log.warn(`IP BLOQUEADA: ${ip}`);
            return true;
        }

        recent.push(now);
        this.attempts.set(key, recent);
        return false;
    }

    validatePhone(phone) {
        const digitsOnly = phone.replace(/\D/g, '');
        return digitsOnly.length >= 7 && digitsOnly.length <= 16;
    }

    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .substring(0, 500);
    }
}

const security = new SecurityDefender();

// ============================================
// CONFIGURACIÓN SUPABASE
// ============================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_KEY) {
    log.error('ERROR: Faltan variables SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    log.error('ERROR: Falta variable ADMIN_PASSWORD');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false }
});

log.info('✅ Supabase configurado correctamente');

// ============================================
// MIDDLEWARES DE SEGURIDAD
// ============================================

app.use(helmet({
    contentSecurityPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true
}));

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas solicitudes' },
    validate: { trustProxy: false }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Demasiados intentos de acceso' },
    validate: { trustProxy: false }
});

app.use(globalLimiter);
app.use('/api/verify-admin', authLimiter);

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware para logging de peticiones
app.use((req, res, next) => {
    log.info(`${req.method} ${req.url}`);
    next();
});

// ============================================
// ARCHIVOS ESTÁTICOS CON CACHÉ OPTIMIZADO
// ============================================

app.use(express.static(__dirname, {
    maxAge: '1y',
    immutable: true,
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate, stale-while-revalidate=60');
        } else if (filePath.endsWith('.json') && filePath.includes('manifest')) {
            res.setHeader('Cache-Control', 'public, max-age=86400, must-revalidate');
            res.setHeader('Content-Type', 'application/manifest+json');
        } else if (filePath.match(/\.(jpg|jpeg|png|gif|webp|svg|ico)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (filePath.match(/\.(css|js)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
        }
    }
}));

// Middleware de bloqueo de IP
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (ipBlacklist.has(ip)) {
        log.warn(`Acceso denegado a IP bloqueada: ${ip}`);
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
});

// ============================================
// RUTAS DE SEGURIDAD
// ============================================

app.post('/api/verify-admin', (req, res) => {
    const ip = req.ip;

    if (security.detectBruteForce(ip, 'login')) {
        return res.status(429).json({ error: 'Demasiados intentos' });
    }

    const { password } = req.body;

    if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Datos inválidos' });
    }

    if (password === ADMIN_PASSWORD) {
        const token = crypto.randomBytes(48).toString('hex');
        log.info('✅ Login exitoso');
        res.json({ success: true, token });
    } else {
        log.warn('❌ Contraseña incorrecta');
        res.status(401).json({ success: false });
    }
});

// ============================================
// API DE CATÁLOGOS
// ============================================

app.get('/api/catalogos', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');

    try {
        const { data, error } = await supabase
            .from('catalogos')
            .select('*')
            .order('id', { ascending: true });

        if (error) {
            log.error('Error al cargar catálogos:', error);
            return res.status(500).json({ error: error.message });
        }

        res.json(data || []);
    } catch (error) {
        log.error('Error:', error);
        res.status(500).json({ error: 'Error al cargar catálogos' });
    }
});

app.post('/api/catalogos', async (req, res) => {
    log.info('📦 Recibiendo catálogo:', req.body);

    const { name, category, link, image, descripcion } = req.body;

    if (!name || !category || !link || !image) {
        return res.status(400).json({
            error: 'Faltan campos requeridos: nombre, categoría, enlace e imagen son obligatorios'
        });
    }

    const catalogoData = {
        name: security.sanitizeInput(name),
        category: security.sanitizeInput(category),
        link: security.sanitizeInput(link),
        image: security.sanitizeInput(image),
        descripcion: security.sanitizeInput(descripcion || '')
    };

    try {
        const { data, error } = await supabase
            .from('catalogos')
            .insert([catalogoData])
            .select();

        if (error) {
            log.error('Error Supabase:', error);
            return res.status(500).json({ error: error.message });
        }

        log.info('✅ Catálogo guardado:', data[0]);
        res.status(201).json(data[0]);
    } catch (error) {
        log.error('Error:', error);
        res.status(500).json({ error: 'Error al guardar: ' + error.message });
    }
});

app.put('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) return res.status(400).json({ error: 'ID inválido' });

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
                link: security.sanitizeInput(link),
                image: security.sanitizeInput(image),
                descripcion: security.sanitizeInput(descripcion || '')
            })
            .eq('id', id);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        log.error('Error al actualizar:', error);
        res.status(500).json({ error: 'Error al actualizar' });
    }
});

app.delete('/api/catalogos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) return res.status(400).json({ error: 'ID inválido' });

    try {
        const { error } = await supabase.from('catalogos').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        log.error('Error al eliminar:', error);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// ============================================
// API DE CONTACTOS (CON SERVICIO SELECCIONADO)
// ============================================

app.post('/api/contactos', async (req, res) => {
    const ip = req.ip;

    if (security.detectBruteForce(ip, 'contacto')) {
        return res.status(429).json({ error: 'Demasiados mensajes. Espere.' });
    }

    let { nombre, telefono, email, mensaje, servicio } = req.body;

    log.info('📩 Contacto recibido:', { nombre, telefono, email, servicio });

    nombre = security.sanitizeInput(nombre);
    telefono = security.sanitizeInput(telefono);
    email = security.sanitizeInput(email);
    mensaje = security.sanitizeInput(mensaje);
    servicio = security.sanitizeInput(servicio || 'No especificado');

    if (!nombre || !telefono || !mensaje) {
        return res.status(400).json({ error: 'Campos requeridos faltantes' });
    }

    if (!security.validatePhone(telefono)) {
        return res.status(400).json({ error: 'Número de teléfono inválido. Debe tener entre 7 y 16 dígitos.' });
    }

    try {
        const { data, error } = await supabase.from('contactos').insert([{
            nombre,
            telefono,
            email: email || 'No especificado',
            mensaje,
            servicio,
            fecha: new Date().toLocaleString('es-ES'),
            timestamp: Date.now()
        }]).select();

        if (error) {
            log.error('Error Supabase al guardar contacto:', error);
            throw error;
        }

        log.info('✅ Contacto guardado con ID:', data[0].id);
        res.status(201).json({ success: true, id: data[0].id });
    } catch (error) {
        log.error('Error al guardar contacto:', error);
        res.status(500).json({ error: 'Error al enviar: ' + error.message });
    }
});

// ============================================
// API DE PEDIDOS
// ============================================

app.post('/api/pedidos', async (req, res) => {
    const ip = req.ip;

    if (security.detectBruteForce(ip, 'pedido')) {
        return res.status(429).json({ error: 'Demasiados pedidos. Espere.' });
    }

    let { cliente, producto, total, estado, fecha, telefono, email } = req.body;

    log.info('📦 Pedido recibido:', { cliente, producto, total, estado });

    cliente = security.sanitizeInput(cliente);
    producto = security.sanitizeInput(producto);
    total = security.sanitizeInput(total || '');
    estado = security.sanitizeInput(estado || 'Pendiente');
    fecha = fecha || new Date().toLocaleString('es-ES');
    telefono = security.sanitizeInput(telefono || '');
    email = security.sanitizeInput(email || '');

    if (!cliente || !producto) {
        return res.status(400).json({ error: 'Cliente y producto son requeridos' });
    }

    try {
        const { data, error } = await supabase.from('pedidos').insert([{
            cliente,
            producto,
            total,
            estado,
            fecha,
            telefono,
            email,
            timestamp: Date.now()
        }]).select();

        if (error) {
            log.error('Error Supabase al guardar pedido:', error);
            throw error;
        }

        log.info('✅ Pedido guardado con ID:', data[0].id);
        res.status(201).json({ success: true, id: data[0].id });
    } catch (error) {
        log.error('Error al guardar pedido:', error);
        res.status(500).json({ error: 'Error al guardar pedido: ' + error.message });
    }
});

app.get('/api/pedidos', async (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=30');

    try {
        const { data, error } = await supabase
            .from('pedidos')
            .select('*')
            .order('timestamp', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        log.error('Error al cargar pedidos:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/pedidos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) return res.status(400).json({ error: 'ID inválido' });

    try {
        await supabase.from('pedidos').delete().eq('id', id);
        res.json({ success: true });
    } catch (error) {
        log.error('Error al eliminar pedido:', error);
        res.status(500).json({ error: 'Error al eliminar' });
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
            .select('*')
            .eq('id', 1)
            .single();

        if (error && error.code !== 'PGRST116') {
            log.error('Error al cargar acercade:', error);
            return res.json({});
        }

        res.json(data || {});
    } catch (error) {
        log.error('Error:', error);
        res.json({});
    }
});

app.post('/api/acercade', async (req, res) => {
    log.info('📝 Guardando Acerca de:', Object.keys(req.body));

    try {
        const newData = req.body;

        const { data: existing } = await supabase
            .from('acercade')
            .select('*')
            .eq('id', 1)
            .single();

        let merged;
        if (existing) {
            merged = { ...existing, ...newData, updated_at: new Date().toISOString() };
        } else {
            merged = { id: 1, ...newData, updated_at: new Date().toISOString() };
        }

        const { error } = await supabase
            .from('acercade')
            .upsert(merged);

        if (error) {
            log.error('Error al guardar acercade:', error);
            return res.status(500).json({ error: error.message });
        }

        log.info('✅ Acerca de guardado');
        res.json({ success: true });
    } catch (error) {
        log.error('Error:', error);
        res.status(500).json({ error: error.message });
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
            supabase.from('catalogos').select('*').order('id', { ascending: true })
        ]);

        res.json({
            contactos: contactos.data || [],
            pedidos: pedidos.data || [],
            catalogos: catalogos.data || []
        });
    } catch (error) {
        log.error('Error al cargar datos admin:', error);
        res.json({ contactos: [], pedidos: [], catalogos: [] });
    }
});

app.delete('/api/contactos/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id || id < 1) return res.status(400).json({ error: 'ID inválido' });

    try {
        await supabase.from('contactos').delete().eq('id', id);
        res.json({ success: true });
    } catch (error) {
        log.error('Error al eliminar contacto:', error);
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// Resetear secuencia de catálogos
app.post('/api/reset-catalogos-sequence', async (req, res) => {
    try {
        const { error } = await supabase.rpc('reset_catalogos_seq');
        if (error) throw error;
        log.info('🔄 Secuencia de catálogos reseteada');
        res.json({ success: true });
    } catch (error) {
        log.error('Error al resetear secuencia:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// CONFIG DE SUPABASE PARA EL CLIENTE
// ============================================

app.get('/api/supabase-config', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.json({
        url: process.env.SUPABASE_URL,
        anonKey: process.env.SUPABASE_ANON_KEY
    });
});

// ============================================
// RUTAS DE PÁGINAS
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/contactar', (req, res) => {
    res.sendFile(path.join(__dirname, 'contactar.html'));
});

app.get('/hacercade', (req, res) => {
    res.sendFile(path.join(__dirname, 'hacercade.html'));
});

// ============================================
// MANEJO DE ERRORES 404
// ============================================

app.use((req, res) => {
    log.warn(`404 - Ruta no encontrada: ${req.url}`);
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// MANEJO DE ERRORES GLOBAL
// ============================================

app.use((err, req, res, next) => {
    log.error('Error global:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================
// INICIAR SERVIDOR
// ============================================

app.listen(PORT, '0.0.0.0', () => {
    log.info(`🚀 FG-Studio iniciado en puerto ${PORT}`);
    log.info(`✅ Compresión GZIP: ACTIVADA`);
    log.info(`✅ Caché de recursos: CONFIGURADA`);
    log.info(`✅ Validación telefónica: ACTIVA (7-16 dígitos)`);
    log.info(`✅ API de Contactos: /api/contactos (con campo servicio)`);
    log.info(`✅ API de Pedidos: /api/pedidos`);
    log.info(`✅ Manifiesto PWA: /manifest.json`);
});