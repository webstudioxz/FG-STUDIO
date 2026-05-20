// server.js - FG-Studio Blindado
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
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
            console.log(`🚨 IP BLOQUEADA: ${ip}`);
            return true;
        }
        
        recent.push(now);
        this.attempts.set(key, recent);
        return false;
    }

    validatePhone(phone) {
        // Eliminar todo excepto dígitos
        const digitsOnly = phone.replace(/\D/g, '');
        
        console.log('📱 Validando:', phone, '→ Dígitos:', digitsOnly, '(' + digitsOnly.length + ')');
        
        // Aceptar cualquier número con 7-16 dígitos
        if (digitsOnly.length >= 7 && digitsOnly.length <= 16) {
            console.log('✅ Teléfono ACEPTADO');
            return true;
        }
        
        console.log('❌ Teléfono RECHAZADO - Debe tener 7-16 dígitos');
        return false;
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
    console.error('❌ ERROR: Faltan variables SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY');
    process.exit(1);
}

if (!ADMIN_PASSWORD) {
    console.error('❌ ERROR: Falta variable ADMIN_PASSWORD');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false }
});

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

app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (ipBlacklist.has(ip)) {
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
        console.log('✅ Login exitoso');
        res.json({ success: true, token });
    } else {
        console.log('❌ Contraseña incorrecta');
        res.status(401).json({ success: false });
    }
});

// ============================================
// API DE CATÁLOGOS
// ============================================

app.get('/api/catalogos', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('catalogos')
            .select('*')
            .order('id', { ascending: true });
        
        if (error) {
            console.error('Error al cargar catálogos:', error);
            return res.status(500).json({ error: error.message });
        }
        
        res.json(data || []);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error al cargar catálogos' });
    }
});

app.post('/api/catalogos', async (req, res) => {
    console.log('📦 Recibiendo catálogo:', req.body);
    
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
            console.error('Error Supabase:', error);
            return res.status(500).json({ error: error.message });
        }
        
        console.log('✅ Catálogo guardado:', data[0]);
        res.status(201).json(data[0]);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error al guardar: ' + error.message });
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
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// ============================================
// API DE CONTACTOS
// ============================================

app.post('/api/contactos', async (req, res) => {
    const ip = req.ip;
    
    if (security.detectBruteForce(ip, 'contacto')) {
        return res.status(429).json({ error: 'Demasiados mensajes. Espere.' });
    }
    
    let { nombre, telefono, email, mensaje } = req.body;
    
    console.log('📩 Contacto recibido:', { nombre, telefono, email });
    
    nombre = security.sanitizeInput(nombre);
    telefono = security.sanitizeInput(telefono);
    email = security.sanitizeInput(email);
    mensaje = security.sanitizeInput(mensaje);
    
    if (!nombre || !telefono || !mensaje) {
        return res.status(400).json({ error: 'Campos requeridos faltantes' });
    }
    
    if (!security.validatePhone(telefono)) {
        return res.status(400).json({ error: 'Número de teléfono inválido. Debe tener entre 7 y 16 dígitos.' });
    }
    
    try {
        const { error } = await supabase.from('contactos').insert([{
            nombre, telefono,
            email: email || 'No especificado',
            mensaje,
            fecha: new Date().toLocaleString('es-ES'),
            timestamp: Date.now()
        }]);
        
        if (error) throw error;
        console.log('✅ Contacto guardado');
        res.status(201).json({ success: true });
    } catch (error) {
        console.error('Error al guardar contacto:', error);
        res.status(500).json({ error: 'Error al enviar: ' + error.message });
    }
});
// Resetear secuencia de catálogos
app.post('/api/reset-catalogos-sequence', async (req, res) => {
    try {
        await supabase.rpc('reset_catalogos_seq');
        console.log('🔄 Secuencia de catálogos reseteada');
        res.json({ success: true });
    } catch (error) {
        console.error('Error al resetear secuencia:', error);
        res.status(500).json({ error: error.message });
    }
});
// ============================================
// API DE ACERCA DE
// ============================================

app.get('/api/acercade', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('acercade')
            .select('*')
            .eq('id', 1)
            .single();
        
        if (error && error.code !== 'PGRST116') {
            console.error('Error al cargar acercade:', error);
            return res.json({});
        }
        
        res.json(data || {});
    } catch (error) {
        console.error('Error:', error);
        res.json({});
    }
});

app.post('/api/acercade', async (req, res) => {
    console.log('📝 Guardando Acerca de:', Object.keys(req.body));
    
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
            console.error('Error al guardar acercade:', error);
            return res.status(500).json({ error: error.message });
        }
        
        console.log('✅ Acerca de guardado');
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
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
        console.error('Error al cargar datos admin:', error);
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
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// ============================================
// ARCHIVOS ESTÁTICOS
// ============================================
app.use(express.static(__dirname));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/contactar', (req, res) => res.sendFile(path.join(__dirname, 'contactar.html')));
app.get('/hacercade', (req, res) => res.sendFile(path.join(__dirname, 'hacercade.html')));

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// MANEJO DE ERRORES
// ============================================
app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔒 FG-Studio SEGURO en puerto ${PORT}`);
    console.log(`✅ Validación telefónica: ACTIVA (7-16 dígitos)`);
    console.log(`🔑 Contraseña admin: CONFIGURADA POR VARIABLE DE ENTORNO`);
});