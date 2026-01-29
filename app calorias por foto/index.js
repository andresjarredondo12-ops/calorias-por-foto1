require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const sharp = require('sharp');
const moment = require('moment');
const Stripe = require('stripe');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Inicializar Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16'
});

// Configuración de multer para manejo de imágenes
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Conexión a PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Middleware para verificar suscripción activa
const requireActiveSubscription = async (req, res, next) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(
      `SELECT subscription_status, trial_ends_at, subscription_ends_at 
       FROM users WHERE id = $1`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const user = result.rows[0];
    const now = new Date();
    
    // Verificar si está en período de prueba
    if (user.trial_ends_at && new Date(user.trial_ends_at) > now) {
      req.user.trialActive = true;
      return next();
    }
    
    // Verificar si tiene suscripción activa
    if (user.subscription_status === 'active' && 
        user.subscription_ends_at && 
        new Date(user.subscription_ends_at) > now) {
      req.user.subscriptionActive = true;
      return next();
    }
    
    // Si no tiene suscripción activa
    return res.status(402).json({ 
      error: 'Suscripción requerida',
      code: 'SUBSCRIPTION_REQUIRED',
      message: 'Tu suscripción ha expirado. Por favor, renueva para continuar usando la app.'
    });
    
  } catch (error) {
    console.error('Subscription check error:', error);
    res.status(500).json({ error: 'Error verificando suscripción' });
  }
};

// ========== HEALTH CHECK ==========
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'NutriApp API',
      version: '2.0.0',
      database: 'connected',
      environment: process.env.NODE_ENV,
      features: ['subscriptions', 'image-analysis', 'payment-processing']
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// ========== RUTAS PÚBLICAS ==========
app.get('/', (req, res) => {
  res.json({
    message: '🚀 NutriApp API v2.0 - Con Sistema de Suscripciones',
    pricing: {
      trial: '7 días gratis',
      monthly: '$3 USD/mes',
      features: [
        'Análisis ilimitado de imágenes',
        'Historial de 90 días',
        'Metas personalizables',
        'Notificaciones inteligentes'
      ]
    }
  });
});

// ========== AUTENTICACIÓN CON SUSCRIPCIÓN ==========
// Registrar usuario con prueba gratuita
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }
    
    // Verificar si usuario ya existe
    const userExists = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    
    if (userExists.rows.length > 0) {
      return res.status(409).json({ error: 'Usuario ya registrado' });
    }
    
    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Calcular fecha de fin de prueba (7 días desde ahora)
    const trialEndsAt = new Date();
    trialEndsAt.setDate(trialEndsAt.getDate() + 7);
    
    // Crear usuario con prueba gratuita
    const result = await pool.query(
      `INSERT INTO users (
        email, password_hash, name, 
        subscription_status, trial_ends_at,
        created_at, updated_at
       ) VALUES ($1, $2, $3, 'trial', $4, NOW(), NOW())
       RETURNING id, email, name, subscription_status, trial_ends_at, created_at`,
      [email, hashedPassword, name || null, trialEndsAt]
    );
    
    const user = result.rows[0];
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        subscription_status: user.subscription_status,
        trial_active: new Date(user.trial_ends_at) > new Date()
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        subscription: {
          status: user.subscription_status,
          trial_ends_at: user.trial_ends_at,
          trial_days_remaining: Math.ceil((new Date(user.trial_ends_at) - new Date()) / (1000 * 60 * 60 * 24))
        }
      },
      token,
      message: '¡Cuenta creada con 7 días de prueba gratuita!'
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Error en el registro' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query(
      `SELECT id, email, password_hash, name, 
              subscription_status, trial_ends_at, 
              subscription_ends_at, stripe_customer_id
       FROM users WHERE email = $1`,
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    // Verificar estado de suscripción
    const now = new Date();
    const trialActive = user.trial_ends_at && new Date(user.trial_ends_at) > now;
    const subscriptionActive = user.subscription_status === 'active' && 
                              user.subscription_ends_at && 
                              new Date(user.subscription_ends_at) > now;
    
    let subscriptionStatus = 'inactive';
    if (subscriptionActive) subscriptionStatus = 'active';
    else if (trialActive) subscriptionStatus = 'trial';
    
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        subscription_status: subscriptionStatus,
        trial_active: trialActive
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Calcular días restantes de prueba
    let trialDaysRemaining = 0;
    if (user.trial_ends_at) {
      trialDaysRemaining = Math.max(0, Math.ceil((new Date(user.trial_ends_at) - now) / (1000 * 60 * 60 * 24)));
    }
    
    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        subscription: {
          status: subscriptionStatus,
          trial_ends_at: user.trial_ends_at,
          trial_days_remaining: trialDaysRemaining,
          subscription_ends_at: user.subscription_ends_at,
          has_payment_method: !!user.stripe_customer_id
        }
      },
      token,
      requires_subscription: !trialActive && !subscriptionActive
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error en el login' });
  }
});

// ========== SISTEMA DE PAGOS ==========
// Crear sesión de pago para suscripción
app.post('/api/payment/create-subscription', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { return_url } = req.body;
    
    // Obtener usuario
    const userResult = await pool.query(
      `SELECT email, stripe_customer_id FROM users WHERE id = $1`,
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const user = userResult.rows[0];
    let customerId = user.stripe_customer_id;
    
    // Crear cliente en Stripe si no existe
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { user_id: userId.toString() }
      });
      customerId = customer.id;
      
      // Guardar customer ID en la base de datos
      await pool.query(
        `UPDATE users SET stripe_customer_id = $1 WHERE id = $2`,
        [customerId, userId]
      );
    }
    
    // Crear sesión de checkout
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID, // Precio de $3 USD/mes configurado en Stripe Dashboard
        quantity: 1,
      }],
      mode: 'subscription',
      subscription_data: {
        trial_period_days: 0, // No hay prueba en el pago
      },
      success_url: `${return_url || process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${return_url || process.env.CLIENT_URL}/payment-cancel`,
      metadata: {
        user_id: userId.toString()
      }
    });
    
    res.json({
      success: true,
      sessionId: session.id,
      url: session.url,
      message: 'Sesión de pago creada'
    });
    
  } catch (error) {
    console.error('Create subscription error:', error);
    res.status(500).json({ 
      error: 'Error creando sesión de pago',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Crear portal de cliente para gestión de suscripción
app.post('/api/payment/create-customer-portal', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { return_url } = req.body;
    
    const userResult = await pool.query(
      `SELECT stripe_customer_id FROM users WHERE id = $1`,
      [userId]
    );
    
    if (!userResult.rows[0]?.stripe_customer_id) {
      return res.status(400).json({ error: 'No hay cliente de pago asociado' });
    }
    
    const session = await stripe.billingPortal.sessions.create({
      customer: userResult.rows[0].stripe_customer_id,
      return_url: return_url || `${process.env.CLIENT_URL}/profile`
    });
    
    res.json({
      success: true,
      url: session.url
    });
    
  } catch (error) {
    console.error('Create portal error:', error);
    res.status(500).json({ error: 'Error creando portal de cliente' });
  }
});

// Verificar estado de pago
app.get('/api/payment/verify/:session_id', authenticateToken, async (req, res) => {
  try {
    const sessionId = req.params.session_id;
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    if (session.payment_status === 'paid' && session.subscription) {
      // Obtener suscripción de Stripe
      const subscription = await stripe.subscriptions.retrieve(session.subscription);
      
      // Actualizar usuario en base de datos
      await pool.query(
        `UPDATE users SET 
          subscription_status = 'active',
          subscription_ends_at = $1,
          stripe_subscription_id = $2,
          updated_at = NOW()
         WHERE id = $3`,
        [new Date(subscription.current_period_end * 1000), 
         subscription.id,
         session.metadata.user_id]
      );
      
      return res.json({
        success: true,
        status: 'active',
        subscription: {
          id: subscription.id,
          current_period_end: new Date(subscription.current_period_end * 1000),
          status: subscription.status
        },
        message: '¡Suscripción activada exitosamente!'
      });
    }
    
    res.json({
      success: false,
      status: session.payment_status,
      message: 'Pago aún no completado'
    });
    
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ error: 'Error verificando pago' });
  }
});

// Obtener información de suscripción del usuario
app.get('/api/user/subscription', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(
      `SELECT subscription_status, trial_ends_at, 
              subscription_ends_at, stripe_customer_id,
              stripe_subscription_id, created_at
       FROM users WHERE id = $1`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const user = result.rows[0];
    const now = new Date();
    
    // Calcular estado actual
    let status = user.subscription_status;
    let trialDaysRemaining = 0;
    let subscriptionDaysRemaining = 0;
    
    if (user.trial_ends_at && new Date(user.trial_ends_at) > now) {
      trialDaysRemaining = Math.ceil((new Date(user.trial_ends_at) - now) / (1000 * 60 * 60 * 24));
    }
    
    if (user.subscription_ends_at && new Date(user.subscription_ends_at) > now) {
      subscriptionDaysRemaining = Math.ceil((new Date(user.subscription_ends_at) - now) / (1000 * 60 * 60 * 24));
    }
    
    // Intentar obtener información actualizada de Stripe
    let stripeSubscription = null;
    if (user.stripe_subscription_id) {
      try {
        const subscription = await stripe.subscriptions.retrieve(user.stripe_subscription_id);
        stripeSubscription = {
          id: subscription.id,
          status: subscription.status,
          current_period_end: new Date(subscription.current_period_end * 1000),
          cancel_at_period_end: subscription.cancel_at_period_end
        };
      } catch (error) {
        console.warn('Error fetching Stripe subscription:', error.message);
      }
    }
    
    res.json({
      subscription: {
        status: status,
        trial_ends_at: user.trial_ends_at,
        trial_days_remaining: trialDaysRemaining,
        subscription_ends_at: user.subscription_ends_at,
        subscription_days_remaining: subscriptionDaysRemaining,
        stripe_customer_id: user.stripe_customer_id,
        stripe_subscription: stripeSubscription,
        created_at: user.created_at
      },
      pricing: {
        monthly: 3.00,
        currency: 'USD',
        trial_days: 7
      }
    });
    
  } catch (error) {
    console.error('Get subscription error:', error);
    res.status(500).json({ error: 'Error obteniendo información de suscripción' });
  }
});

// ========== WEBHOOKS DE STRIPE ==========
// Endpoint para webhooks de Stripe
app.post('/api/webhooks/stripe', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Manejar diferentes eventos
  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await handleSubscriptionUpdate(event.data.object);
      break;
      
    case 'customer.subscription.deleted':
      await handleSubscriptionCancel(event.data.object);
      break;
      
    case 'invoice.payment_succeeded':
      await handlePaymentSucceeded(event.data.object);
      break;
      
    case 'invoice.payment_failed':
      await handlePaymentFailed(event.data.object);
      break;
  }

  res.json({received: true});
});

// ========== FUNCIONES PARA WEBHOOKS ==========
async function handleSubscriptionUpdate(subscription) {
  try {
    const customerId = subscription.customer;
    const periodEnd = new Date(subscription.current_period_end * 1000);
    
    // Encontrar usuario por stripe_customer_id
    const result = await pool.query(
      `SELECT id FROM users WHERE stripe_customer_id = $1`,
      [customerId]
    );
    
    if (result.rows.length > 0) {
      const userId = result.rows[0].id;
      
      await pool.query(
        `UPDATE users SET 
          subscription_status = $1,
          subscription_ends_at = $2,
          stripe_subscription_id = $3,
          updated_at = NOW()
         WHERE id = $4`,
        [subscription.status, periodEnd, subscription.id, userId]
      );
      
      console.log(`✅ Suscripción actualizada para usuario ${userId}`);
    }
  } catch (error) {
    console.error('Error handling subscription update:', error);
  }
}

async function handleSubscriptionCancel(subscription) {
  try {
    const customerId = subscription.customer;
    
    const result = await pool.query(
      `SELECT id FROM users WHERE stripe_customer_id = $1`,
      [customerId]
    );
    
    if (result.rows.length > 0) {
      const userId = result.rows[0].id;
      
      await pool.query(
        `UPDATE users SET 
          subscription_status = 'canceled',
          updated_at = NOW()
         WHERE id = $1`,
        [userId]
      );
      
      console.log(`❌ Suscripción cancelada para usuario ${userId}`);
    }
  } catch (error) {
    console.error('Error handling subscription cancel:', error);
  }
}

async function handlePaymentSucceeded(invoice) {
  try {
    const customerId = invoice.customer;
    const subscriptionId = invoice.subscription;
    
    if (subscriptionId) {
      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      await handleSubscriptionUpdate(subscription);
    }
  } catch (error) {
    console.error('Error handling payment succeeded:', error);
  }
}

async function handlePaymentFailed(invoice) {
  try {
    const customerId = invoice.customer;
    
    // Enviar email de notificación al usuario
    // Aquí podrías integrar un servicio de email
    console.log(`⚠️ Pago fallido para cliente ${customerId}`);
  } catch (error) {
    console.error('Error handling payment failed:', error);
  }
}

// ========== RUTAS CON SUSCRIPCIÓN REQUERIDA ==========
// Verificar acceso del usuario (usado por la app móvil al iniciar)
app.get('/api/user/access', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(
      `SELECT subscription_status, trial_ends_at, subscription_ends_at 
       FROM users WHERE id = $1`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const user = result.rows[0];
    const now = new Date();
    
    // Determinar estado de acceso
    let hasAccess = false;
    let status = 'inactive';
    let message = '';
    
    if (user.trial_ends_at && new Date(user.trial_ends_at) > now) {
      hasAccess = true;
      status = 'trial';
      const daysLeft = Math.ceil((new Date(user.trial_ends_at) - now) / (1000 * 60 * 60 * 24));
      message = `Tienes ${daysLeft} días restantes de prueba`;
    } 
    else if (user.subscription_status === 'active' && 
             user.subscription_ends_at && 
             new Date(user.subscription_ends_at) > now) {
      hasAccess = true;
      status = 'active';
      const daysLeft = Math.ceil((new Date(user.subscription_ends_at) - now) / (1000 * 60 * 60 * 24));
      message = `Suscripción activa (${daysLeft} días restantes)`;
    }
    else {
      status = 'expired';
      message = 'Tu suscripción ha expirado. Por favor, renueva para continuar.';
    }
    
    res.json({
      has_access: hasAccess,
      status: status,
      message: message,
      trial_ends_at: user.trial_ends_at,
      subscription_ends_at: user.subscription_ends_at,
      requires_payment: !hasAccess && status === 'expired'
    });
    
  } catch (error) {
    console.error('Access check error:', error);
    res.status(500).json({ error: 'Error verificando acceso' });
  }
});

// ========== ANÁLISIS DE ALIMENTOS (REQUIERE SUSCRIPCIÓN) ==========
app.post('/api/food/analyze', 
  authenticateToken, 
  requireActiveSubscription,
  upload.single('image'), 
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No se envió ninguna imagen' });
      }
      
      // Comprimir imagen
      const compressedImage = await sharp(req.file.buffer)
        .resize(800, 800, { fit: 'inside' })
        .jpeg({ quality: 80 })
        .toBuffer();
      
      const imageBase64 = compressedImage.toString('base64');
      
      // Usar Google Vision API
      const visionApiKey = process.env.GOOGLE_CLOUD_VISION_API_KEY;
      if (!visionApiKey) {
        return res.status(500).json({ error: 'API de visión no configurada' });
      }
      
      const visionResponse = await axios.post(
        `https://vision.googleapis.com/v1/images:annotate?key=${visionApiKey}`,
        {
          requests: [{
            image: { content: imageBase64 },
            features: [{ type: 'LABEL_DETECTION', maxResults: 10 }]
          }]
        },
        { timeout: 10000 }
      );
      
      const labels = visionResponse.data.responses[0]?.labelAnnotations || [];
      const foodLabel = labels.find(label => 
        ['food', 'fruit', 'vegetable', 'dish', 'meal']
          .some(keyword => label.description.toLowerCase().includes(keyword))
      )?.description || labels[0]?.description || 'comida';
      
      // Registrar uso de análisis (para métricas)
      await pool.query(
        `INSERT INTO usage_metrics (user_id, action_type, details)
         VALUES ($1, 'image_analysis', $2)`,
        [req.user.id, JSON.stringify({ food_identified: foodLabel })]
      );
      
      // Buscar datos nutricionales
      let nutritionData = null;
      const edamamAppId = process.env.EDAMAM_APP_ID;
      const edamamAppKey = process.env.EDAMAM_APP_KEY;
      
      if (edamamAppId && edamamAppKey) {
        try {
          const edamamResponse = await axios.get(
            'https://api.edamam.com/api/food-database/v2/parser',
            {
              params: {
                'app_id': edamamAppId,
                'app_key': edamamAppKey,
                'ingr': foodLabel,
                'nutrition-type': 'cooking'
              }
            }
          );
          
          if (edamamResponse.data.hints?.length > 0) {
            const food = edamamResponse.data.hints[0].food;
            nutritionData = {
              name: food.label,
              calories: Math.round(food.nutrients.ENERC_KCAL || 0),
              protein: Math.round((food.nutrients.PROCNT || 0) * 10) / 10,
              carbs: Math.round((food.nutrients.CHOCDF || 0) * 10) / 10,
              fat: Math.round((food.nutrients.FAT || 0) * 10) / 10,
              brand: food.brand || 'Genérico',
              servingSize: 100,
              servingUnit: 'g'
            };
          }
        } catch (edamamError) {
          console.warn('Edamam API error:', edamamError.message);
        }
      }
      
      // Usar datos estimados si no hay API
      if (!nutritionData) {
        nutritionData = estimateNutrition(foodLabel);
      }
      
      res.json({
        success: true,
        analysis: {
          identifiedAs: foodLabel,
          confidence: labels[0]?.score || 0.5,
          nutrition: nutritionData
        },
        user_status: {
          trial_active: req.user.trialActive,
          subscription_active: req.user.subscriptionActive
        }
      });
      
    } catch (error) {
      console.error('Image analysis error:', error.message);
      res.status(500).json({ 
        error: 'Error analizando la imagen',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// Función de estimación nutricional
function estimateNutrition(foodName) {
  const estimates = {
    'manzana': { calories: 95, protein: 0.5, carbs: 25, fat: 0.3 },
    'banana': { calories: 105, protein: 1.3, carbs: 27, fat: 0.4 },
    'pollo': { calories: 165, protein: 31, carbs: 0, fat: 3.6 },
    'arroz': { calories: 130, protein: 2.7, carbs: 28, fat: 0.3 },
    'ensalada': { calories: 50, protein: 2, carbs: 8, fat: 1 },
    'pizza': { calories: 285, protein: 12, carbs: 36, fat: 10 },
    'hamburguesa': { calories: 354, protein: 25, carbs: 30, fat: 16 },
    'sopa': { calories: 80, protein: 5, carbs: 10, fat: 2 },
    'pescado': { calories: 206, protein: 22, carbs: 0, fat: 12 },
    'pasta': { calories: 131, protein: 5, carbs: 25, fat: 1 },
  };
  
  const lowerFood = foodName.toLowerCase();
  for (const [key, value] of Object.entries(estimates)) {
    if (lowerFood.includes(key)) {
      return {
        name: foodName,
        calories: value.calories,
        protein: value.protein,
        carbs: value.carbs,
        fat: value.fat,
        fiber: 2,
        servingSize: 100,
        servingUnit: 'g',
        estimated: true
      };
    }
  }
  
  return {
    name: foodName,
    calories: 250,
    protein: 10,
    carbs: 30,
    fat: 8,
    fiber: 3,
    servingSize: 100,
    servingUnit: 'g',
    estimated: true
  };
}

// ========== DIARIO (REQUIERE SUSCRIPCIÓN) ==========
app.post('/api/diary', authenticateToken, requireActiveSubscription, async (req, res) => {
  try {
    const { food, calories, protein, carbs, fat, mealType, servings = 1, date } = req.body;
    const userId = req.user.id;
    
    const result = await pool.query(
      `INSERT INTO diary_entries 
       (user_id, food_name, calories, protein, carbs, fat, meal_type, servings, date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        userId, 
        food, 
        calories * servings, 
        protein * servings, 
        carbs * servings, 
        fat * servings,
        mealType || 'other',
        servings,
        date || new Date().toISOString().split('T')[0]
      ]
    );
    
    res.json({ 
      success: true, 
      entry: result.rows[0]
    });
    
  } catch (error) {
    console.error('Diary add error:', error);
    res.status(500).json({ error: 'Error añadiendo entrada' });
  }
});

app.get('/api/diary/:date?', authenticateToken, requireActiveSubscription, async (req, res) => {
  try {
    const userId = req.user.id;
    const date = req.params.date || new Date().toISOString().split('T')[0];
    
    const entriesResult = await pool.query(
      `SELECT * FROM diary_entries 
       WHERE user_id = $1 AND date = $2
       ORDER BY created_at DESC`,
      [userId, date]
    );
    
    const totalsResult = await pool.query(
      `SELECT 
         SUM(calories) as total_calories,
         SUM(protein) as total_protein,
         SUM(carbs) as total_carbs,
         SUM(fat) as total_fat
       FROM diary_entries 
       WHERE user_id = $1 AND date = $2`,
      [userId, date]
    );
    
    const totals = totalsResult.rows[0] || {
      total_calories: 0, total_protein: 0, 
      total_carbs: 0, total_fat: 0
    };
    
    res.json({
      date,
      entries: entriesResult.rows,
      totals
    });
    
  } catch (error) {
    console.error('Diary get error:', error);
    res.status(500).json({ error: 'Error obteniendo diario' });
  }
});

// ========== TAREAS PROGRAMADAS ==========
// Verificar suscripciones expiradas diariamente
cron.schedule('0 0 * * *', async () => {
  console.log('🔍 Verificando suscripciones expiradas...');
  
  try {
    const result = await pool.query(
      `SELECT id, email, subscription_ends_at 
       FROM users 
       WHERE subscription_status = 'active' 
         AND subscription_ends_at < NOW()`
    );
    
    for (const user of result.rows) {
      await pool.query(
        `UPDATE users SET 
          subscription_status = 'expired',
          updated_at = NOW()
         WHERE id = $1`,
        [user.id]
      );
      
      console.log(`❌ Suscripción expirada para usuario ${user.email}`);
      // Aquí podrías enviar un email de notificación
    }
    
    console.log(`✅ Verificación completada. ${result.rows.length} suscripciones expiradas.`);
  } catch (error) {
    console.error('Error en verificación de suscripciones:', error);
  }
});

// Enviar recordatorio de fin de prueba (3 días antes)
cron.schedule('0 9 * * *', async () => {
  console.log('📧 Enviando recordatorios de fin de prueba...');
  
  try {
    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);
    
    const result = await pool.query(
      `SELECT id, email, trial_ends_at 
       FROM users 
       WHERE subscription_status = 'trial' 
        