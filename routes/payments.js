const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const db = require('../database/db-helper');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

const router = express.Router();

// POST /api/payments/create - Create payment intent with Stripe
router.post('/create', authenticateToken, async (req, res) => {
    try {
        const { amount, credits, currency = 'usd' } = req.body;

        if (!amount || !credits) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Amount and credits are required'
            });
        }

        // Validate amount and credits
        if (amount <= 0 || credits <= 0) {
            return res.status(400).json({
                error: 'Invalid values',
                message: 'Amount and credits must be positive numbers'
            });
        }

        // Check if Stripe is configured (demo mode if not)
        if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith('sk_test_demo')) {
            return res.json({
                success: true,
                message: 'Payment intent created (demo mode)',
                clientSecret: 'pi_demo_' + Date.now(),
                amount,
                credits,
                demoMode: true
            });
        }

        // Create Stripe payment intent
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount * 100), // Convert to cents
            currency: currency.toLowerCase(),
            metadata: {
                userId: req.user.id.toString(),
                userEmail: req.user.email,
                credits: credits.toString(),
                plan: req.body.plan || 'credit_purchase'
            },
            description: `VINaris Credit Purchase - ${credits} credits for ${req.user.email}`
        });

        res.json({
            success: true,
            message: 'Payment intent created successfully',
            clientSecret: paymentIntent.client_secret,
            paymentIntentId: paymentIntent.id,
            amount,
            credits
        });
        
    } catch (error) {
        console.error('Payment creation error:', error);
        res.status(500).json({
            error: 'Payment creation failed',
            message: error.message || 'Unable to create payment intent'
        });
    }
});

// POST /api/payments/confirm - Confirm payment (placeholder)
router.post('/confirm', authenticateToken, async (req, res) => {
    try {
        const { paymentIntentId, credits } = req.body;

        // In production, verify payment with Stripe
        // const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        // const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
        // if (paymentIntent.status !== 'succeeded') {
        //     return res.status(400).json({ error: 'Payment not completed' });
        // }

        // For demo, just add credits
        await db.connect();
        const newBalance = await db.addCredits(req.user.id, credits, `Credit purchase - ${credits} credits`, 'demo_payment');
        db.keepAlive();

        res.json({
            success: true,
            message: 'Payment confirmed and credits added',
            creditsAdded: credits,
            newBalance
        });
    } catch (error) {
        console.error('Payment confirmation error:', error);
        res.status(500).json({
            error: 'Payment confirmation failed',
            message: 'Unable to confirm payment'
        });
    }
});

// POST /api/payments/webhook - Stripe webhook handler
router.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        // Verify webhook signature if endpoint secret is configured
        if (endpointSecret) {
            event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        } else {
            // For demo/testing, parse the body directly
            event = JSON.parse(req.body);
        }
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    try {
        switch (event.type) {
            case 'payment_intent.succeeded':
                await handlePaymentSuccess(event.data.object);
                break;
            case 'payment_intent.payment_failed':
                await handlePaymentFailure(event.data.object);
                break;
            default:
                console.log(`Unhandled event type ${event.type}`);
        }
    } catch (error) {
        console.error('Webhook handling error:', error);
        return res.status(500).send('Webhook handling failed');
    }

    res.json({received: true});
});

// Handle successful payment
async function handlePaymentSuccess(paymentIntent) {
    try {
        const { userId, credits } = paymentIntent.metadata;
        
        await db.connect();
        
        // Record the payment
        const paymentId = 'PAY_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
        await db.run(`
            INSERT INTO payments (
                payment_id, user_id, amount_cents, currency, payment_method,
                payment_status, payment_reference, credits_purchased, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            paymentId,
            parseInt(userId),
            paymentIntent.amount,
            paymentIntent.currency,
            'stripe',
            'completed',
            paymentIntent.id,
            parseInt(credits),
            JSON.stringify(paymentIntent.metadata)
        ]);
        
        // Add credits to user account
        await db.addCredits(
            parseInt(userId),
            parseInt(credits),
            `Credit purchase - Payment ${paymentIntent.id}`,
            'stripe',
            null
        );
        
        // Log activity
        await db.logActivity(
            parseInt(userId),
            'credit_purchase',
            `Successfully purchased ${credits} credits via Stripe`,
            JSON.stringify({ paymentIntentId: paymentIntent.id, amount: paymentIntent.amount })
        );
        
        db.keepAlive();
        
        console.log(`✅ Payment processed successfully for user ${userId}: ${credits} credits`);
        
    } catch (error) {
        console.error('Error processing successful payment:', error);
        throw error;
    }
}

// Handle failed payment
async function handlePaymentFailure(paymentIntent) {
    try {
        const { userId } = paymentIntent.metadata;
        
        await db.connect();
        
        // Log failed payment attempt
        await db.logActivity(
            parseInt(userId),
            'payment_failed',
            `Payment failed: ${paymentIntent.last_payment_error?.message || 'Unknown error'}`,
            JSON.stringify({ paymentIntentId: paymentIntent.id, amount: paymentIntent.amount })
        );
        
        db.keepAlive();
        
        console.log(`❌ Payment failed for user ${userId}: ${paymentIntent.last_payment_error?.message}`);
        
    } catch (error) {
        console.error('Error processing failed payment:', error);
    }
}

// GET /api/payments/history - Get payment history
router.get('/history', authenticateToken, async (req, res) => {
    try {
        await db.connect();
        
        const payments = await db.all(`
            SELECT * FROM payments 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50
        `, [req.user.id]);
        
        db.keepAlive();
        
        const formattedPayments = payments.map(payment => ({
            id: payment.id,
            paymentId: payment.payment_id,
            amount: payment.amount_cents / 100, // Convert back to dollars
            currency: payment.currency,
            status: payment.payment_status,
            method: payment.payment_method,
            creditsReceived: payment.credits_purchased,
            createdAt: payment.created_at,
            reference: payment.payment_reference
        }));
        
        res.json({
            success: true,
            payments: formattedPayments
        });
        
    } catch (error) {
        console.error('Payment history error:', error);
        res.status(500).json({
            error: 'Payment history fetch failed',
            message: 'Unable to fetch payment history'
        });
    }
});

module.exports = router;
