/**
 * VINaris Payment Service
 * Handles payment processing with multiple gateways
 */

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');

class PaymentService {
    constructor() {
        this.gateways = {
            stripe: this.stripeGateway,
            paypal: this.paypalGateway,
            bank_transfer: this.bankTransferGateway
        };
    }

    // Stripe Payment Gateway
    async stripeGateway(paymentData) {
        try {
            const { amount, currency, customerEmail, metadata } = paymentData;
            
            // Create payment intent
            const paymentIntent = await stripe.paymentIntents.create({
                amount: Math.round(amount * 100), // Convert to cents
                currency: currency.toLowerCase(),
                metadata: {
                    customer_email: customerEmail,
                    service: 'vinaris',
                    ...metadata
                },
                automatic_payment_methods: {
                    enabled: true,
                },
            });

            return {
                success: true,
                paymentId: paymentIntent.id,
                clientSecret: paymentIntent.client_secret,
                status: paymentIntent.status,
                gateway: 'stripe'
            };

        } catch (error) {
            console.error('Stripe payment error:', error);
            return {
                success: false,
                error: error.message,
                gateway: 'stripe'
            };
        }
    }

    // PayPal Payment Gateway (placeholder)
    async paypalGateway(paymentData) {
        try {
            // PayPal integration would go here
            // This is a placeholder implementation
            
            const { amount, currency, customerEmail } = paymentData;
            
            // Simulate PayPal payment creation
            const paymentId = `paypal_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            
            return {
                success: true,
                paymentId: paymentId,
                approvalUrl: `https://paypal.com/approve/${paymentId}`,
                status: 'pending',
                gateway: 'paypal'
            };

        } catch (error) {
            console.error('PayPal payment error:', error);
            return {
                success: false,
                error: error.message,
                gateway: 'paypal'
            };
        }
    }

    // Bank Transfer Gateway
    async bankTransferGateway(paymentData) {
        try {
            const { amount, currency, customerEmail, customerName } = paymentData;
            
            // Generate bank transfer details
            const transferId = `bank_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            
            const bankDetails = {
                accountName: 'VINaris LLC',
                accountNumber: process.env.BANK_ACCOUNT_NUMBER || '1234567890',
                bankName: process.env.BANK_NAME || 'Bank of Georgia',
                swiftCode: process.env.BANK_SWIFT || 'BAGEUS33',
                reference: transferId,
                amount: amount,
                currency: currency
            };

            return {
                success: true,
                paymentId: transferId,
                status: 'pending_verification',
                gateway: 'bank_transfer',
                bankDetails: bankDetails,
                instructions: `Please transfer ${amount} ${currency} using the provided bank details. Use reference: ${transferId}`
            };

        } catch (error) {
            console.error('Bank transfer error:', error);
            return {
                success: false,
                error: error.message,
                gateway: 'bank_transfer'
            };
        }
    }

    // Main payment processing method
    async processPayment(paymentData) {
        const { gateway = 'stripe', amount, currency = 'USD', customerEmail, customerName, metadata = {} } = paymentData;

        // Validate payment data
        if (!amount || amount <= 0) {
            return {
                success: false,
                error: 'Invalid payment amount'
            };
        }

        if (!customerEmail) {
            return {
                success: false,
                error: 'Customer email is required'
            };
        }

        // Check if gateway is supported
        if (!this.gateways[gateway]) {
            return {
                success: false,
                error: `Unsupported payment gateway: ${gateway}`
            };
        }

        // Add metadata
        const enhancedPaymentData = {
            ...paymentData,
            metadata: {
                timestamp: new Date().toISOString(),
                service: 'vinaris',
                ...metadata
            }
        };

        // Process payment with selected gateway
        const result = await this.gateways[gateway](enhancedPaymentData);

        // Log payment attempt
        console.log(`Payment processed via ${gateway}:`, {
            success: result.success,
            paymentId: result.paymentId,
            amount: amount,
            currency: currency,
            customer: customerEmail
        });

        return result;
    }

    // Verify payment status
    async verifyPayment(paymentId, gateway) {
        try {
            switch (gateway) {
                case 'stripe':
                    const paymentIntent = await stripe.paymentIntents.retrieve(paymentId);
                    return {
                        success: true,
                        status: paymentIntent.status,
                        amount: paymentIntent.amount / 100,
                        currency: paymentIntent.currency,
                        gateway: 'stripe'
                    };

                case 'paypal':
                    // PayPal verification would go here
                    return {
                        success: true,
                        status: 'completed', // Placeholder
                        gateway: 'paypal'
                    };

                case 'bank_transfer':
                    // Bank transfer verification would check bank records
                    return {
                        success: true,
                        status: 'pending_verification',
                        gateway: 'bank_transfer'
                    };

                default:
                    return {
                        success: false,
                        error: 'Unknown gateway'
                    };
            }
        } catch (error) {
            console.error('Payment verification error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Refund payment
    async refundPayment(paymentId, gateway, amount = null) {
        try {
            switch (gateway) {
                case 'stripe':
                    const refund = await stripe.refunds.create({
                        payment_intent: paymentId,
                        amount: amount ? Math.round(amount * 100) : undefined
                    });

                    return {
                        success: true,
                        refundId: refund.id,
                        status: refund.status,
                        amount: refund.amount / 100,
                        gateway: 'stripe'
                    };

                case 'paypal':
                    // PayPal refund would go here
                    return {
                        success: true,
                        refundId: `paypal_refund_${Date.now()}`,
                        status: 'completed',
                        gateway: 'paypal'
                    };

                case 'bank_transfer':
                    // Bank transfer refunds require manual processing
                    return {
                        success: true,
                        refundId: `bank_refund_${Date.now()}`,
                        status: 'pending_processing',
                        gateway: 'bank_transfer',
                        message: 'Refund will be processed manually within 3-5 business days'
                    };

                default:
                    return {
                        success: false,
                        error: 'Unknown gateway'
                    };
            }
        } catch (error) {
            console.error('Refund error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Generate payment webhook signature
    generateWebhookSignature(payload, secret) {
        return crypto
            .createHmac('sha256', secret)
            .update(payload, 'utf8')
            .digest('hex');
    }

    // Verify webhook signature
    verifyWebhookSignature(payload, signature, secret) {
        const expectedSignature = this.generateWebhookSignature(payload, secret);
        return crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    }

    // Get supported payment methods
    getSupportedGateways() {
        return {
            stripe: {
                name: 'Stripe',
                currencies: ['USD', 'EUR', 'GBP', 'GEL'],
                methods: ['card', 'bank_transfer', 'apple_pay', 'google_pay'],
                fees: '2.9% + 30¢ per transaction'
            },
            paypal: {
                name: 'PayPal',
                currencies: ['USD', 'EUR', 'GBP', 'GEL'],
                methods: ['paypal', 'credit_card'],
                fees: '3.4% + fixed fee per transaction'
            },
            bank_transfer: {
                name: 'Bank Transfer',
                currencies: ['GEL', 'USD', 'EUR'],
                methods: ['bank_transfer'],
                fees: 'No fees (customer pays bank fees)',
                processing_time: '1-3 business days'
            }
        };
    }

    // Calculate credit packages
    getCreditPackages() {
        return [
            {
                id: 'starter',
                name: 'Starter Package',
                credits: 5,
                price: 49.95,
                currency: 'USD',
                description: 'Perfect for occasional VIN checks',
                popular: false
            },
            {
                id: 'professional',
                name: 'Professional Package',
                credits: 15,
                price: 139.95,
                currency: 'USD',
                description: 'Great for regular users',
                popular: true
            },
            {
                id: 'business',
                name: 'Business Package',
                credits: 50,
                price: 399.95,
                currency: 'USD',
                description: 'Ideal for businesses and dealers',
                popular: false
            },
            {
                id: 'enterprise',
                name: 'Enterprise Package',
                credits: 200,
                price: 1299.95,
                currency: 'USD',
                description: 'For high-volume users',
                popular: false
            }
        ];
    }
}

// Create singleton instance
const paymentService = new PaymentService();

module.exports = paymentService;
