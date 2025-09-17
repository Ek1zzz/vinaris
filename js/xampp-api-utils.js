/**
 * VINaris API Utilities
 * Now works with Node.js backend API
 */

// =================== API CONFIGURATION ===================
class APIConfig {
    static BASE_URL = 'http://localhost:3001/api';
    
    static ENDPOINTS = {
        // Authentication
        REGISTER: '/auth/register',
        LOGIN: '/auth/login',
        LOGOUT: '/auth/logout',
        
        // Users
        PROFILE: '/users/profile',
        CREDITS: '/users/credits',
        HISTORY: '/users/history',
        
        // VIN Services
        VIN_CHECK: '/vin/check',
        
        // System
        HEALTH: '/health'
    };
}

// =================== API CLIENT ===================
class APIClient {
    static async request(endpoint, options = {}) {
        const url = APIConfig.BASE_URL + endpoint;
        
        // Get JWT token if available
        const token = TokenManager.getAccessToken();
        
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            credentials: 'include', // Include cookies for session management
            ...options
        };
        
        // Add Authorization header if token exists
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        
        try {
            const response = await fetch(url, config);

            if (!response.ok) {
                // Try to get error message from response
                let errorMessage = `Request failed with status ${response.status}`;
                try {
                    const errorData = await response.json();
                    if (errorData.message) {
                        errorMessage = errorData.message;
                    }
                } catch (parseError) {
                    // If we can't parse as JSON, try to get text
                    try {
                        const errorText = await response.text();
                        if (errorText) {
                            errorMessage = errorText;
                        }
                    } catch (textError) {
                        // If both fail, use status-based message
                        if (response.status === 401) {
                            errorMessage = 'არასწორი პაროლი';
                        }
                    }
                }
                console.error('API Request failed:', response.status, errorMessage);
                throw new Error(errorMessage);
            }
            
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }
    
    static async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }
    
    static async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    static async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
}

// =================== TOKEN MANAGEMENT ===================
class TokenManager {
    static USER_KEY = 'vinaris_current_user';
    static SESSION_KEY = 'vinaris_session';
    static TOKEN_KEY = 'vinaris_access_token';
    
    static setCurrentUser(user, tokens = null) {
        const userData = {
            ...user,
            loginTime: Date.now(),
            sessionId: this.generateSessionId()
        };
        localStorage.setItem(this.USER_KEY, JSON.stringify(userData));
        
        // Store JWT token if provided
        if (tokens && tokens.accessToken) {
            localStorage.setItem(this.TOKEN_KEY, tokens.accessToken);
        }
        sessionStorage.setItem(this.SESSION_KEY, userData.sessionId);
    }
    
    static getCurrentUser() {
        try {
            const user = localStorage.getItem(this.USER_KEY);
            if (!user) return null;
            
            const userData = JSON.parse(user);
            
            // Check if session is still valid (24 hours)
            const sessionAge = Date.now() - userData.loginTime;
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours
            
            if (sessionAge > maxAge) {
                this.clearToken();
                return null;
            }
            
            return userData;
        } catch (error) {
            console.error('Error parsing user data:', error);
            this.clearToken();
            return null;
        }
    }
    
    static getAccessToken() {
        try {
            return localStorage.getItem(this.TOKEN_KEY);
        } catch (error) {
            console.error('Error getting access token:', error);
            return null;
        }
    }
    
    static clearToken() {
        localStorage.removeItem(this.USER_KEY);
        localStorage.removeItem(this.TOKEN_KEY);
        sessionStorage.removeItem(this.SESSION_KEY);
    }
    
    static generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    static isSessionValid() {
        const user = this.getCurrentUser();
        const sessionId = sessionStorage.getItem(this.SESSION_KEY);
        return user && user.sessionId === sessionId;
    }
}

// =================== API-CONNECTED AUTHENTICATION ===================
class EnhancedAuth {
    static async login(email, password, rememberMe = false) {
        try {
            // Validate input
            if (!email || !password) {
                throw new Error('ელ-ფოსტა და პაროლი აუცილებელია');
            }
            
            const response = await APIClient.post(APIConfig.ENDPOINTS.LOGIN, {
                email: email.trim(),
                password: password.trim()
            });
            
            if (response && response.success && response.user) {
                TokenManager.setCurrentUser(response.user, response.tokens);
                EnhancedUI.showToast('წარმატებით შედიხართ!', 'success');
                return response.user;
            } else {
                console.error('Login failed - response:', response);
                throw new Error(response?.message || 'შესვლა ვერ მოხერხდა');
            }
        } catch (error) {
            EnhancedUI.showToast(error.message || 'შესვლისას შეცდომა', 'error');
            throw error;
        }
    }
    
    static async register(name, email, password, company = '', phone = '') {
        try {
            const response = await APIClient.post(APIConfig.ENDPOINTS.REGISTER, {
                name,
                email,
                password,
                company,
                phone
            });
            
            if (response.success) {
                TokenManager.setCurrentUser(response.user, response.tokens);
                EnhancedUI.showToast('წარმატებით დარეგისტრირდით!', 'success');
                return response.user;
            }
        } catch (error) {
            EnhancedUI.showToast(error.message || 'რეგისტრაციისას შეცდომა', 'error');
            throw error;
        }
    }
    
    static async logout() {
        try {
            // Try to logout from server
            await APIClient.post(APIConfig.ENDPOINTS.LOGOUT);
        } catch (error) {
            console.warn('Server logout failed:', error);
        } finally {
            // Always clear local session
            TokenManager.clearToken();
            EnhancedUI.showToast('წარმატებით გამოხვედით!', 'success');
            
            // Redirect to login page
            setTimeout(() => {
                window.location.href = '../Login/login.html';
            }, 1000);
        }
        return true;
    }
    
    static isLoggedIn() {
        return TokenManager.isSessionValid();
    }
    
    static isAdmin() {
        const user = TokenManager.getCurrentUser();
        return user && (user.type === 'admin' || user.user_type === 'admin');
    }
    
    static getCurrentUser() {
        return TokenManager.getCurrentUser();
    }
    
    static checkSession() {
        if (!this.isLoggedIn()) {
            this.logout();
            return false;
        }
        return true;
    }
    
    static refreshSession() {
        const user = this.getCurrentUser();
        if (user) {
            TokenManager.setCurrentUser(user);
            return true;
        }
        return false;
    }
    
    static async refreshUserData() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.PROFILE);
            if (response.success) {
                TokenManager.setCurrentUser(response.user);
                return response.user;
            }
        } catch (error) {
            console.error('Failed to refresh user data:', error);
            // Don't throw error, just return null
            return null;
        }
    }
}

// =================== API-CONNECTED USER MANAGEMENT ===================
class UserManager {
    static async getProfile() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.PROFILE);
            if (response.success) {
                TokenManager.setCurrentUser(response.user);
                return {
                    user: response.user,
                    recentTransactions: [],
                    recentActivities: []
                };
            }
        } catch (error) {
            console.error('Failed to get profile:', error);
            throw error;
        }
    }
    
    static async updateProfile(profileData) {
        try {
            const response = await APIClient.post('/users/profile/update', profileData);
            if (response.success) {
                TokenManager.setCurrentUser(response.user);
                EnhancedUI.showToast('პროფილი წარმატებით განახლდა!', 'success');
                return response.user;
            }
        } catch (error) {
            console.error('Failed to update profile:', error);
            EnhancedUI.showToast('პროფილის განახლება ვერ მოხერხდა: ' + error.message, 'error');
            throw error;
        }
    }
    
    static async getCredits() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.CREDITS);
            if (response.success) {
                return {
                    credits: response.credits,
                    totalEarned: response.credits,
                    totalSpent: 0,
                    transactions: []
                };
            }
        } catch (error) {
            console.error('Failed to get credits:', error);
            throw error;
        }
    }
    
    static async getHistory() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.HISTORY);
            return response.success ? response.requests : [];
        } catch (error) {
            console.error('Failed to get history:', error);
            return [];
        }
    }
    
    static getAllUsers() {
        // Mock data for now - replace with real API call
        return {};
    }
    
    static getUserById(userId) {
        // Mock data for now - replace with real API call
        return null;
    }
}

// =================== API-CONNECTED ADMIN MANAGEMENT ===================
class AdminManager {
    static async getRequests() {
        try {
            const response = await APIClient.get('/admin/requests');
            if (response.success) {
                return response.requests.map(request => ({
                    id: request.id,
                    requestId: request.requestId,
                    vin: request.vin,
                    plan: request.plan,
                    status: request.status,
                    userName: request.userName,
                    userEmail: request.userEmail,
                    createdAt: request.createdAt,
                    pdf_filename: request.pdf_filename,
                    processed_by: request.processed_by,
                    processing_notes: request.processing_notes,
                    report_data: request.report_data
                }));
            }
            return [];
        } catch (error) {
            console.error('Failed to get admin requests:', error);
            return [];
        }
    }
    
    static async getUsers() {
        try {
            const response = await APIClient.get('/admin/users');
            return response.success ? response.users : [];
        } catch (error) {
            console.error('Failed to get admin users:', error);
            return [];
        }
    }
    
    static async updateUserCredits(userId, credits) {
        try {
            const response = await APIClient.post('/admin/users/credits', {
                user_id: userId,
                credits: credits
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update user credits:', error);
            return false;
        }
    }
    
    static async updateUser(userId, userData) {
        try {
            const response = await APIClient.post('/admin/users/update', {
                user_id: userId,
                name: userData.name,
                email: userData.email
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update user:', error);
            return false;
        }
    }
    
    static async updateUserStatus(userId, status) {
        try {
            const response = await APIClient.post('/admin/users/status', {
                user_id: userId,
                status: status
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update user status:', error);
            return false;
        }
    }
    
    static async getUserActivities(userId) {
        try {
            const response = await APIClient.get(`/admin/users/${userId}/activities`);
            return response.success ? response.activities : [];
        } catch (error) {
            console.error('Failed to get user activities:', error);
            return [];
        }
    }

    static async createUser(userData) {
        try {
            const response = await APIClient.post('/admin/users/create', userData);
            return response.success ? response : null;
        } catch (error) {
            console.error('Failed to create user:', error);
            throw error;
        }
    }

    static async getUserDetails(userId) {
        try {
            const response = await APIClient.get(`/admin/users/${userId}/details`);
            return response.success ? response : null;
        } catch (error) {
            console.error('Failed to get user details:', error);
            throw error;
        }
    }
    
    static async deleteUser(userId) {
        try {
            const response = await APIClient.delete(`/admin/users/${userId}`);
            return response.success;
        } catch (error) {
            console.error('Failed to delete user:', error);
            return false;
        }
    }
    
    static async updateRequestStatus(requestId, status, notes = '') {
        try {
            const response = await APIClient.put(`/admin/request/${requestId}`, {
                status: status,
                notes: notes
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update request status:', error);
            return false;
        }
    }
    
    static async getDashboardStats() {
        try {
            console.log('Fetching dashboard stats...');
            const [requests, users] = await Promise.all([
                this.getRequests(),
                this.getUsers()
            ]);
            
            console.log('Requests:', requests.length, 'Users:', users.length);
            
            const today = new Date().toISOString().split('T')[0];
            const todayRequests = requests.filter(req => 
                req.createdAt && req.createdAt.startsWith(today)
            );
            
            const pendingRequests = requests.filter(req => req.status === 'pending');
            
            const stats = {
                totalUsers: users.length,
                totalRequests: requests.length,
                todayRequests: todayRequests.length,
                pendingRequests: pendingRequests.length,
                averageProcessingTime: 5 // Mock data for now
            };
            
            console.log('Calculated stats:', stats);
            return stats;
        } catch (error) {
            console.error('Failed to get dashboard stats:', error);
            return {
                totalUsers: 0,
                totalRequests: 0,
                todayRequests: 0,
                pendingRequests: 0,
                averageProcessingTime: 0
            };
        }
    }
}

// =================== API-CONNECTED CREDIT MANAGEMENT ===================
class CreditManager {
    static async addCredits(userId, amount, reason, adminId) {
        try {
            const response = await APIClient.post('/admin/users/credits', {
                user_id: userId,
                credits: amount,
                reason: reason,
                admin_id: adminId
            });
            return response.success;
        } catch (error) {
            console.error('Failed to add credits:', error);
            return false;
        }
    }
    
    static async deductCredits(userId, amount, reason, adminId) {
        try {
            const response = await APIClient.post('/admin/users/credits', {
                user_id: userId,
                credits: -amount,
                reason: reason,
                admin_id: adminId
            });
            return response.success;
        } catch (error) {
            console.error('Failed to deduct credits:', error);
            return false;
        }
    }
    
    static async getAllTransactions() {
        try {
            const response = await APIClient.get('/admin/credit-transactions');
            return response.success ? response.transactions : [];
        } catch (error) {
            console.error('Failed to fetch credit transactions:', error);
            return [];
        }
    }
    
    static async getUserTransactions(userId) {
        try {
            const response = await APIClient.get(`/admin/credit-transactions?user_id=${userId}`);
            return response.success ? response.transactions : [];
        } catch (error) {
            console.error('Failed to fetch user credit transactions:', error);
            return [];
        }
    }
    
    static async getUserCreditTransactions(limit = 50) {
        try {
            const response = await APIClient.get(`/users/credit-transactions?limit=${limit}`);
            return response.success ? response.transactions : [];
        } catch (error) {
            console.error('Failed to fetch user credit transactions:', error);
            return [];
        }
    }
}

// =================== API-CONNECTED PDF MANAGEMENT ===================
class PDFManager {
    static async uploadPDF(requestId, file, adminId) {
        try {
            // Convert file to base64
            const base64Data = await this.fileToBase64(file);
            
            const response = await APIClient.post('/admin/upload-pdf', {
                request_id: requestId,
                admin_id: adminId,
                pdf_data: base64Data
            });
            
            if (response.success) {
                return true;
            } else {
                console.error('PDF upload failed:', response.error || response.message);
                return false;
            }
        } catch (error) {
            console.error('Failed to upload PDF:', error);
            return false;
        }
    }
    
    static fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => resolve(reader.result);
            reader.onerror = error => reject(error);
        });
    }
    
    static async sendPDFToUser(requestId, adminId) {
        try {
            const response = await APIClient.post('/admin/send-pdf', {
                request_id: requestId,
                admin_id: adminId
            });
            
            if (response.success) {
                return true;
            } else {
                console.error('Send PDF failed:', response.error || response.message);
                return false;
            }
        } catch (error) {
            console.error('Failed to send PDF:', error);
            return false;
        }
    }
}

// =================== API-CONNECTED DATABASE MANAGEMENT ===================
class VinDatabase {
    static ADMIN_SETTINGS_KEY = 'admin_settings';
    
    static get(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('Failed to get from database:', error);
            return defaultValue;
        }
    }
    
    static set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error('Failed to set in database:', error);
            return false;
        }
    }
}

// =================== API-CONNECTED VIN REQUEST MANAGEMENT ===================
class VinRequestManager {
    static async createRequest(vin, plan = 'basic') {
        try {
            const response = await APIClient.post(APIConfig.ENDPOINTS.VIN_CHECK, {
                vin: vin.toUpperCase(),
                plan
            });
            
            if (response.success) {
                EnhancedUI.showToast('VIN მოთხოვნა წარმატებით გაიგზავნა!', 'success');
                
                // Update current user credits
                const currentUser = TokenManager.getCurrentUser();
                if (currentUser) {
                    currentUser.credits = response.creditsRemaining;
                    TokenManager.setCurrentUser(currentUser);
                }
                
                return {
                    id: response.requestId,
                    vin: response.vin,
                    plan: response.plan,
                    status: response.status,
                    basicData: response.basicData,
                    creditsRemaining: response.creditsRemaining,
                    estimatedCompletion: response.estimatedCompletion
                };
            } else {
                // Handle API error response
                const errorMessage = response.error || response.message || 'VIN check failed';
                throw new Error(errorMessage);
            }
        } catch (error) {
            EnhancedUI.showToast(error.message || 'VIN მოთხოვნის შექმნისას შეცდომა', 'error');
            throw error;
        }
    }
    
    static async getUserRequests() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.HISTORY);
            return response.success ? response.requests : [];
        } catch (error) {
            console.error('Failed to get user requests:', error);
            return [];
        }
    }
    
    static async getAllRequests() {
        try {
            const response = await fetch('/Vinaris/api.php/users/requests', {
                method: 'GET',
                credentials: 'include'
            });
            
            const result = await response.json();
            if (result.success) {
                return result.requests.map(request => ({
                    id: request.id,
                    vin: request.vin,
                    plan: request.plan,
                    status: request.status,
                    createdAt: request.createdAt,
                    pdfFilename: request.pdf_filename,
                    reportData: request.report_data
                }));
            } else {
                console.error('Failed to get VIN requests:', result.error);
                return [];
            }
        } catch (error) {
            console.error('Failed to get VIN requests:', error);
            return [];
        }
    }
    
    static async updateRequestStatus(requestId, status, adminId, reason) {
        try {
            const response = await APIClient.post('/admin/requests/status', {
                request_id: requestId,
                status: status,
                admin_id: adminId,
                reason: reason
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update request status:', error);
            return false;
        }
    }
    
    static async downloadPDF(requestId) {
        try {
            // Get request details to find the request ID
            const requests = await this.getUserRequests();
            const request = requests.find(r => r.id == requestId);
            
            if (!request || !request.pdf_filename) {
                throw new Error('PDF not available for this request');
            }
            
            // Get the access token
            const token = TokenManager.getAccessToken();
            if (!token) {
                throw new Error('Authentication required');
            }
            
            // Create download link using the API endpoint
            const downloadUrl = `${APIConfig.BASE_URL}/users/download-pdf/${request.requestId}`;
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = `VINaris_Report_${request.vin}.pdf`;
            
            // Add authorization header by creating a fetch request
            const response = await fetch(downloadUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                let errorMessage = 'Failed to download PDF';
                try {
                    const errorData = await response.json();
                    if (errorData.message) {
                        errorMessage = errorData.message;
                    }
                } catch (parseError) {
                    // If we can't parse as JSON, use default message
                    console.error('Failed to parse error response:', parseError);
                }
                throw new Error(errorMessage);
            }
            
            // Get the PDF blob
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            
            // Create download link
            link.href = url;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Clean up the URL object
            window.URL.revokeObjectURL(url);
            
            return true;
        } catch (error) {
            console.error('Failed to download PDF:', error);
            throw error;
        }
    }
}

// =================== ENHANCED UI COMPONENTS ===================
class EnhancedUI {
    static showToast(message, type = 'info', duration = 4000) {
        // Remove existing toasts
        const existingToasts = document.querySelectorAll('.toast');
        existingToasts.forEach(toast => toast.remove());

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        `;
        
        // Debug: Log toast positioning
        console.log('Toast created with position:', {
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: '10000'
        });
        
        // Add styles if not already present
        if (!document.querySelector('#toast-styles')) {
            const styles = document.createElement('style');
            styles.id = 'toast-styles';
            styles.textContent = `
                .toast {
                    position: fixed !important;
                    top: 20px !important;
                    right: 20px !important;
                    background: white;
                    border-radius: 8px;
                    padding: 16px 20px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    border-left: 4px solid;
                    z-index: 10000;
                    max-width: 400px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    animation: slideIn 0.3s ease;
                }
                
                .toast-success { border-left-color: #22c55e; }
                .toast-error { border-left-color: #ef4444; }
                .toast-warning { border-left-color: #f59e0b; }
                .toast-info { border-left-color: #3b82f6; }
                
                .toast-message {
                    flex: 1;
                    font-size: 14px;
                    color: #333;
                }
                
                .toast-close {
                    background: none;
                    border: none;
                    font-size: 18px;
                    cursor: pointer;
                    padding: 0;
                    width: 20px;
                    height: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #666;
                }
                
                .toast-close:hover {
                    color: #333;
                }
                
                @keyframes slideIn {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            `;
            document.head.appendChild(styles);
        }
        
        document.body.appendChild(toast);
        
        // Auto remove after duration
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, duration);
    }
    
    static showLoading(message = 'იტვირთება...') {
        const existing = document.querySelector('.loading-overlay');
        if (existing) existing.remove();
        
        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-content">
                <div class="loading-spinner"></div>
                <p>${message}</p>
            </div>
        `;
        
        // Add styles if not already present
        if (!document.querySelector('#loading-styles')) {
            const styles = document.createElement('style');
            styles.id = 'loading-styles';
            styles.textContent = `
                .loading-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 10001;
                }
                
                .loading-content {
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                }
                
                .loading-spinner {
                    border: 3px solid #f3f4f6;
                    border-top: 3px solid #e60000;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 0 auto 15px;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .loading-content p {
                    margin: 0;
                    color: #333;
                    font-size: 16px;
                }
            `;
            document.head.appendChild(styles);
        }
        
        document.body.appendChild(overlay);
    }
    
    static hideLoading() {
        const overlay = document.querySelector('.loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }
    
    static formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('ka-GE') + ' ' + date.toLocaleTimeString('ka-GE', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }
    
    static formatCurrency(amount) {
        return `$${amount.toFixed(2)}`;
    }
}

// =================== SYSTEM HEALTH CHECK ===================
class SystemHealth {
    static async checkAPIConnection() {
        try {
            const response = await APIClient.get(APIConfig.ENDPOINTS.HEALTH);
            return response.status === 'healthy';
        } catch (error) {
            console.error('API health check failed:', error);
            return false;
        }
    }
    
    static async initializeSystem() {
        // Check if user is logged in
        if (TokenManager.getCurrentUser()) {
            try {
                await EnhancedAuth.refreshUserData();
                return true;
            } catch (error) {
                TokenManager.clearToken();
                return false;
            }
        }
        return false;
    }
}

// =================== INITIALIZATION ===================
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 VINaris XAMPP-Compatible System Initializing...');
    
    try {
        // Check API connection
        const isAPIHealthy = await SystemHealth.checkAPIConnection();
        if (!isAPIHealthy) {
            EnhancedUI.showToast('API სერვერთან კავშირი ვერ დამყარდა', 'error');
            console.error('API server is not responding');
        } else {
            console.log('✅ API connection successful');
        }
        
        // Initialize user session
        const isLoggedIn = await SystemHealth.initializeSystem();
        console.log(isLoggedIn ? '👤 User session restored' : '🔓 No active session');
        
        // Initialize any page-specific functionality
        if (typeof window.initializePage === 'function') {
            window.initializePage();
        }
        
    } catch (error) {
        console.error('System initialization error:', error);
        EnhancedUI.showToast('სისტემის ინიციალიზაციისას შეცდომა', 'error');
    }
});

// =================== ACTIVITY LOGGING ===================
class ActivityLogger {
    static async log(activityType, description, metadata = {}) {
        try {
            const response = await APIClient.post('/activities/log', {
                activity_type: activityType,
                description: description,
                metadata: metadata
            });
            return response.success;
        } catch (error) {
            console.error('Failed to log activity:', error);
            return false;
        }
    }
    
    static async getAllActivities(limit = 100) {
        try {
            const response = await APIClient.get(`/admin/activities?limit=${limit}`);
            return response.success ? response.activities : [];
        } catch (error) {
            console.error('Failed to fetch activities:', error);
            return [];
        }
    }
    
    static async getUserActivities(userId, limit = 50) {
        try {
            const response = await APIClient.get(`/admin/activities?user_id=${userId}&limit=${limit}`);
            return response.success ? response.activities : [];
        } catch (error) {
            console.error('Failed to fetch user activities:', error);
            return [];
        }
    }
}

// =================== PAYMENT MANAGEMENT ===================
class PaymentManager {
    static async createPaymentRequest(paymentData) {
        try {
            const response = await APIClient.post('/users/payment-request', paymentData);
            return response.success ? response : null;
        } catch (error) {
            console.error('Failed to create payment request:', error);
            throw error;
        }
    }
    
    static async getUserPaymentRequests(limit = 20) {
        try {
            const response = await APIClient.get(`/users/payment-requests?limit=${limit}`);
            return response.success ? response.requests : [];
        } catch (error) {
            console.error('Failed to fetch payment requests:', error);
            return [];
        }
    }
    
    static async getAllPaymentRequests(status = null, limit = 50) {
        try {
            const url = status ? 
                `/admin/payment-requests?status=${status}&limit=${limit}` : 
                `/admin/payment-requests?limit=${limit}`;
            const response = await APIClient.get(url);
            return response.success ? response.requests : [];
        } catch (error) {
            console.error('Failed to fetch payment requests:', error);
            return [];
        }
    }
    
    static async updatePaymentStatus(paymentId, status, verificationNotes = '') {
        try {
            const response = await APIClient.post('/admin/payment-request', {
                payment_id: paymentId,
                status: status,
                verification_notes: verificationNotes
            });
            return response.success;
        } catch (error) {
            console.error('Failed to update payment status:', error);
            return false;
        }
    }
    
    static formatPaymentStatus(status) {
        const statusMap = {
            'pending': { text: 'მოლოდინში', class: 'warning' },
            'verified': { text: 'შემოწმებული', class: 'info' },
            'approved': { text: 'დამტკიცებული', class: 'success' },
            'rejected': { text: 'უარყოფილი', class: 'danger' },
            'cancelled': { text: 'გაუქმებული', class: 'muted' }
        };
        return statusMap[status] || { text: status, class: 'muted' };
    }
}

// Export classes for global use
window.EnhancedAuth = EnhancedAuth;
window.UserManager = UserManager;
window.VinRequestManager = VinRequestManager;
window.EnhancedUI = EnhancedUI;
window.APIClient = APIClient;
window.TokenManager = TokenManager;
window.APIConfig = APIConfig;
window.ActivityLogger = ActivityLogger;
window.PaymentManager = PaymentManager;
