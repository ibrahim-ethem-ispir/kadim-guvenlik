import React, { useState } from 'react';
import { Link } from 'react-router';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import '../pages/LoginPage.css';

export default function LoginRoute() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const { login } = useAuth();
    const [loading, setLoading] = useState(false);

    const AUTH_URL = '/api/auth';

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        // Türkçe: Basit validasyon
        if (!username.trim() || !password.trim()) {
            setError('Kullanıcı adı ve şifre zorunludur');
            return;
        }

        if (username.length < 3) {
            setError('Kullanıcı adı en az 3 karakter olmalıdır');
            return;
        }

        setLoading(true);
        setError('');

        try {
            // Türkçe: Nginx proxy üzerinden auth-service'e istek at
            // /api/auth -> auth-service:8007 şeklinde yönlendiriliyor
            const data = await api.post<any>('/api/auth/login', {
                username: username.trim(),
                password
            });

            // Türkçe: Başarılı giriş - token ve kullanıcı bilgisi ile login
            login(data.token, { username: data.username, role: data.role });
        } catch (err: any) {
            setError(err.message || 'Bir hata oluştu. Lütfen tekrar deneyin.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            {/* Pure CSS Stars */}
            <div id="stars"></div>
            <div id="stars2"></div>
            <div id="stars3"></div>

            {/* Shooting Stars */}
            <span className="shooting-star"></span>
            <span className="shooting-star"></span>
            <span className="shooting-star"></span>
            <span className="shooting-star"></span>

            <div className="login-box">
                <h2>Kadim Güvenlik</h2>
                <p className="subtitle">Güvenlik Yönetim Platformu</p>

                {error && <div className="error-message">{error}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="input-group">
                        <input
                            type="text"
                            placeholder="Kullanıcı Adı"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            autoComplete="username"
                            required
                        />
                    </div>
                    <div className="input-group">
                        <input
                            type="password"
                            placeholder="Şifre"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            autoComplete="current-password"
                            required
                        />
                    </div>
                    <button type="submit" disabled={loading}>
                        {loading ? 'Giriş Yapılıyor...' : 'Giriş Yap'}
                    </button>

                    <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
                        <p style={{ color: '#666', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                            Hesabınız yok mu?
                        </p>
                        <Link
                            to="/register"
                            style={{
                                color: '#4facfe',
                                textDecoration: 'none',
                                fontSize: '0.9rem',
                                fontWeight: '500'
                            }}
                        >
                            Yeni Hesap Oluştur
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
}

