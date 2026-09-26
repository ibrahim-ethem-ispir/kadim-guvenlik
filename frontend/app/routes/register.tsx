import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { api } from '../services/api';
import '../pages/LoginPage.css';

export default function RegisterRoute() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [successMessage, setSuccessMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const AUTH_URL = '/api/auth';

    // Türkçe: Şifre gücü kontrolü
    const getPasswordStrength = (pwd: string) => {
        if (pwd.length < 6) return { level: 0, text: 'Çok Kısa', color: '#ef4444' };
        if (pwd.length < 8) return { level: 1, text: 'Zayıf', color: '#f97316' };
        if (pwd.length >= 8 && /[A-Z]/.test(pwd) && /[0-9]/.test(pwd)) {
            return { level: 3, text: 'Güçlü', color: '#22c55e' };
        }
        return { level: 2, text: 'Orta', color: '#eab308' };
    };

    const passwordStrength = getPasswordStrength(password);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');

        // Türkçe: Validasyonlar
        if (!username.trim()) {
            setError('Kullanıcı adı zorunludur');
            return;
        }

        if (username.trim().length < 3) {
            setError('Kullanıcı adı en az 3 karakter olmalıdır');
            return;
        }

        if (username.trim().length > 20) {
            setError('Kullanıcı adı en fazla 20 karakter olabilir');
            return;
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username.trim())) {
            setError('Kullanıcı adı sadece harf, rakam ve alt çizgi içerebilir');
            return;
        }

        if (password.length < 6) {
            setError('Şifre en az 6 karakter olmalıdır');
            return;
        }

        if (password !== confirmPassword) {
            setError('Şifreler uyuşmuyor');
            return;
        }

        setLoading(true);

        try {
            const data = await api.post<any>('/api/auth/register', {
                username: username.trim(),
                password
            });

            setSuccessMessage(data.message || 'Kayıt başarılı! Giriş sayfasına yönlendiriliyorsunuz...');
            setTimeout(() => navigate('/login'), 2000);

        } catch (err: any) {
            setError(err.message || 'Kayıt işlemi sırasında bir hata oluştu');
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
                <p className="subtitle">Yeni Hesap Oluştur</p>

                {error && <div className="error-message">{error}</div>}
                {successMessage && (
                    <div className="success-message" style={{ color: '#4caf50', marginBottom: '1rem', textAlign: 'center' }}>
                        {successMessage}
                    </div>
                )}

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
                            placeholder="Şifre (en az 6 karakter)"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            autoComplete="new-password"
                            required
                        />
                        {password && (
                            <div style={{ marginTop: '0.5rem', fontSize: '0.75rem' }}>
                                <div style={{
                                    display: 'flex',
                                    gap: '4px',
                                    marginBottom: '4px'
                                }}>
                                    {[0, 1, 2, 3].map((i) => (
                                        <div
                                            key={i}
                                            style={{
                                                height: '4px',
                                                flex: 1,
                                                borderRadius: '2px',
                                                backgroundColor: i <= passwordStrength.level ? passwordStrength.color : '#374151'
                                            }}
                                        />
                                    ))}
                                </div>
                                <span style={{ color: passwordStrength.color }}>
                                    {passwordStrength.text}
                                </span>
                            </div>
                        )}
                    </div>
                    <div className="input-group">
                        <input
                            type="password"
                            placeholder="Şifre Tekrar"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            autoComplete="new-password"
                            required
                        />
                        {confirmPassword && password !== confirmPassword && (
                            <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#ef4444' }}>
                                Şifreler uyuşmuyor
                            </div>
                        )}
                    </div>
                    <button type="submit" disabled={loading || password !== confirmPassword}>
                        {loading ? 'Kaydediliyor...' : 'Kayıt Ol'}
                    </button>

                    <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
                        <p style={{ color: '#666', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                            Zaten hesabınız var mı?
                        </p>
                        <Link
                            to="/login"
                            style={{
                                color: '#4facfe',
                                textDecoration: 'none',
                                fontSize: '0.9rem',
                                fontWeight: '500'
                            }}
                        >
                            Giriş Yap
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
}

