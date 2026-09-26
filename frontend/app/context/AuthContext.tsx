import React, { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router';

interface AuthContextType {
    token: string | null;
    user: any | null;
    login: (token: string, user: any) => void;
    logout: () => void;
    isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [token, setToken] = useState<string | null>(localStorage.getItem('kadim_token'));
    const [user, setUser] = useState<any | null>(
        localStorage.getItem('kadim_user') ? JSON.parse(localStorage.getItem('kadim_user')!) : null
    );
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        // Check if token is expired (basic check)
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                if (payload.exp * 1000 < Date.now()) {
                    logout();
                }
            } catch (e) {
                logout();
            }
        }
    }, [location]);

    const login = (newToken: string, newUser: any) => {
        localStorage.setItem('kadim_token', newToken);
        localStorage.setItem('kadim_user', JSON.stringify(newUser));
        setToken(newToken);
        setUser(newUser);
        navigate('/');
    };

    const logout = () => {
        localStorage.removeItem('kadim_token');
        localStorage.removeItem('kadim_user');
        setToken(null);
        setUser(null);
        navigate('/login');
    };



    return (
        <AuthContext.Provider value={{ token, user, login, logout, isAuthenticated: !!token }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
