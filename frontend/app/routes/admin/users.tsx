import { useState, useEffect } from 'react';
import {
    Users, RefreshCw, Trash2, Shield, Eye,
    CheckCircle, XCircle, AlertTriangle, Search,
    UserCheck, UserX, ChevronDown, Edit3, Key, X
} from 'lucide-react';
import { api } from '../../services/api';

interface User {
    id: string;
    username: string;
    role: string;
    is_active: boolean;
    created_at: string;
    last_login: string | null;
}

// Türkçe: API URL'i environment'dan al, yoksa relative path kullan
const AUTH_URL = import.meta.env.VITE_AUTH_URL || '/api/auth';

// Türkçe: Düzenleme Modal Bileşeni
const EditUserModal = ({
    user,
    onClose,
    onSave
}: {
    user: User;
    onClose: () => void;
    onSave: (userId: string, updates: { role?: string; is_active?: boolean }) => Promise<void>;
}) => {
    const [role, setRole] = useState(user.role);
    const [isActive, setIsActive] = useState(user.is_active);
    const [saving, setSaving] = useState(false);

    const handleSave = async () => {
        setSaving(true);
        await onSave(user.id, { role, is_active: isActive });
        setSaving(false);
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-md shadow-2xl">
                <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800">
                    <h3 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Edit3 className="w-5 h-5 text-emerald-400" />
                        Kullanıcı Düzenle
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="p-6 space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Kullanıcı Adı</label>
                        <div className="px-4 py-3 bg-slate-100 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white">
                            {user.username}
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Yetki</label>
                        <select
                            value={role}
                            onChange={(e) => setRole(e.target.value)}
                            className="w-full px-4 py-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white
                         focus:outline-none focus:border-emerald-500 transition-colors"
                        >
                            <option value="admin">Admin</option>
                            <option value="viewer">Viewer</option>
                        </select>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Durum</label>
                        <div className="flex gap-3">
                            <button
                                onClick={() => setIsActive(true)}
                                className={`flex-1 px-4 py-3 rounded-lg border transition-all duration-300 flex items-center justify-center gap-2
                           ${isActive
                                        ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                                        : 'bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-400 dark:hover:border-slate-600'}`}
                            >
                                <CheckCircle className="w-4 h-4" />
                                Aktif
                            </button>
                            <button
                                onClick={() => setIsActive(false)}
                                className={`flex-1 px-4 py-3 rounded-lg border transition-all duration-300 flex items-center justify-center gap-2
                           ${!isActive
                                        ? 'bg-amber-500/20 border-amber-500 text-amber-400'
                                        : 'bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-400 dark:hover:border-slate-600'}`}
                            >
                                <XCircle className="w-4 h-4" />
                                Pasif
                            </button>
                        </div>
                    </div>
                </div>

                <div className="flex gap-3 p-6 border-t border-slate-200 dark:border-slate-800">
                    <button
                        onClick={onClose}
                        className="flex-1 px-4 py-3 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 
                       rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                        İptal
                    </button>
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="flex-1 px-4 py-3 bg-emerald-500 text-white rounded-lg 
                       hover:bg-emerald-600 transition-colors disabled:opacity-50"
                    >
                        {saving ? 'Kaydediliyor...' : 'Kaydet'}
                    </button>
                </div>
            </div>
        </div>
    );
};

// Türkçe: Şifre Değiştirme Modal Bileşeni
const ChangePasswordModal = ({
    user,
    onClose,
    onSave
}: {
    user: User;
    onClose: () => void;
    onSave: (userId: string, newPassword: string) => Promise<boolean>;
}) => {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [saving, setSaving] = useState(false);

    const handleSave = async () => {
        setError('');

        if (newPassword.length < 6) {
            setError('Şifre en az 6 karakter olmalıdır');
            return;
        }

        if (newPassword !== confirmPassword) {
            setError('Şifreler uyuşmuyor');
            return;
        }

        setSaving(true);
        const success = await onSave(user.id, newPassword);
        setSaving(false);

        if (success) {
            onClose();
        }
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-md shadow-2xl">
                <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800">
                    <h3 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Key className="w-5 h-5 text-amber-400" />
                        Şifre Değiştir
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="p-6 space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Kullanıcı</label>
                        <div className="px-4 py-3 bg-slate-100 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white">
                            {user.username}
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Yeni Şifre</label>
                        <input
                            type="password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            placeholder="En az 6 karakter"
                            className="w-full px-4 py-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white
                         placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition-colors"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">Şifre Tekrar</label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="Şifreyi tekrar girin"
                            className="w-full px-4 py-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white
                         placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition-colors"
                        />
                    </div>

                    {error && (
                        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}
                </div>

                <div className="flex gap-3 p-6 border-t border-slate-200 dark:border-slate-800">
                    <button
                        onClick={onClose}
                        className="flex-1 px-4 py-3 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 
                       rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                        İptal
                    </button>
                    <button
                        onClick={handleSave}
                        disabled={saving || !newPassword || !confirmPassword}
                        className="flex-1 px-4 py-3 bg-amber-500 text-white rounded-lg 
                       hover:bg-amber-600 transition-colors disabled:opacity-50"
                    >
                        {saving ? 'Değiştiriliyor...' : 'Şifreyi Değiştir'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default function UsersAdmin() {
    const [users, setUsers] = useState<User[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
    const [updating, setUpdating] = useState<string | null>(null);
    const [editingUser, setEditingUser] = useState<User | null>(null);
    const [passwordChangeUser, setPasswordChangeUser] = useState<User | null>(null);

    const fetchUsers = async () => {
        setLoading(true);
        setError('');
        try {
            const data = await api.get<{ users: User[] }>(`${AUTH_URL}/users`);
            setUsers(data.users || []);
        } catch (err: any) {
            setError(err.message || 'Bir hata oluştu');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    const updateUser = async (userId: string, updates: { role?: string; is_active?: boolean }) => {
        setUpdating(userId);
        try {
            await api.put(`${AUTH_URL}/users/${userId}`, updates);
            await fetchUsers();
        } catch (err: any) {
            setError(err.message);
        } finally {
            setUpdating(null);
        }
    };

    const changePassword = async (userId: string, newPassword: string): Promise<boolean> => {
        try {
            await api.put(`${AUTH_URL}/users/${userId}/password`, { new_password: newPassword });
            return true;
        } catch (err: any) {
            setError(err.message || 'Şifre değiştirme hatası');
            return false;
        }
    };

    const deleteUser = async (userId: string) => {
        try {
            await api.delete(`${AUTH_URL}/users/${userId}`);
            setDeleteConfirm(null);
            await fetchUsers();
        } catch (err: any) {
            setError(err.message);
        }
    };

    const formatDate = (dateStr: string | null) => {
        if (!dateStr) return 'Hiç giriş yapmadı';
        return new Date(dateStr).toLocaleString('tr-TR');
    };

    const filteredUsers = users.filter(user =>
        user.username.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="p-6 max-w-7xl mx-auto">
            {/* Modals */}
            {editingUser && (
                <EditUserModal
                    user={editingUser}
                    onClose={() => setEditingUser(null)}
                    onSave={updateUser}
                />
            )}
            {passwordChangeUser && (
                <ChangePasswordModal
                    user={passwordChangeUser}
                    onClose={() => setPasswordChangeUser(null)}
                    onSave={changePassword}
                />
            )}

            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 rounded-xl border border-emerald-500/30">
                        <Users className="w-8 h-8 text-emerald-400" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-wide">Kullanıcı Yönetimi</h1>
                        <p className="text-slate-400 text-sm">Sistem kullanıcılarını yönetin</p>
                    </div>
                </div>
                <button
                    onClick={fetchUsers}
                    disabled={loading}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 
                     border border-slate-300 dark:border-slate-700 rounded-lg transition-all duration-300
                     text-slate-700 dark:text-slate-300 hover:text-emerald-600 dark:hover:text-emerald-400"
                >
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    <span>Yenile</span>
                </button>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-500/20 rounded-lg">
                            <Users className="w-5 h-5 text-blue-400" />
                        </div>
                        <div>
                            <p className="text-2xl font-bold text-slate-900 dark:text-white">{users.length}</p>
                            <p className="text-slate-400 text-sm">Toplam Kullanıcı</p>
                        </div>
                    </div>
                </div>
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-emerald-500/20 rounded-lg">
                            <UserCheck className="w-5 h-5 text-emerald-400" />
                        </div>
                        <div>
                            <p className="text-2xl font-bold text-slate-900 dark:text-white">{users.filter(u => u.is_active).length}</p>
                            <p className="text-slate-400 text-sm">Aktif Kullanıcı</p>
                        </div>
                    </div>
                </div>
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-amber-500/20 rounded-lg">
                            <UserX className="w-5 h-5 text-amber-400" />
                        </div>
                        <div>
                            <p className="text-2xl font-bold text-slate-900 dark:text-white">{users.filter(u => !u.is_active).length}</p>
                            <p className="text-slate-400 text-sm">Onay Bekleyen</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Search */}
            <div className="mb-6">
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                    <input
                        type="text"
                        placeholder="Kullanıcı ara..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full pl-10 pr-4 py-3 bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl
                       text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-emerald-500/50
                       transition-colors duration-300"
                    />
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    <span className="text-red-400">{error}</span>
                    <button onClick={() => setError('')} className="ml-auto text-red-400 hover:text-red-300">
                        <X className="w-4 h-4" />
                    </button>
                </div>
            )}

            {/* Users Table */}
            <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full">
                    <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800">
                            <th className="px-6 py-4 text-left text-sm font-semibold text-slate-400">Kullanıcı</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-slate-400">Yetki</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-slate-400">Durum</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-slate-400">Son Giriş</th>
                            <th className="px-6 py-4 text-right text-sm font-semibold text-slate-400">İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr>
                                <td colSpan={5} className="px-6 py-12 text-center text-slate-500 dark:text-slate-500">
                                    <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-2" />
                                    <span>Yükleniyor...</span>
                                </td>
                            </tr>
                        ) : filteredUsers.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                                    Kullanıcı bulunamadı
                                </td>
                            </tr>
                        ) : (
                            filteredUsers.map((user) => (
                                <tr key={user.id} className="border-b border-slate-200 dark:border-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                                    <td className="px-6 py-4">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-emerald-500 to-cyan-500 
                                      flex items-center justify-center text-white font-bold">
                                                {user.username.charAt(0).toUpperCase()}
                                            </div>
                                            <span className="text-slate-900 dark:text-white font-medium">{user.username}</span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className={`px-3 py-1 rounded-lg text-sm font-medium
                                     ${user.role === 'admin'
                                                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                                                : 'bg-slate-700/50 text-slate-300 border border-slate-600'}`}>
                                            {user.role === 'admin' ? 'Admin' : 'Viewer'}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className={`flex items-center gap-2 px-3 py-1 rounded-lg text-sm font-medium w-fit
                                     ${user.is_active
                                                ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                                                : 'bg-amber-500/10 border border-amber-500/30 text-amber-400'}`}>
                                            {user.is_active ? (
                                                <><CheckCircle className="w-4 h-4" /> Aktif</>
                                            ) : (
                                                <><XCircle className="w-4 h-4" /> Pasif</>
                                            )}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-slate-400 text-sm">
                                        {formatDate(user.last_login)}
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex items-center justify-end gap-2">
                                            <button
                                                onClick={() => setEditingUser(user)}
                                                className="p-2 text-slate-500 hover:text-emerald-400 hover:bg-emerald-500/10 
                                   rounded-lg transition-all duration-300"
                                                title="Düzenle"
                                            >
                                                <Edit3 className="w-5 h-5" />
                                            </button>
                                            <button
                                                onClick={() => setPasswordChangeUser(user)}
                                                className="p-2 text-slate-500 hover:text-amber-400 hover:bg-amber-500/10 
                                   rounded-lg transition-all duration-300"
                                                title="Şifre Değiştir"
                                            >
                                                <Key className="w-5 h-5" />
                                            </button>
                                            {deleteConfirm === user.id ? (
                                                <div className="flex items-center gap-1">
                                                    <button
                                                        onClick={() => deleteUser(user.id)}
                                                        className="px-2 py-1 bg-red-500/20 border border-red-500/30 text-red-400 
                                       rounded text-xs hover:bg-red-500/30 transition-colors"
                                                    >
                                                        Sil
                                                    </button>
                                                    <button
                                                        onClick={() => setDeleteConfirm(null)}
                                                        className="px-2 py-1 bg-slate-800 border border-slate-700 text-slate-400 
                                       rounded text-xs hover:bg-slate-700 transition-colors"
                                                    >
                                                        İptal
                                                    </button>
                                                </div>
                                            ) : (
                                                <button
                                                    onClick={() => setDeleteConfirm(user.id)}
                                                    className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 
                                     rounded-lg transition-all duration-300"
                                                    title="Sil"
                                                >
                                                    <Trash2 className="w-5 h-5" />
                                                </button>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            {/* Info Box */}
            <div className="mt-6 p-4 bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl">
                <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-emerald-400 mt-0.5" />
                    <div>
                        <h3 className="text-slate-900 dark:text-white font-medium mb-1">Kullanıcı Yönetimi Hakkında</h3>
                        <p className="text-slate-400 text-sm">
                            <span className="text-emerald-400">Düzenle</span> butonu ile yetki ve aktiflik değiştirebilir,
                            <span className="text-amber-400 ml-1">Şifre Değiştir</span> butonu ile kullanıcı şifresini sıfırlayabilirsiniz.
                            <span className="text-red-400 ml-1">Silme</span> işlemi geri alınamaz.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
