import { redirect } from "react-router";

const API_BASE = ''; // Relative path for proxy

class ApiService {
    private getToken(): string | null {
        if (typeof window === 'undefined') return null;
        return localStorage.getItem('kadim_token');
    }

    private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
        const token = this.getToken();
        const headers = new Headers(options.headers);

        if (token) {
            headers.set('Authorization', `Bearer ${token}`);
        }

        if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
            headers.set('Content-Type', 'application/json');
        }

        const config: RequestInit = {
            ...options,
            headers,
        };

        const response = await fetch(`${API_BASE}${endpoint}`, config);

        // Handle 401 Unauthorized
        if (response.status === 401) {
            // Clear storage
            localStorage.removeItem('kadim_token');
            localStorage.removeItem('kadim_user');

            // Redirect to login
            if (typeof window !== 'undefined') {
                window.location.href = '/login';
            }
            throw new Error('Oturum süresi doldu, lütfen tekrar giriş yapın.');
        }

        if (!response.ok) {
            let errorMessage = 'Bir hata oluştu';
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorData.message || errorData.detail || errorMessage;
            } catch (e) {
                // If JSON parse fails, use status text
                errorMessage = response.statusText;
            }
            throw new Error(errorMessage);
        }

        // Return empty object for 204 No Content
        if (response.status === 204) {
            return {} as T;
        }

        try {
            return await response.json();
        } catch (e) {
            // If response is not JSON (e.g. blob or text), return as is or handle appropriately
            // For now, assuming most API calls return JSON. 
            // If we expect text, we might need a different method or option.
            return {} as T;
        }
    }

    get<T>(endpoint: string, options?: RequestInit) {
        return this.request<T>(endpoint, { ...options, method: 'GET' });
    }

    post<T>(endpoint: string, body: any, options?: RequestInit) {
        return this.request<T>(endpoint, {
            ...options,
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    put<T>(endpoint: string, body: any, options?: RequestInit) {
        return this.request<T>(endpoint, {
            ...options,
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    delete<T>(endpoint: string, options?: RequestInit) {
        return this.request<T>(endpoint, { ...options, method: 'DELETE' });
    }

    upload<T>(endpoint: string, formData: FormData, options?: RequestInit) {
        return this.request<T>(endpoint, {
            ...options,
            method: 'POST',
            body: formData
        });
    }

    /**
     * SSE (Server-Sent Events) stream için fetch yapılandırması
     * Token otomatik olarak eklenir
     */
    streamSSE(endpoint: string, signal?: AbortSignal): Promise<Response> {
        const token = this.getToken();
        const headers: HeadersInit = {
            'Accept': 'text/event-stream',
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        return fetch(`${API_BASE}${endpoint}`, {
            method: 'GET',
            headers,
            signal
        });
    }
}

export const api = new ApiService();
