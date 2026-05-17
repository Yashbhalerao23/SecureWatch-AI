import axios from 'axios';

const AUTH_TOKEN_KEY = 'soc_auth_token';
const REFRESH_TOKEN_KEY = 'soc_refresh_token';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api/v1',
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true
});

api.interceptors.request.use((config) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem(AUTH_TOKEN_KEY) : null;
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const refreshToken = typeof window !== 'undefined' ? localStorage.getItem(REFRESH_TOKEN_KEY) : null;

    if (error.response?.status === 401 && refreshToken && !originalRequest?._retry) {
      originalRequest._retry = true;
      const refreshResponse = await axios.post(`${api.defaults.baseURL}/auth/token/refresh/`, {
        refresh: refreshToken
      });
      const accessToken = refreshResponse.data.access ?? refreshResponse.data.token;
      if (accessToken && typeof window !== 'undefined') {
        localStorage.setItem(AUTH_TOKEN_KEY, accessToken);
      }
      originalRequest.headers.Authorization = `Bearer ${accessToken}`;
      return api(originalRequest);
    }

    return Promise.reject(error);
  }
);

export interface ApiError {
  message: string;
}
