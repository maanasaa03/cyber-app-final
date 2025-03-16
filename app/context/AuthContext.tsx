import { createContext, useContext, useEffect, useState } from "react";
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';
import { useRouter } from 'expo-router';

interface AuthProps {
    authState?: { token: string | null; authenticated: boolean | null };
    onRegister: (email: string, password: string) => Promise<any>;
    onLogin: (email: string, password: string) => Promise<any>;
    onLogout?: () => Promise<any>;
}

const TOKEN_KEY = 'my-jwt';
export const API_URL = 'https://api.developbetterapps.com';
const AuthContext = createContext<AuthProps>({
    onRegister: function (email: string, password: string): Promise<any> {
        throw new Error("Function not implemented.");
    },
    onLogin: function (email: string, password: string): Promise<any> {
        throw new Error("Function not implemented.");
    }
});

export const useAuth = () => {
    return useContext(AuthContext);
}

export const AuthProvider = ({ children }: any) => {
    const [authState, setAuthState] = useState<{ token: string | null; authenticated: boolean | null }>({
        token: null,
        authenticated: null
    });
    const router = useRouter(); // Initialize router here

    useEffect(() => {
        const loadToken = async () => {
            const token = await SecureStore.getItemAsync(TOKEN_KEY);
            console.log("stored", token);

            if (token) {
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
                setAuthState({
                    token: token,
                    authenticated: true
                });
            }
        };
        loadToken();
    }, []);

    const register = async (email: string, password: string) => {
        try {
            return await axios.post(`${API_URL}/users`, { email, password });
        } catch (e) {
            return { error: true, msg: (e as any).response.data.msg };
        }
    };

    const login = async (email: string, password: string) => {
        try {
            const result = await axios.post(`${API_URL}/auth`, { email, password });
            console.log("~file: AuthContext.tsx:41 ~login ~result:", result);

            setAuthState({
                token: result.data.token,
                authenticated: true
            });

            axios.defaults.headers.common['Authorization'] = `Bearer ${result.data.token}`;
            await SecureStore.setItemAsync(TOKEN_KEY, result.data.token);

            return result;

        } catch (e) {
            return { error: true, msg: (e as any).response.data.msg };
        }
    };

    const logout = async () => {
        await SecureStore.deleteItemAsync(TOKEN_KEY);
        axios.defaults.headers.common['Authorization'] = '';

        setAuthState({
            token: null,
            authenticated: false
        });

        // Navigate to the login screen
        router.replace('/LoginScreen');
    };

    const value = {
        onRegister: register,
        onLogin: login,
        onLogout: logout,
        authState
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

