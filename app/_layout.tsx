import FontAwesome from '@expo/vector-icons/FontAwesome';
import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native';
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect } from 'react';
import { useColorScheme } from '@/components/useColorScheme';
import { AuthProvider, useAuth } from './context/AuthContext'; // Import AuthProvider and useAuth

export {
  ErrorBoundary,
} from 'expo-router';

export const unstable_settings = {
  initialRouteName: 'LoginScreen',
};


SplashScreen.preventAutoHideAsync();

export default function RootLayout() {
  const [loaded, error] = useFonts({
    SpaceMono: require('../assets/fonts/SpaceMono-Regular.ttf'),
    ...FontAwesome.font,
  });

  useEffect(() => {
    if (error) throw error;
  }, [error]);

  useEffect(() => {
    if (loaded) {
      SplashScreen.hideAsync();
    }
  }, [loaded]);

  if (!loaded) {
    return null; // Show nothing while fonts are loading
  }

  return (
    <AuthProvider>
      <RootLayoutNav />
    </AuthProvider>
  );
}

function RootLayoutNav() {
  const colorScheme = useColorScheme();
  const { authState } = useAuth(); // Access authentication state from AuthContext

  return (
    <ThemeProvider value={colorScheme === 'dark' ? DarkTheme : DefaultTheme}>
      <Stack>
        {!authState?.authenticated ? (
          <Stack.Screen name="LoginScreen" options={{ headerShown: false }} />
        ) : (
          <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        )}
        <Stack.Screen name="ArticleLinksScreen" options={{ title: 'Resources',headerStyle: {
      backgroundColor: '#9C4DCC' }}} />
        <Stack.Screen name="QuizScreen" options={{ title: 'Take Quiz!', headerStyle: {
      backgroundColor: '#9C4DCC' } }} />
        <Stack.Screen name="QuestionnaireScreen" options={{ title: 'Test Your Cyber Awareness!', headerStyle: {
      backgroundColor: '#9C4DCC' } }} />
        <Stack.Screen name="ChatbotScreen" options={{ title: 'Welcome to CHAI!',headerStyle: {
      backgroundColor: '#9C4DCC' }}} />
      <Stack.Screen name="BrowserScreen" options={{ title: 'Browser',headerStyle: {
      backgroundColor: '#9C4DCC' }}} />
      </Stack>
    </ThemeProvider>
  );
}
  


















