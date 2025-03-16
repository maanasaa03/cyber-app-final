import React, { useEffect, useState } from 'react';
import { View, Text, Button } from 'react-native';
import { useRouter } from 'expo-router';
import AsyncStorage from '@react-native-async-storage/async-storage';

export default function SettingsScreen() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    const fetchUserData = async () => {
      const storedUsername = await AsyncStorage.getItem('username');
      const storedPassword = await AsyncStorage.getItem('password');
      if (storedUsername) setUsername(storedUsername);
      if (storedPassword) setPassword(storedPassword);
    };

    fetchUserData();
  }, []);

  const handleLogout = async () => {
    // Clear user data from AsyncStorage
    await AsyncStorage.removeItem('isLoggedIn');
    await AsyncStorage.removeItem('username');
    await AsyncStorage.removeItem('password');
    // Use replace to navigate to the login screen and remove navigation history
    router.replace('/LoginScreen');
  };
  

  return (
    <View>
      <Text>Username: {username}</Text>
      <Text>Password: {password}</Text>
      <Button title="Logout" onPress={handleLogout} />
    </View>
  );
}

