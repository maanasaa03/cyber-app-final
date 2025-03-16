import { View, Text, Image, TouchableOpacity, StyleSheet, TextInput } from 'react-native';
import React, { useState } from 'react';
import { useAuth } from './context/AuthContext';
import { useRouter } from 'expo-router';


const LoginScreen = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { onLogin, onRegister } = useAuth();
  const router = useRouter();

  const login = async () => {
    const result = await onLogin!(email, password);
    if (result && result.error) {
      alert(result.msg);
    }
    else{
      router.replace('/');
    }
  };

  const register = async () => {
    const result = await onRegister!(email, password);
    if (result && result.error) {
      alert(result.msg);
    } else {
      login();
    }
  };

  return (
    <View style={styles.container}>
      <Image 
        source={{ uri: 'https://www.allen.ac.in/apps2223/assets/images/login.jpg' }} 
        style={styles.image} 
      />
      <View style={styles.form}>
        <TextInput 
          style={styles.input} 
          placeholder='Email' 
          onChangeText={(text: string) => setEmail(text)} 
          value={email} 
          placeholderTextColor="#B08BBB"
        />
        <TextInput 
          style={styles.input} 
          placeholder='Password' 
          secureTextEntry={true} 
          onChangeText={(text: string) => setPassword(text)} 
          value={password} 
          placeholderTextColor="#B08BBB"
        />
        
        <TouchableOpacity style={styles.button} onPress={login}>
          <Text style={styles.buttonText}>Sign in</Text>
        </TouchableOpacity>
        
        <TouchableOpacity style={styles.button} onPress={register}>
          <Text style={styles.buttonText}>Create Account</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    backgroundColor: '#F2EAFB',
    paddingHorizontal: 20,
  },
  image: {
    width: 120, // Make the image a bit larger
    height: 120,
    borderRadius: 60, // Keep it circular with increased size
    marginBottom: 20,
    borderWidth: 2,
    borderColor: '#8A2BE2',
  },
  form: {
    gap: 10,
    width: '80%',
    alignItems: 'center',
  },
  input: {
    height: 44,
    width: '100%',
    borderWidth: 1,
    borderRadius: 8,
    padding: 10,
    backgroundColor: '#FFFFFF',
    borderColor: '#B08BBB',
    color: '#4B0082',
  },
  button: {
    width: '100%',
    paddingVertical: 12,
    backgroundColor: '#8A2BE2',
    borderRadius: 20, // Rounded corners for buttons
    alignItems: 'center',
    marginVertical: 5,
  },
  buttonText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
    fontSize: 16,
  },
});

export default LoginScreen;









