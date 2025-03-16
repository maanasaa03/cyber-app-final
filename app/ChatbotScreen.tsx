import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, ScrollView, ActivityIndicator, StyleSheet } from 'react-native';
import axios from 'axios';
import { useNavigation } from '@react-navigation/native';
import { router } from 'expo-router';

const BACKEND_URL = 'http://192.168.0.104:5000';

const ChatbotScreen = () => {
  const navigation = useNavigation();
  const [messages, setMessages] = useState<{ text: string; isUser: boolean }[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendMessage = async () => {
    if (!input.trim()) return;
  
    const newMessages = [...messages, { text: input, isUser: true }];
    setMessages(newMessages);
    setInput('');
    setLoading(true);
  
    try {
      const response = await fetch(`${BACKEND_URL}/chatbot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: input }),
      });
  
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
  
      const data = await response.json();
      setMessages([...newMessages, { text: data.reply, isUser: false }]);
    } catch (error) {
      console.error('Error sending message:', error);
      setMessages([...newMessages, { text: '⚠️ Error: Failed to fetch response.', isUser: false }]);
    } finally {
      setLoading(false);
    }
  };
  

  return (
    <View style={styles.container}>
      <ScrollView style={styles.chatContainer}>
        {messages.map((msg, index) => (
          <View key={index} style={[styles.message, msg.isUser ? styles.userMessage : styles.botMessage]}>
            <Text style={styles.messageText}>{msg.text}</Text>
          </View>
        ))}
        {loading && <ActivityIndicator size="small" color="#007AFF" />}
      </ScrollView>
      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder="Type a message..."
          value={input}
          onChangeText={setInput}
        />
        <TouchableOpacity style={styles.sendButton} onPress={sendMessage}>
          <Text style={styles.sendButtonText}>Send</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F2F2F2', padding: 10 },
  chatContainer: { flex: 1, marginBottom: 10 },
  message: { padding: 12, borderRadius: 18, marginVertical: 5, maxWidth: '75%' },
  userMessage: { backgroundColor: '#007AFF', alignSelf: 'flex-end' },
  botMessage: { backgroundColor: '#E5E5EA', alignSelf: 'flex-start' },
  messageText: { fontSize: 16, color: '#000' },
  inputContainer: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', borderRadius: 25, padding: 10 },
  input: { flex: 1, paddingHorizontal: 10, fontSize: 16 },
  sendButton: { backgroundColor: '#007AFF', borderRadius: 20, paddingVertical: 8, paddingHorizontal: 15 },
  sendButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
});

export default ChatbotScreen;





