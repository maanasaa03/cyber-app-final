import React, { useState } from 'react';
import { View, TextInput, TouchableOpacity, Text, Alert, StyleSheet } from 'react-native';
import WebView from 'react-native-webview';

const BrowserScreen = () => {
  const [url, setUrl] = useState('');
  const [finalUrl, setFinalUrl] = useState('');
  const [securityScore, setSecurityScore] = useState<number | null>(null);
  const [checklist, setChecklist] = useState<string[]>([]);
  const [fullAnalysis, setFullAnalysis] = useState<string | null>(null);

  const BACKEND_URL = 'http://192.168.0.104:5000';

  const handleGo = () => {
    const formattedUrl = url.startsWith('http') ? url : `https://${url}`;
    setFinalUrl(formattedUrl);
    analyzeWebsite(formattedUrl);
  };

  const analyzeWebsite = async (websiteUrl: string) => {
    try {
      const response = await fetch(`${BACKEND_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: websiteUrl }),
      });
  
      if (!response.ok) {
        throw new Error('Failed to analyze website');
      }
  
      // ✅ Fetch the correct field from the backend response
      const { securityScore, summaryChecklist, detailedReport } = await response.json();
  
      setSecurityScore(securityScore);
      setChecklist(summaryChecklist || []); // Ensure it's always an array
      setFullAnalysis(detailedReport);
  
      Alert.alert(
        '🔍 Website Security Analysis',
        `🛡️ Security Score: ${securityScore}/100\n\n✅ Checklist:\n${(summaryChecklist || []).join('\n')}`,
        [
          { text: 'OK' },
          {
            text: 'Show Detailed Report',
            onPress: () => Alert.alert('📋 Full Report', detailedReport || "No report available."),
          },
        ]
      );
    } catch (error) {
      console.error('Error analyzing website:', error);
      Alert.alert('Analysis Error', 'Failed to analyze website. Try again.');
    }
  };
  

  return (
    <View style={styles.container}>
      <View style={styles.searchContainer}>
        <TextInput
          style={styles.input}
          placeholder="Enter URL..."
          value={url}
          onChangeText={setUrl}
        />
        <TouchableOpacity style={styles.goButton} onPress={handleGo}>
          <Text style={styles.goButtonText}>Go</Text>
        </TouchableOpacity>
      </View>
      {finalUrl ? <WebView source={{ uri: finalUrl }} style={styles.webView} /> : null}
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F2F2F2', padding: 10 },
  searchContainer: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', borderRadius: 25, padding: 10 },
  input: { flex: 1, paddingHorizontal: 10, fontSize: 16 },
  goButton: { backgroundColor: '#007AFF', borderRadius: 20, paddingVertical: 8, paddingHorizontal: 15 },
  goButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
  webView: { flex: 1, marginTop: 10, borderRadius: 10, overflow: 'hidden' },
});

export default BrowserScreen;
