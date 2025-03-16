import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Alert,
} from 'react-native';
import * as Network from 'expo-network';
import * as Device from 'expo-device';
import * as Location from 'expo-location';
import * as LocalAuthentication from 'expo-local-authentication';
import { useCameraPermissions } from 'expo-camera';

export default function CyberScoreScreen() {
  const [cyberScore, setCyberScore] = useState(100);
  const [scoreLabel, setScoreLabel] = useState('Excellent');
  const [networkType, setNetworkType] = useState<Network.NetworkStateType | null>(null);
  const [wifiSecurity, setWifiSecurity] = useState('Unknown');
  const [permissionIssues, setPermissionIssues] = useState<string[]>([]);
  const [deviceSecurity, setDeviceSecurity] = useState(true);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    const requestPermissions = async () => {
      await requestCameraPermission();
      await Location.requestForegroundPermissionsAsync();
    };

    requestPermissions();
    calculateCyberScore();
  }, []);

  const calculateCyberScore = async () => {
    let score = 100;
    let issues: string[] = [];

    // Network Security Check
    const networkInfo = await Network.getNetworkStateAsync();
    if (networkInfo.type && networkInfo.type !== Network.NetworkStateType.WIFI) {
      score -= 20;
      issues.push('Not connected to WiFi (may be less secure)');
    }
    setNetworkType(networkInfo.type || null);

    if (networkInfo.type === Network.NetworkStateType.WIFI) {
      setWifiSecurity('Secured');
    } else {
      setWifiSecurity('Not Applicable');
    }

    // Device Security Check
    if (Device.isRootedExperimentalAsync) {
      const isRooted = await Device.isRootedExperimentalAsync();
      if (isRooted) {
        score -= 30;
        issues.push('Device is rooted (security risk)');
        setDeviceSecurity(false);
      }
    }

    // Biometric Authentication Check
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    if (!isEnrolled) {
      score -= 10;
      issues.push('Biometric authentication not enabled');
    }
    setBiometricAvailable(hasHardware && isEnrolled);

    // Camera Permission Check
    if (cameraPermission?.status === 'granted') {
      score -= 10;
      issues.push('Camera permission granted');
    }

    // Location Permission Check
    const { status: locationStatus } = await Location.requestForegroundPermissionsAsync();
    if (locationStatus === 'granted') {
      score -= 10;
      issues.push('Location permission granted');
    }

    // Set score and label
    setPermissionIssues(issues);
    setCyberScore(score);
    if (score >= 80) setScoreLabel('Excellent');
    else if (score >= 60) setScoreLabel('Good');
    else if (score >= 40) setScoreLabel('Average');
    else setScoreLabel('Poor');
  };

  const toggleDetails = () => {
    setShowDetails(!showDetails);
  };

  const showExplanation = (category: string) => {
    const explanations: Record<string, string> = {
      'WiFi Security': 'WiFi encryption protects your data from being intercepted on public networks.',
      'Device Security': 'A rooted device is more vulnerable to malware and unauthorized access.',
      Permissions: 'Granting permissions like camera or location can expose sensitive data.',
    };
    Alert.alert(category, explanations[category] || 'No explanation available.');
  };

  return (
    <View style={styles.container}>
      <View style={styles.scoreContainer}>
        <View style={styles.titleContainer}>
          <Text style={styles.title}>Cyber Score</Text>
          <TouchableOpacity
            style={styles.infoButton}
            onPress={() =>
              Alert.alert(
                'What is Cyber Score?',
                'Your Cyber Score represents the security posture of your device. A higher score indicates better security. You can click on each individual parameter to learn what it means and how it impacts your security.'
              )
            }
          >
            <Text style={styles.infoIcon}>ℹ️</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.separator} />

        <View style={styles.score}>
          <Text style={styles.scoreText}>{cyberScore}</Text>
          <Text style={styles.labelText}>{scoreLabel}</Text>
        </View>

        {showDetails && (
          <View style={styles.infoContainer}>
            <TouchableOpacity onPress={() => showExplanation('WiFi Security')}>
              <Text style={[styles.info, networkType !== Network.NetworkStateType.WIFI && styles.issue]}>
                Network Type: {networkType ?? 'Unknown'}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => showExplanation('WiFi Security')}>
              <Text style={[styles.info, wifiSecurity === 'Not Applicable' ? null : styles.issue]}>
                WiFi Security: {wifiSecurity}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => showExplanation('Device Security')}>
              <Text style={[styles.info, !deviceSecurity && styles.issue]}>
                Device Security: {deviceSecurity ? 'Secure' : 'Rooted'}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => showExplanation('Permissions')}>
              <Text style={styles.info}>Permissions:</Text>
            </TouchableOpacity>
            {permissionIssues.length === 0 ? (
              <Text style={styles.info}>All permissions are safe</Text>
            ) : (
              permissionIssues.map((issue, index) => (
                <Text key={index} style={styles.issue}>
                  {issue}
                </Text>
              ))
            )}
          </View>
        )}

        <View style={styles.buttonContainer}>
          <TouchableOpacity style={styles.recalculateButton} onPress={calculateCyberScore}>
            <Text style={styles.buttonText}>Recalculate</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity style={styles.showMoreButton} onPress={toggleDetails}>
          <Text style={[styles.showMoreText, showDetails && styles.underlinedText]}>
            {showDetails ? 'Show Less' : 'Show More'}
          </Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
    backgroundColor: '#E7DDFF',
  },
  scoreContainer: {
    width: '90%',
    maxWidth: 350,
    padding: 20,
    backgroundColor: '#FFFFFF',
    borderRadius: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.1,
    shadowRadius: 8,
    elevation: 5,
    alignItems: 'center',
  },
  titleContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#8A2BE2',
  },
  infoButton: {
    marginLeft: 8,
    padding: 4,
  },
  infoIcon: {
    fontSize: 18,
    color: '#8A2BE2',
  },
  separator: {
    width: '80%',
    height: 1,
    backgroundColor: '#8A2BE2',
    marginVertical: 10,
  },
  score: {
    width: 120,
    height: 120,
    borderRadius: 60,
    backgroundColor: '#8A2BE2',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
  },
  scoreText: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#FFFFFF',
  },
  labelText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
    marginTop: 4,
  },
  infoContainer: {
    marginVertical: 16,
    width: '100%',
  },
  info: {
    fontSize: 16,
    color: '#333',
    marginVertical: 5,
    textAlign: 'center',
  },
  issue: {
    fontSize: 16,
    color: '#D32F2F',
    fontWeight: 'bold',
    textAlign: 'center',
  },
  buttonContainer: {
    marginTop: 20,
    alignItems: 'center',
  },
  recalculateButton: {
    backgroundColor: '#8A2BE2',
    paddingVertical: 12,
    paddingHorizontal: 40,
    borderRadius: 25,
  },
  buttonText: {
    fontSize: 16,
    color: '#FFFFFF',
    fontWeight: 'bold',
  },
  showMoreButton: {
    marginTop: 10,
    paddingVertical: 8,
    paddingHorizontal: 20,
    borderRadius: 25,
  },
  showMoreText: {
    fontSize: 14,
    color: '#8A2BE2',
    fontWeight: 'bold',
  },
  underlinedText: {
    textDecorationLine: 'underline',
  },
});
















