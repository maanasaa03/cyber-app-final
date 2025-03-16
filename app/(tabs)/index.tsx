import React, { useEffect, useState } from 'react';
import { View, Text, TouchableOpacity, ScrollView, StyleSheet } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useRouter } from 'expo-router';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useNavigation } from '@react-navigation/native';
import { MaterialIcons } from '@expo/vector-icons';

export default function HomeScreen() {
  const router = useRouter();
  const [showAllModules, setShowAllModules] = useState(false);
  const [lastAccessedModule, setLastAccessedModule] = useState<string | null>(null);
  const [lastAccessedTitle, setLastAccessedTitle] = useState<string | null>(null);

  const modules = [
    { title: 'Introduction to Cyber Hygiene', lessons: '7 Lessons', moduleKey: 'introtocyber' },
    { title: 'Safe Use of Public Wi-Fi', lessons: '6 Lessons', moduleKey: 'publicwifi' },
    { title: 'Phishing', lessons: '8 Lessons', moduleKey: 'phishing' },
    { title: 'Secure Browsing', lessons: '8 Lessons', moduleKey: 'securebrowsing' },
    { title: 'Authentication and Access Control', lessons: '7 Lessons', moduleKey: 'authandaccess' },
    { title: 'Data Encryption', lessons: '4 Lessons', moduleKey: 'dataencrypt' },
  ];

  const getLastAccessedModule = async () => {
    try {
      const moduleKey = await AsyncStorage.getItem('lastAccessedModule');
      if (moduleKey) {
        const matchedModule = modules.find(module => module.moduleKey === moduleKey);
        if (matchedModule) {
          setLastAccessedModule(moduleKey);
          setLastAccessedTitle(matchedModule.title);
        }
      }
    } catch (e) {
      console.error('Failed to fetch the last accessed module:', e);
    }
  };

  useEffect(() => {
    getLastAccessedModule();
  }, []);

  const handleModulePress = async (module: { title: string | null; moduleKey: string }) => {
    try {
      await AsyncStorage.setItem('lastAccessedModule', module.moduleKey);
      setLastAccessedModule(module.moduleKey);
      setLastAccessedTitle(module.title);
    } catch (e) {
      console.error('Failed to save the last accessed module:', e);
    }

    router.push({
      pathname: '/ArticleLinksScreen',
      params: { module: module.moduleKey },
    });
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        <View style={styles.greetingContainer}>
          <Text style={styles.greetingText}>Hello there, 👋</Text>
          <Text style={styles.username}>User.</Text>
        </View>

        <View style={styles.quoteContainer}>
          <Text style={styles.quoteText}>
            "Cyber hygiene is not just a set of best practices; it’s a mindset that empowers individuals and organizations to protect their digital lives."
          </Text>
        </View>

        <TouchableOpacity 
          style={styles.questionnaireButton} 
          onPress={() => router.push('/QuestionnaireScreen')}
        >
          <Text style={styles.questionnaireButtonText}>Take Questionnaire</Text>
        </TouchableOpacity>

        <View style={styles.lessonContainer}>
          <Text style={styles.sectionTitle}>Where were we?</Text>
          {lastAccessedModule ? (
            <TouchableOpacity style={styles.lessonCard} onPress={() => handleModulePress({ title: lastAccessedTitle, moduleKey: lastAccessedModule })}>
              <Text style={styles.lessonTitle}>{lastAccessedTitle}</Text>
              <Text style={styles.lessonProgress}>Resume</Text>
            </TouchableOpacity>
          ) : (
            <Text style={styles.lessonTitle}>No module accessed yet</Text>
          )}
        </View>

        <View style={styles.modulesHeader}>
          <Text style={styles.sectionTitle}>Modules</Text>
          <TouchableOpacity onPress={() => setShowAllModules(!showAllModules)}>
            <Text style={styles.seeAll}>{showAllModules ? 'Show Less' : 'See All'}</Text>
          </TouchableOpacity>
        </View>

        {showAllModules ? (
          <View style={styles.gridContainer}>
            {modules.map((module, index) => (
              <TouchableOpacity
                key={index}
                style={styles.gridModuleCard}
                onPress={() => handleModulePress(module)}
              >
                <Text style={styles.moduleTitle}>{module.title}</Text>
                <Text style={styles.moduleLessons}>{module.lessons}</Text>
              </TouchableOpacity>
            ))}
          </View>
        ) : (
          <View style={styles.moduleList}>
            <ScrollView horizontal showsHorizontalScrollIndicator={false}>
              {modules.slice(0, 3).map((module, index) => (
                <TouchableOpacity
                  key={index}
                  style={styles.moduleCard}
                  onPress={() => handleModulePress(module)}
                >
                  <Text style={styles.moduleTitle}>{module.title}</Text>
                  <Text style={styles.moduleLessons}>{module.lessons}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>
          </View>
        )}

        <TouchableOpacity onPress={() => router.push('/QuizScreen')}> 
          <View style={styles.quizHeadingContainer}>
            <Text style={styles.quizHeading}>Ready to test your knowledge?</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity 
          style={styles.quizButton} 
          onPress={() => router.push('/QuizScreen')}
        >
          <Text style={styles.quizButtonText}>Start Quiz</Text>
        </TouchableOpacity>
      </ScrollView>
      <TouchableOpacity 
  style={styles.chatbotButton} 
  onPress={() => router.push('/ChatbotScreen')}
>
  <MaterialIcons name="chat" size={36} color="#fff" />
</TouchableOpacity>

<TouchableOpacity 
  style={styles.browserButton} 
  onPress={() => router.push('/BrowserScreen')}
>
  <MaterialIcons name="language" size={36} color="#fff" />
</TouchableOpacity>


    </SafeAreaView>
  );
}


const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#E6E0FF', // Light purple background for container
    padding: 20,
  },
  chatbotButton: {
    position: 'absolute',
    bottom: 30,
    right: 20, // Keep chatbot on the far right
    backgroundColor: '#5E3CB2',
    padding: 18,
    borderRadius: 40,
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 3.5,
  },
  
  browserButton: {
    position: 'absolute',
    bottom: 30,
    right: 100, // Increased spacing from chatbot
    backgroundColor: '#5E3CB2',
    padding: 18,
    borderRadius: 40,
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 3.5,
  },
  
  
  greetingContainer: {
    marginTop: 10, // Adjusted for spacing near the header
  },
  greetingText: {
    fontSize: 20,
    color: '#5E3CB2', // Dark purple for text
  },
  username: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#5E3CB2', // Dark purple for emphasis
    marginBottom: 15,
  },
  quoteContainer: {
    marginTop: 20,
    padding: 20,
    backgroundColor: '#B085F5', // Medium purple for the quote background
    borderRadius: 10,
  },
  quoteText: {
    fontSize: 16,
    fontStyle: 'italic',
    color: '#fff', // White text on purple background
  },
  lessonContainer: {
    marginTop: 30,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#5E3CB2', // Dark purple for section titles
    marginBottom: 10,
  },
  lessonCard: {
    backgroundColor: '#9C4DCC', // Rich purple for resume card
    padding: 25,
    borderRadius: 10,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  lessonTitle: {
    fontSize: 16,
    color: '#fff', // White text on purple card
  },
  lessonProgress: {
    fontSize: 16,
    color: '#fff',
  },
  modulesHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 30,
  },
  seeAll: {
    color: '#7A3EB1', // Slightly lighter purple for "See All" text
    fontSize: 16,
    fontWeight: 'bold',
  },
  moduleList: {
    marginTop: 10,
  },
  moduleCard: {
    backgroundColor: '#7A3EB1',
    padding: 25,
    borderRadius: 12,
    width: 180, // Reduced width to make them more square
    height: 180, // Set height to match width for a square shape
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 15,
  },
  
  moduleTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
  moduleLessons: {
    fontSize: 14,
    color: '#fff',
    marginTop: 10,
  },
  progressBar: {
    height: 6,
    backgroundColor: '#D1C4E9', // Light purple for progress bar background
    borderRadius: 3,
    overflow: 'hidden',
    marginTop: 10,
  },
  progressFill: {
    height: '100%',
    width: '0%', // Placeholder; update dynamically based on progress
    backgroundColor: '#4A148C', // Deep purple for progress fill
  },
  progressText: {
    fontSize: 12,
    color: '#fff',
    marginTop: 5,
  },
  // Grid View Styles
  gridContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginTop: 10,
  },
  gridModuleCard: {
    backgroundColor: '#7A3EB1',
    padding: 25,
    borderRadius: 12,
    width: '48%',
    marginBottom: 15,
  },
  quizButton: {
    backgroundColor: '#9C4DCC',
    paddingVertical: 12, // Adjusted padding to make it smaller
    paddingHorizontal: 40, // Centered horizontally
    borderRadius: 20, // Slightly rounded corners
    alignItems: 'center',
    marginTop: 20, // Adjusted top margin
  },
  quizButtonText: {
    color: '#FFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  quizHeadingContainer: {
    marginTop: 30, // Adjusted top margin for a gap from the modules
    marginBottom: 10, // Gap below the heading
  },
  quizHeading: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#5E3CB2', // Dark purple for heading
    marginLeft: 10, // Align the heading to the left with some padding
  },
  questionnaireButton: {
    backgroundColor: '#8E24AA',
    borderRadius: 12,
    paddingVertical: 10,
    paddingHorizontal: 20,
    marginHorizontal: 16,
    marginVertical: 20,
  },
  questionnaireButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
    textAlign: 'center',
  },
});