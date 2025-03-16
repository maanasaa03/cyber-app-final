import React, { useState } from 'react';
import { StyleSheet } from 'react-native';
import { View, Text, TouchableOpacity, ScrollView, Alert } from 'react-native';

const questions = [
    // Cyber Hygiene
    {
      question: "Which of these is a key aspect of cyber hygiene?",
      options: ["Using strong passwords", "Keeping devices always unlocked", "Ignoring security updates", "Connecting to any available Wi-Fi"],
      answer: "Using strong passwords",
      topic: "Cyber Hygiene",
    },
    {
      question: "What is the benefit of regular software updates?",
      options: ["Improves appearance", "Fixes security vulnerabilities", "Makes device slower", "Increases battery usage"],
      answer: "Fixes security vulnerabilities",
      topic: "Cyber Hygiene",
    },
    {
      question: "Why should you avoid using the same password for multiple accounts?",
      options: ["Easier to remember", "Increases security risk", "Improves account performance", "Required by law"],
      answer: "Increases security risk",
      topic: "Cyber Hygiene",
    },
  
    // Public Wi-Fi Safety
    {
      question: "What is the safest way to access personal data on public Wi-Fi?",
      options: ["Use HTTPS websites", "Turn off device security", "Connect to open networks", "Disable password protection"],
      answer: "Use HTTPS websites",
      topic: "Public Wi-Fi Safety",
    },
    {
      question: "Which tool can protect your data on public Wi-Fi?",
      options: ["VPN", "Bluetooth", "Cookies", "Data Saver Mode"],
      answer: "VPN",
      topic: "Public Wi-Fi Safety",
    },
    {
      question: "When using public Wi-Fi, which of these should you avoid?",
      options: ["Accessing banking apps", "Using HTTPS websites", "Updating your antivirus", "Disabling auto-connect"],
      answer: "Accessing banking apps",
      topic: "Public Wi-Fi Safety",
    },
  
    // Phishing
    {
      question: "Which of the following is a common sign of a phishing email?",
      options: ["Personalized greeting", "Misspellings and urgent tone", "Email from known address", "Contains only text"],
      answer: "Misspellings and urgent tone",
      topic: "Phishing",
    },
    {
      question: "What should you do if you suspect an email is phishing?",
      options: ["Reply to confirm details", "Click the link to check", "Report it as spam", "Ignore and keep it"],
      answer: "Report it as spam",
      topic: "Phishing",
    },
    {
      question: "Which action is most likely to protect you from phishing attacks?",
      options: ["Clicking unfamiliar links", "Ignoring email subjects", "Enabling multi-factor authentication", "Using common passwords"],
      answer: "Enabling multi-factor authentication",
      topic: "Phishing",
    },
  
    // Secure Browsing
    {
      question: "Which of these indicates a secure website?",
      options: ["HTTP in the URL", "HTTPS and a lock icon", "No address bar", "Red background"],
      answer: "HTTPS and a lock icon",
      topic: "Secure Browsing",
    },
    {
      question: "Why is it important to log out of websites on public computers?",
      options: ["Saves time", "Prevents unauthorized access", "Boosts computer speed", "Improves internet connection"],
      answer: "Prevents unauthorized access",
      topic: "Secure Browsing",
    },
    {
      question: "What should you do if your browser warns you about a suspicious website?",
      options: ["Ignore the warning", "Close the browser", "Proceed with caution", "Leave the site immediately"],
      answer: "Leave the site immediately",
      topic: "Secure Browsing",
    },
  
    // Authentication and Access Control
    {
      question: "What does multi-factor authentication (MFA) provide?",
      options: ["Improved battery life", "Stronger account security", "Faster access", "Reduced security"],
      answer: "Stronger account security",
      topic: "Authentication and Access Control",
    },
    {
      question: "Which is considered a weak password?",
      options: ["123456", "Pass@123", "SecureKey!45", "MyDog@Home4"],
      answer: "123456",
      topic: "Authentication and Access Control",
    },
    {
      question: "What should you do if you think someone has accessed your account without permission?",
      options: ["Ignore it", "Change your password immediately", "Delete the account", "Report it to friends"],
      answer: "Change your password immediately",
      topic: "Authentication and Access Control",
    },
  
    // Device Security and Encryption
    {
      question: "Why is it important to enable encryption on your device?",
      options: ["Improves device speed", "Prevents unauthorized access to data", "Saves battery life", "Increases storage"],
      answer: "Prevents unauthorized access to data",
      topic: "Device Security and Encryption",
    },
    {
      question: "What is a common way to protect mobile devices from theft?",
      options: ["Leaving it unlocked", "Enabling screen lock", "Sharing password", "Turning off GPS"],
      answer: "Enabling screen lock",
      topic: "Device Security and Encryption",
    },
    {
      question: "What should you do before disposing of an old device?",
      options: ["Clear storage", "Reset to factory settings", "Delete a few files", "Nothing"],
      answer: "Reset to factory settings",
      topic: "Device Security and Encryption",
    },
  
    // Data Privacy
    {
      question: "What information should you avoid sharing on social media?",
      options: ["Vacation plans", "Favorite movie", "Public news", "Hobby"],
      answer: "Vacation plans",
      topic: "Data Privacy",
    },
    {
      question: "Which is an example of personal data you should protect?",
      options: ["Name of favorite pet", "Credit card details", "Favorite color", "Nickname"],
      answer: "Credit card details",
      topic: "Data Privacy",
    },
    {
      question: "What is a safe way to store sensitive data?",
      options: ["Cloud storage without encryption", "Encrypted storage", "On a sticky note", "Shared with friends"],
      answer: "Encrypted storage",
      topic: "Data Privacy",
    },
  ];
  

export default function QuestionnaireScreen() {
  const [answers, setAnswers] = useState<string[]>(Array(questions.length).fill(''));
  const [score, setScore] = useState<number | null>(null);
  const [suggestedTopics, setSuggestedTopics] = useState<string[]>([]);

  const handleAnswerSelect = (questionIndex: number, option: string) => {
    const newAnswers = [...answers];
    newAnswers[questionIndex] = option;
    setAnswers(newAnswers);
  };

  const handleSubmit = () => {
    let correctAnswers = 0;
    const topicErrors: { [key: string]: number } = {};

    questions.forEach((question, index) => {
      if (answers[index] === question.answer) {
        correctAnswers++;
      } else {
        topicErrors[question.topic] = (topicErrors[question.topic] || 0) + 1;
      }
    });

    setScore(correctAnswers);

    const leastCorrectTopics = Object.keys(topicErrors)
      .filter(topic => topicErrors[topic] > 0)
      .sort((a, b) => topicErrors[b] - topicErrors[a]);

    setSuggestedTopics(leastCorrectTopics);

    Alert.alert(
      "Quiz Result",
      `Your Cyber Awareness Score: ${correctAnswers}/${questions.length}\n\nSuggested Topics to Review:\n${leastCorrectTopics.join(", ")}`,
      [{ text: "OK" }]
    );
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Cybersecurity Questionnaire</Text>

      {questions.map((question, index) => (
        <View key={index} style={styles.questionContainer}>
          <Text style={styles.questionText}>{question.question}</Text>
          {question.options.map((option, optionIndex) => (
            <TouchableOpacity
              key={optionIndex}
              style={[
                styles.optionButton,
                answers[index] === option && styles.selectedOption
              ]}
              onPress={() => handleAnswerSelect(index, option)}
            >
              <Text style={styles.optionText}>{option}</Text>
            </TouchableOpacity>
          ))}
        </View>
      ))}

      <TouchableOpacity onPress={handleSubmit} style={styles.submitButton}>
        <Text style={styles.submitButtonText}>Submit</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
    container: {
      flexGrow: 1,
      padding: 15,  // Reduced padding for smaller layout
      backgroundColor: '#F3E5F5', // light purple background for the screen
    },
    title: {
      fontSize: 20,  // Reduced font size for title
      fontWeight: 'bold',
      marginBottom: 15,  // Reduced bottom margin
      textAlign: 'center',
      color: '#4A148C', // deep purple
    },
    questionContainer: {
      marginBottom: 20,  // Reduced bottom margin
      padding: 12,  // Reduced padding
      backgroundColor: '#FFFFFF',
      borderRadius: 8,
      shadowColor: '#000',
      shadowOpacity: 0.15,  // Slightly reduced shadow opacity
      shadowOffset: { width: 0, height: 2 },
      shadowRadius: 3,  // Slightly reduced shadow radius
      elevation: 2,  // Reduced elevation for smaller shadow
    },
    questionText: {
      fontSize: 16,  // Reduced font size for question text
      fontWeight: 'bold',
      color: '#4A148C', // deep purple for question text
      marginBottom: 8,  // Reduced margin for spacing
    },
    optionButton: {
      backgroundColor: '#E1BEE7', // light purple background for options
      paddingVertical: 8,  // Reduced padding for smaller buttons
      paddingHorizontal: 12,  // Reduced horizontal padding
      borderRadius: 5,
      marginBottom: 6,  // Reduced margin between options
    },
    selectedOption: {
      backgroundColor: '#7B1FA2', // darker purple for selected option
    },
    optionText: {
      fontSize: 14,  // Reduced font size for option text
      color: '#4A148C', // deep purple text color for options
    },
    submitButton: {
      backgroundColor: '#4A148C', // deep purple button color
      paddingVertical: 12,  // Reduced padding for the submit button
      borderRadius: 8,
      alignItems: 'center',
      marginTop: 15,  // Reduced margin top
    },
    submitButtonText: {
      color: 'white',
      fontSize: 16,  // Reduced font size for submit button text
      fontWeight: 'bold',
    },
  });
  