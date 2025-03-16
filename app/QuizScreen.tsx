import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useRouter } from 'expo-router';
import { PieChart } from 'react-native-chart-kit';
import { Dimensions } from 'react-native';

const screenWidth = Dimensions.get('window').width;

const questions = [
  {
    question: 'What is Cyber Hygiene?',
    options: ['Best practices for online safety', 'A type of virus', 'A software update', 'A physical firewall'],
    correctOption: 0, // Index of the correct answer
    topic: 'Cyber Hygiene',
  },
  {
    question: 'What should you do when using public Wi-Fi?',
    options: ['Share passwords', 'Disable VPN', 'Avoid online banking', 'Leave the network open'],
    correctOption: 2,
    topic: 'Public Wi-Fi',
  },
  {
    question: 'What is phishing?',
    options: ['A type of email scam', 'A network protocol', 'A firewall configuration', 'A secure website'],
    correctOption: 0,
    topic: 'Phishing',
  },
  {
    question: 'What is multi-factor authentication?',
    options: ['A way to use multiple devices', 'A type of encryption', 'A method of verifying identity', 'A password recovery tool'],
    correctOption: 2,
    topic: 'Authentication',
  },
  {
    question: 'What is two-factor authentication (2FA)?',
    options: [
      'A method of authentication requiring two passwords',
      'A security measure that requires two forms of identification',
      'A type of encryption used for secure communication',
      'A method for securing passwords with a password manager',
    ],
    correctOption: 1, // Correct answer: "A security measure that requires two forms of identification"
    topic: 'Authentication',
  },
  {
    question: 'What does VPN stand for?',
    options: [
      'Virtual Private Network',
      'Verified Public Network',
      'Virtual Protected Node',
      'Verified Private Network',
    ],
    correctOption: 0, // Correct answer: "Virtual Private Network"
    topic: 'Networking',
  },
  {
    question: 'Which of the following is a secure password?',
    options: [
      '123456',
      'password',
      'myp@ssw0rd!',
      'qwerty',
    ],
    correctOption: 2, // Correct answer: "myp@ssw0rd!"
    topic: 'Passwords',
  },
  {
    question: 'What is malware?',
    options: [
      'A type of software designed to harm your device',
      'A type of hardware to improve security',
      'A network configuration tool',
      'A browser extension for privacy',
    ],
    correctOption: 0, // Correct answer: "A type of software designed to harm your device"
    topic: 'Cybersecurity',
  },
  {
    question: 'What is phishing?',
    options: [
      'A type of email scam that tricks users into revealing personal information',
      'A method of secure communication',
      'A network security protocol',
      'A method of software patching',
    ],
    correctOption: 0, // Correct answer: "A type of email scam"
    topic: 'Phishing',
  },
  {
    question: 'What does HTTPS stand for?',
    options: [
      'HyperText Transfer Protocol Secure',
      'Hyper Transfer Text Protocol Secure',
      'HyperText Transmission Protocol Secure',
      'HyperText Transfer Path Secure',
    ],
    correctOption: 0, // Correct answer: "HyperText Transfer Protocol Secure"
    topic: 'Networking',
  },
  {
    question: 'What is the purpose of a firewall?',
    options: [
      'To block unwanted network traffic',
      'To speed up network connections',
      'To provide encryption for data transmission',
      'To monitor internet usage on your device',
    ],
    correctOption: 0, // Correct answer: "To block unwanted network traffic"
    topic: 'Cybersecurity',
  },
  {
    question: 'What is encryption?',
    options: [
      'A process to make data unreadable without a key',
      'A method of storing data securely in databases',
      'A way of improving password strength',
      'A technique for blocking malicious websites',
    ],
    correctOption: 0, // Correct answer: "A process to make data unreadable without a key"
    topic: 'Cybersecurity',
  },
  {
    question: 'Which of the following is a sign that your device may have been infected with malware?',
    options: [
      'Your device runs faster than usual',
      'Your device slows down or crashes frequently',
      'Your device starts using less battery',
      'Your device starts behaving more efficiently',
    ],
    correctOption: 1, // Correct answer: "Your device slows down or crashes frequently"
    topic: 'Malware',
  },
];

const topicColors = ['#8B4CE4', '#CC6CE7', '#6D8BE6', '#7A3EB1','#FF6347','#90BE6D','#FFA500','#D32F2F']; // Unique colors for each topic

export default function QuizScreen() {
  const router = useRouter();
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>(Array(questions.length).fill(-1)); // Store selected answers
  const [score, setScore] = useState<number | null>(null); // To store the score after submission

  // Function to handle option selection
  const handleSelectOption = (questionIndex: number, optionIndex: number) => {
    const newAnswers = [...selectedAnswers];
    newAnswers[questionIndex] = optionIndex; // Update selected option
    setSelectedAnswers(newAnswers);
  };

  // Function to calculate the score
  const handleSubmitQuiz = () => {
    let totalScore = 0;
    selectedAnswers.forEach((answer, index) => {
      if (answer === questions[index].correctOption) {
        totalScore++;
      }
    });
    setScore(totalScore); // Set the score
  };

  // Calculate the correct/incorrect answers for each unique topic
  const topicsResult = questions.reduce<{ [key: string]: { correct: number, total: number } }>((acc, q, index) => {
    if (!acc[q.topic]) acc[q.topic] = { correct: 0, total: 0 };

    // Increase total questions for the topic
    acc[q.topic].total++;

    // If answer is correct, increase the correct count for that topic
    if (selectedAnswers[index] === q.correctOption) {
      acc[q.topic].correct++;
    }

    return acc;
  }, {});

  // Prepare data for the pie chart with unique topics
  const chartData = Object.keys(topicsResult).map((topic, index) => ({
    name: topic,
    population: topicsResult[topic].correct,
    color: topicColors[index],
    legendFontColor: topicColors[index],
    legendFontSize: 14,
  }));

  // Determine which topics to focus on based on score and avoid duplicates
  const topicsToLearnSet = new Set(
    questions.filter((q, index) => selectedAnswers[index] !== q.correctOption)
      .map(q => q.topic)
  );

  const topicsToLearn = Array.from(topicsToLearnSet);

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Quiz</Text>
      <ScrollView contentContainerStyle={styles.scrollViewContainer}>
        {score === null && (
          <>
            {questions.map((q, questionIndex) => (
              <View key={questionIndex} style={styles.questionContainer}>
                <Text style={styles.question}>{q.question}</Text>
                {q.options.map((option, optionIndex) => (
                  <TouchableOpacity
                    key={optionIndex}
                    style={[
                      styles.optionButton,
                      selectedAnswers[questionIndex] === optionIndex && styles.selectedOption, // Highlight selected option
                    ]}
                    onPress={() => handleSelectOption(questionIndex, optionIndex)}
                  >
                    <Text style={styles.optionText}>{option}</Text>
                  </TouchableOpacity>
                ))}
              </View>
            ))}

            <TouchableOpacity style={styles.submitButton} onPress={handleSubmitQuiz}>
              <Text style={styles.submitButtonText}>Submit Quiz</Text>
            </TouchableOpacity>
          </>
        )}

        {score !== null && (
          <View style={styles.scoreContainer}>
            <Text style={styles.scoreText}>You scored {score}/{questions.length}</Text>

            <Text style={styles.chartTitle}>Your Performance</Text>
            <PieChart
              data={chartData.map(({ name, population, color, legendFontColor, legendFontSize }) => ({
                name,
                population,
                color,
                legendFontColor,
                legendFontSize,
              }))}
              width={screenWidth - 40}
              height={220}
              chartConfig={{
                color: () => `rgba(0, 0, 0, 0.5)`,
              }}
              accessor="population"
              backgroundColor="transparent"
              paddingLeft="15"
              absolute
            />

            <View style={styles.topicsContainer}>
              <Text style={styles.topicsTitle}>Topics to Learn:</Text>
              {topicsToLearn.length > 0 ? (
                topicsToLearn.map((topic, index) => (
                  <Text key={index} style={styles.topicText}>{topic}</Text>
                ))
              ) : (
                <Text style={styles.noTopicsText}>Great job! You got all the topics right.</Text>
              )}
            </View>

            <TouchableOpacity 
              style={styles.homeButton} 
              onPress={() => router.push('/(tabs)/two')} // Navigate back to home
            >
              <Text style={styles.homeButtonText}>Go Back Home</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#E7DDFF',
    padding: 20,
  },
  scrollViewContainer: {
    flexGrow: 1,
    justifyContent: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 10,
    textAlign: 'center',
    color: '#8A2BE2',
  },
  questionContainer: {
    marginBottom: 20,
  },
  question: {
    fontSize: 18,
    marginBottom: 10,
    color: '#333',
  },
  optionButton: {
    backgroundColor: '#CC6CE7',
    padding: 10,
    borderRadius: 5,
    marginVertical: 5,
  },
  selectedOption: {
    backgroundColor: '#8B4CE4', // Highlight selected option
  },
  optionText: {
    color: '#FFF',
    fontSize: 16,
  },
  submitButton: {
    backgroundColor: '#7A3EB1',
    padding: 15,
    borderRadius: 10,
    alignItems: 'center',
    marginTop: 20,
  },
  submitButtonText: {
    color: '#FFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  scoreContainer: {
    marginTop: 30,
    alignItems: 'center',
  },
  scoreText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#8A2BE2',
    marginBottom: 20,
  },
  chartTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#8A2BE2',
    marginBottom: 10,
    textAlign: 'center',
  },
  topicsContainer: {
    marginTop: 20,
    alignItems: 'center',
  },
  topicsTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#8A2BE2',
  },
  topicText: {
    fontSize: 14,
    color: '#333',
    marginTop: 5,
  },
  noTopicsText: {
    fontSize: 14,
    color: '#4CAF50',
    fontStyle: 'italic',
  },
  homeButton: {
    marginTop: 20,
    backgroundColor: '#7A3EB1',
    padding: 10,
    borderRadius: 5,
  },
  homeButtonText: {
    color: '#FFF',
    fontSize: 16,
  },
});







