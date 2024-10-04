import './App.css';
import axios from 'axios';
// src/App.js
import React, { useState, useEffect } from 'react';
import { checkEmails, sendEmail} from './services/api'; // Backend API functions
axios.defaults.withCredentials = true;

function LoginComponent() {
  const handleLogin = () => {
    // Redirect to the Flask /login route
    window.location.href = 'http://127.0.0.1:5000/login';
  };

  return (
    <div>
      <h2>Login</h2>
      <button onClick={handleLogin} className="bg-blue-500 text-white p-2 rounded">
        Login with Gmail
      </button>
    </div>
  );
}

function ChatComponent({ messages }) {
  return (
    <div className="chat-container bg-gray-100 p-4 rounded-lg max-w-2xl mx-auto">
      <div className="chat-messages space-y-4">
        {messages.map((message, index) => (
          <div
            key={index}
            className={`${
              message.role === 'assistant'
                ? 'bg-blue-100 text-left'
                : 'bg-green-100 text-right'
            } p-4 rounded-lg shadow-md`}
            dangerouslySetInnerHTML={{ __html: message.content }}  // Use innerHTML to render formatted content
          />
        ))}
      </div>
    </div>
  );
}

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [messages, setMessages] = useState([]);
  const [emailSummary, setEmailSummary] = useState('');
  const [userInput, setUserInput] = useState('');
  const [senderEmail, setSenderEmail] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [messageId, setMessageId] = useState('');  // Store the message ID for replying
  const [threadId, setThreadId] = useState('');

  // Check for login status
  useEffect(() => {
    // Check if user is logged in through backend session
    axios.get('http://127.0.0.1:5000/check_login')
      .then(response => {
        console.log('Login status response:', response.data);
        if (response.data.logged_in) {
          setIsLoggedIn(true);  // Set the user as logged in
        } else {
          setIsLoggedIn(false);  // Not logged in
        }
      })
      .catch(error => {
        console.error('Error checking login status:', error);
      });
  }, []);

  const handleCheckEmails = async () => {
    const emails = await checkEmails(); // Fetch emails from Gmail API via backend
    const { summary, sender_email, subject, message_id, thread_id } = emails;
    // Store the extracted values
    setEmailSummary(summary); // Get summarized emails
    setSenderEmail(sender_email);
    setEmailSubject(subject);
    setMessageId(message_id);  // Store message ID
    setThreadId(thread_id);  // Store thread ID
    setMessages((prev) => [...prev, { role: 'assistant', content: emails.summary }]);
  };

  // Function to get the refined email body from GPT
  const handleRefineEmailBody = async () => {
    // Get the last GPT message from the messages state
    const lastGPTMessage = messages.reverse().find((msg) => msg.role === 'assistant');
    if (!lastGPTMessage) {
      console.error('No GPT response found to refine');
      return;
    }

    try {
      // Send the last GPT message back to GPT for refinement
      const response = await axios.post('http://127.0.0.1:5000/refine_email_body', {
        last_response: lastGPTMessage.content
      });

      const refinedBody = response.data.body;
      setEmailBody(refinedBody);  // Store the refined email body

      setMessages((prevMessages) => [
        ...prevMessages,
        { role: 'assistant', content: `Refined Email Body: ${refinedBody}` }
      ]);
    } catch (error) {
      console.error('Error refining email body:', error);
    }
  };

  // Function to handle sending the crafted email
  const handleSendEmail = async () => {
    if (emailBody) {
      try {
        const response = await axios.post('http://127.0.0.1:5000/send_email', {
          to: senderEmail,  // Send to the extracted sender's email
          subject: `Re: ${emailSubject}`,  // Use the original subject and prepend "Re:"
          body: emailBody,
          messageId: messageId,  // Use the original email's messageId for reply
          threadId: threadId
        });
        console.log('Email sent:', response.data);
        setMessages((prevMessages) => [
          ...prevMessages,
          { role: 'assistant', content: 'Email sent successfully!' }
        ]);
      } catch (error) {
        console.error('Error sending email:', error);
        setMessages((prevMessages) => [
          ...prevMessages,
          { role: 'assistant', content: 'Failed to send email.' }
        ]);
      }
    }
  };

  // Function to handle user input submission
  const handleSendMessage = async () => {
    // Add the user's message to the chat history
    setMessages((prevMessages) => [
      ...prevMessages,
      { role: 'user', content: userInput }
    ]);

    // Send the user input and previous messages to the backend to get GPT's response
    try {
      const response = await axios.post('http://127.0.0.1:5000/chat', {
        messages: [...messages, { role: 'user', content: userInput }],
      });
      const gptResponse = response.data.message;

      // Add GPT's response to the chat history
      setMessages((prevMessages) => [
        ...prevMessages,
        { role: 'assistant', content: gptResponse }
      ]);

    } catch (error) {
      console.error('Error fetching GPT response:', error);
    }

    // Clear the input field after sending the message
    setUserInput('');
  };

  return (
    <div className="container mx-auto p-6">
      {!isLoggedIn ? (
        <LoginComponent onLogin={setIsLoggedIn} />
      ) : (
        <div>
          <ChatComponent messages={messages} />
          <div className="my-4">
            <input
              type="text"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              className="border p-2 w-full"
            />
            <button
              onClick={handleSendMessage}
              className="bg-green-500 text-white p-2 rounded mt-4"
            >
              Send Message
            </button>
          </div>
          <div className="my-4">
            <button
              onClick={handleCheckEmails}
              className="bg-blue-500 text-white p-2 rounded"
            >
              Check Emails
            </button>
          </div>
          <button onClick={handleRefineEmailBody} className="bg-yellow-500 text-white p-2 rounded mt-4">
            Refine Email Body
          </button>
          {emailBody && (
            <button onClick={handleSendEmail} className="bg-green-500 text-white p-2 rounded mt-4">
              Send Email
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
