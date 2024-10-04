// src/services/api.js
import axios from 'axios';

// Function to check emails from the Flask backend
export const checkEmails = async () => {
  try {
    const response = await axios.get('/check_emails');
    return response.data;
  } catch (error) {
    console.error("Error fetching emails:", error);
    throw error;
  }
};

// Function to send an email via the Flask backend
export const sendEmail = async (content, profile) => {
  try {
    const response = await axios.post('/send_email', { content, profile });
    return response.data;
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
};
