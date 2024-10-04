from flask import Flask, session, redirect, request, jsonify
import openai
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from flask_cors import CORS  # Import CORS
import secrets
from google.oauth2.credentials import Credentials
import json
from openai import OpenAI
import openai
import base64
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load the OpenAI API key from a JSON file
def load_api_key(filepath="openaikey.json"):
    with open(filepath, "r") as file:
        data = json.load(file)
        return data.get("plyhealthprotokey")
# Function to extract action items using OpenAI GPT model
def comprehend_email_with_gpt(body):
    api_key = load_api_key()
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
      model="gpt-4o",
      messages = [
            {"role": "system", "content": "You are a helpful assistant assisting healthcare providers in responding to payer enrollment emails. You help by filtering, summarizing, and drafting responses to enrollment-related emails."},
            {
                "role": "user",
                "content": f"""
                - Filter the following emails for relevance to payer enrollment, insurance network applications, or enrollment status updates.
                - An email is relevant if it mentions "payer enrollment," "insurance network," "enrollment status," or similar phrases.
                - If an email is irrelevant (e.g., marketing emails, newsletters, spam), ignore it.
                - If none of the emails are relevant, explicitly say "No payer enrollment today!" or something of the same tone.
                - Once you identify relevant emails, summarize them using this format:
                - Identify the payer (The organization being enrolled into e.g., 'Aetna emailed you...')
                - Clearly state the action required (e.g., 'They are requesting information to complete your application')
                - List the specific pieces of information requested by the payer (e.g., 'Please provide the following details: Practice name, Practice address, Tax ID/NPI, etc.')
                - Politely ask me if I would like assistance in providing the requested information and drafting a response.
                
                Here are the emails:
                {body}
                """
            }
        ]
    )
    return response

def chat_with_gpt(messages):
    api_key = load_api_key()
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
      model="gpt-4o",
      messages = messages
    )
    return response

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Enable CORS for all routes
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:3000"])
# app.config['SESSION_COOKIE_SAMESITE'] = 'None'
# app.config['SESSION_COOKIE_SECURE'] = False 

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
API_KEY = 'your-openai-api-key'

openai.api_key = API_KEY

@app.route('/login')
def login():
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    flow.redirect_uri = 'http://127.0.0.1:5000/oauth2callback'
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    # Store the state in the session to verify the callback
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES, state=state)
    flow.redirect_uri = 'http://127.0.0.1:5000/oauth2callback'

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store the credentials in the session
    session['credentials'] = flow.credentials.to_json()
    print('credentials' in session)

    return redirect('http://127.0.0.1:3000')

@app.route('/check_login', methods=['GET'])
def check_login():
    if 'credentials' in session:
        return jsonify({"logged_in": True})
    return jsonify({"logged_in": False})

# Fetch emails from Gmail
@app.route('/check_emails', methods=['GET'])
def check_emails():
    creds_json = session.get('credentials')
    creds = Credentials.from_authorized_user_info(json.loads(creds_json))
    service = build('gmail', 'v1', credentials=creds)
    messages = service.users().messages().list(userId='me').execute().get('messages', [])


    relevant_emails = []
    for msg in messages:
        message = service.users().messages().get(userId='me', id=msg['id']).execute()
        text = service.users().messages().get(userId="me", id=message['id'],format='raw').execute()
        # Decode the raw message from base64
        msg_str = base64.urlsafe_b64decode(text['raw'].encode('ASCII'))

        # Parse the message using the email library
        mime_msg = email.message_from_bytes(msg_str)
        sender_email = mime_msg['From']
        email_subject = mime_msg['Subject']
        message_id = message['id']  # Get the messageId from Gmail API
        thread_id = message['threadId']
        # Walk through the parts to extract the body
        for part in mime_msg.walk():
            if part.get_content_type() == 'text/plain' and part.get_content_disposition() is None:
                body = part.get_payload(decode=True)  # Decode the message body
                body_text = body.decode()  # Convert from bytes to string
                relevant_emails.append(body_text)
    email_text = "\n".join(relevant_emails)
    print(email_text)
    # Summarize using openai
    response = comprehend_email_with_gpt(email_text)
    print(response.choices[0].message.content)
    formatted_response = response.choices[0].message.content
    formatted_response = formatted_response.replace('\n', '<br>')
    return jsonify({
        'summary': formatted_response,
        'sender_email': sender_email,
        'subject': email_subject,
        'message_id': message_id,  # Include messageId for replying
        'thread_id': thread_id  # Include threadId for replying
    })

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    messages = data['messages']
    # Create a structured prompt using the message history
    response = chat_with_gpt(messages)
    # Extract GPT's response
    formatted_response = response.choices[0].message.content
    formatted_response = formatted_response.replace('\n', '<br>')
    return jsonify({'message': formatted_response})

@app.route('/refine_email_body', methods=['POST'])
def refine_email_body():
    data = request.get_json()
    last_response = data['last_response']  # Get the last GPT response

    # Send the last response back to GPT to refine it into email body only
    prompt = f"""
    Here is a gpt response with an email it helped me draft inside of it. Please provide only the email body text without gpt response text:
    
    {last_response}
    
    Return just the email body text without additional words from gpt.
    """

    messages = [
            {"role": "system", "content": "You are an assistant that generates email responses."},
            {"role": "user", "content": prompt}
        ]
    response = chat_with_gpt(messages)

    refined_body = response.choices[0].message.content
    refined_body = refined_body.replace('\n', '<br>')
    # Return the refined email body
    return jsonify({'body': refined_body})

# Send email response
@app.route('/send_email', methods=['POST'])
def send_email():
    data = request.get_json()

    # Extract email details from request data
    to = data['to']
    subject = data['subject']
    body = data['body'].replace('<br>','\n')
    thread_id = data['threadId']  # Include the threadId of the original email
    message_id = data['messageId']

    # Retrieve credentials from the session
    creds_json = session.get('credentials')
    creds = Credentials.from_authorized_user_info(json.loads(creds_json))

    # Build the Gmail service
    service = build('gmail', 'v1', credentials=creds)

    # Create the reply email message
    message = MIMEMultipart()
    message['to'] = to
    message['subject'] = subject
    message['In-Reply-To'] = message_id  # Reply to the original message ID
    message['References'] = message_id  # Reference the original message ID

    # Add the body to the email
    text_part = MIMEText(body, 'plain')
    message.attach(text_part)

    # Encode the message in base64 and prepare it for the API request
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        # Send the email reply using Gmail API
        message = service.users().messages().send(
            userId='me',
            body={'raw': raw_message, 'threadId': thread_id}  # Include threadId to reply in the thread
        ).execute()

        # Archive the original email after replying
        service.users().messages().modify(
            userId='me',
            id=message_id,
            body={'removeLabelIds': ['INBOX']}  # This archives the email by removing it from the inbox
        ).execute()

        return jsonify({'status': 'Email sent successfully and original email archived!'})
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'status': 'Failed to send email', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)