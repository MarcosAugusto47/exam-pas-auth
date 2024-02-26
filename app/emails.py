import requests
import json
from dotenv import load_dotenv
load_dotenv()
import os
import resend

# Set up the API key and endpoint
#api_key = os.environ.get('SENDINBLUE')
resend.api_key = os.environ.get('RESEND_API_KEY')
url = "https://api.sendinblue.com/v3/smtp/email"

def send_welcome_email(email):

    params1 = {
        #"sender": {"name": "Frederick | The Best App", "email": "youremail@yoursite.com"},
        "from": "noreply@pasvision.xyz",
        "to": [f"{email}"],
        "subject": "Bem-vindo a PAS Vision 📚",
        "html": "Olá, estudante!📝<br><br>Muito obrigado, por se juntar à PAS Vision, sua ferramenta de analytics para o Exame PAS UNB. 💻"
        "<br><br>✅ Probabilidade de aprovação.<br>✅ Estatísticas de desempenho dos candidatos aprovados.<br>✅ Explore cenários."
        "<br><br>Não hesite em entrar em contato se tiver alguma dúvida ou feedback."            
        "<br><br>Até breve,<br><br>PAS Vision Group,<br>PAS Vision App",
    }

    params2 = {
        #"sender": {"name": "The Best App", "email": "contact@callmefred.com"},
        "from": "noreply@pasvision.xyz",
        "to": [f"marcos_augusto_business@proton.me"],
        "subject": "🤘 NEW USER SIGNUP",
        "html": f"A new user has just signed up.<br><br>📧 User's Email: {email}",
    }

    #headers = {"api-key": api_key, "Content-Type": "application/json"}

    #response1 = requests.post(url, headers=headers, data=json.dumps(params1))
    response1 = resend.Emails.send(params1)

    #response2 = requests.post(url, headers=headers, data=json.dumps(params2))
    response2 = resend.Emails.send(params2)
    
    response_status1 = resend.Emails.get(response1['id'])['last_event']
    response_status2 = resend.Emails.get(response2['id'])['last_event']

    if response_status1 == "delivered":

        print("Email 1 sent successfully!")

    else:
        print("An error occurred: ", response_status1)

    if response_status2 == "delivered":

        print("Email 2 sent successfully!")

    else:
        print("An error occurred: ", response_status2)


    return "Emails sent successfully!"


def send_mail_pw_reset(recipient, reset_url):

    #headers = {"api-key": api_key, "Content-Type": "application/json"}

    params = {
        #"sender": {"name": "The Best App", "email": "youremail@yoursite.com"},
        "from": "noreply@pasvision.xyz",
        "to": [f"{recipient}"],
        "subject": "Password Reset Request",
        "html": f"Hi there!<br><br>You have requested to reset your password.<br><br>Please click on the following link to choose a new password: {reset_url}<br><br>If it wasn't you, please ignore this message.<br><br>Best,<br><br>PAS Vision Group,<br>PAS Vision App",
    }

    #response = requests.post(url, headers=headers, data=json.dumps(params))
    response = resend.Emails.send(params)

    response_status = resend.Emails.get(response['id'])['last_event']
    if response_status == "delivered":

        print("Reset email sent successfully!")

    else:
        print("An error occurred: ", response_status)


# def send_mail_verification(recipient, verification_url):
#     headers = {"api-key": api_key, "Content-Type": "application/json"}

#     params = {
#         "sender": {"name": "The Best App", "email": "youremail@yoursite.com"},
#         "to": [{"email": f"{recipient}"}],
#         "subject": "Email Verification Request",
#         "htmlContent": f"Hi there!<br><br>Please verify your email address for The Best App.<br><br>Click on the following link to verify: {verification_url}<br><br>If it wasn't you, please ignore this message.<br><br>Best,<br><br>Frederick,<br>The Best App",
#     }

#     response = requests.post(url, headers=headers, data=json.dumps(params))

#     if response.status_code == 201:
#         print("Verification email sent successfully!")
#     else:
#         print("An error occurred: ", response.text)


def send_mail_verification(recipient, verification_url):
    #headers = {"api-key": api_key, "Content-Type": "application/json"}

    params = {
        "from": "noreply@pasvision.xyz",
        "to": [f"{recipient}"],
        "subject": "Email Verification Request",
        "html": f"Hi there!<br><br>Please verify your email address for PAS Vision App.<br><br>Click on the following link to verify: {verification_url}<br><br>If it wasn't you, please ignore this message.<br><br>Best,<br><br>PAS Vision Group,<br>PAS Vision App",
    }

    #response = requests.post(url, headers=headers, data=json.dumps(params))

    response = resend.Emails.send(params)

    response_status = resend.Emails.get(response['id'])['last_event']
    if response_status == "delivered":
        print("Verification email sent successfully!")
    else:
        print("An error occurred: ", response_status)