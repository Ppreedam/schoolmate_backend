import ssl
# import base64
import smtplib
# import requests
# from dotenv import dotenv_values
from email.message import EmailMessage
from rest_framework.exceptions import PermissionDenied
# from msal import ConfidentialClientApplication

def send_otp_on_email(prd_setting, email, otp):

    subject = "Email veryfication - Schoolmate"
    # outlook_mail_status = prd_setting.outlook_mail_status

        # Customize the email content with the company name
    company_logo_url = "https://expedblobstorage.blo.core.windows.net/images/18a75a0b-9680-43f3-9676-5c4196f8b83b?se=2139-02-07T04%3A19%3A16Z&sp=r&sv=2023-11-03&sr=b&sig=LqEpnEJl0GtmMXHvlPpIIsWU7NY7WNRjPRSXLd%2BVpMo%3D"

    articles = f"""
        <img src="{company_logo_url}" alt="Logo" style="max-width: 100%; display: block; margin: auto; height: auto; max-height: 50px; max-width: 50px;"><br><br>

        <strong style="text-align: center;display: block; font-size: 25px;">Email Verification</strong>
        <br><br>

        <p style="text-align: center;font-size:16px;display: block;">Welcome to Schoolmate!</p>
        <br>

        <p style="margin: auto;text-align:center;font-size: 20px;display: block;width:50%;">Thank you for registering with us. To complete your sign-up process, please verify your email address.</p>

        <p style="margin: auto;text-align:center;font-size: 20px;display: block;width:50%;">Use the following 6-digit verification code to confirm your email:</p>

        <p style="text-align: center; font-size: 25px; font-family: arial; display: block;"><strong>{otp}</strong></p>

        <p style="margin: auto;text-align:center;font-size:20px;display: block;width:55%;">If you did not initiate this request, please ignore this email.</p>
        <br><br>

        <strong>Thanks!</strong><br>
        Schoolmate Team.
    """


    # if outlook_mail_status:
    #     res = outlook_mail_excutive_function(subject, articles, email)
    # else:
    res = gmail_mail_excutive_function(email, subject, articles)    
      
    if res:
      return f"OTP sent successfully to {email}!"
    else:
      return "Email not sent"
    

def gmail_mail_excutive_function(email, subject, articles):
    # Sender email credentials
    # email_sender = env_vars['email_sender_c']
    # email_password = env_vars['email_password_c']
    email_sender = "sk6201184579@gmail.com"
    email_password = "taxk vmur wcfi zotw"

    # Create the email message
    msg = EmailMessage()
    msg['From'] = f"Schoolmate <{email_sender}>"
    msg['To'] = email
    msg['Subject'] = subject

    # Add HTML content
    msg.add_alternative(articles, subtype='html')

    # Create a secure SSL context
    context = ssl.create_default_context()

    # Send the email using SMTP SSL
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.send_message(msg)
        return f"OTP sent successfully to {email}!"
    except Exception as e:
        return PermissionDenied(str(e), status=500)
