from dotenv import load_dotenv
import os
from twilio.rest import Client

load_dotenv()


def send_sms(message, recipient_num):
    client = Client(os.getenv('ACC_SID'), os.getenv('AUTH_TOKEN'))

    try:
        message = client.messages.create(
        from_=os.getenv('TWILIO_NUM'),
        body=message,
        to=recipient_num
        )
    except:
        pass

