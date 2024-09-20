from dotenv import load_dotenv
import os
from twilio.rest import Client

load_dotenv()

client = Client(os.getenv('ACC_SID'), os.getenv('AUTH_TOKEN'))

message = client.messages.create(
  from_=os.getenv('TWILIO_NUM'),
  body='Hi From Twilio!!',
  to='+917666275103'
)

print(message.sid)