<div align="center">
  
  # dmarc-man
  
</div>

Python script to read your dmarc report inbox and send you summaries

#  Installation
Using pip for python3, first install the requirements
```
pip install -r requirements.txt
```
Then call the run.py script 
```
python -m dmarc_man.run
```

## .env file
Inside of the .env file, this is where you store all your user variables as follows:
```
USER_NAME={email/username to connect to email server to fetch emails}
PASSWORD={password to connect to email server to fetch emails}
SERVER={email server to fetch emails}
SEND_SERVER={email user to send emails using the above credentials}
DMARC_EMAIL={TO emails that recieve dmarc reports (can be multiple comma separated)}
WHITELISTED_EMAILS={FROM emails that send you dmarc reports (can be multiple comma separated)}
```

#  Troubleshooting
Send me an email, or open an issue if you need any help :)

# Purpose / My Motivation
I wanted to be able to be able to see the benefits of using DMARC and dmarc reporting tools to monitor my domains, without having to involve a 3rd party such as Dmarcian.
