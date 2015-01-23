#### About

Sends e-mail with attached file via user specified SMTP server to the VirusTotal security service for the further scanning.

#### Configurations

The full path to the folder that is planed to be scaned can be specified in the *'SCAN_FOLDER'* constant inside **smtp_virustotal.py** main python script.

Two files that contains configuration parameters are existing:
* **email_configs.py** - for the configs of the SMTP server
* **email_credentials.py** - e-mail credentials

***NOTE***

If file **email_credentials.py** is not existing, please create it by copy-pasting code below and setting up your own credentials.
```
# e-mail
FROM_EMAIL = '<full-e-mail>'

# Common credentials
LOGIN = '<email-until-at>'
PASSWORD = '<password>'
```

#### Dependencies

* Python 2.7 is required - [download](http://www.python.org/download/)

#### Author

* Viktor Dmitriyev
