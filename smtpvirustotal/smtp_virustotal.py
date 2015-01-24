# coding: utf-8
#!/usr/bin/env python

__author__     = "Viktor Dmitriyev"
__copyright__ = "Copyright 2015, Viktor Dmitriyev"
__credits__ = ["Viktor Dmitriyev"]
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "-"
__email__     = ""
__status__     = "Test"
__date__    = "23.01.2015"
__description__ = "Script send files as an attachment to the VirusTotal."


# SCAN_FOLDER = 'd:\\Distr\\_misc\\_Misc\\test\\'
SCAN_FOLDER = 'd:\\Distr\\_misc\\Images'


import smtplib
import Queue
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.Utils import formatdate
import threading

# importing configs
import email_configs as configs
import email_credentials as creadentials

# helper
from folder_iterator import FolderIterator

class VirusTotalAttachmentSender(threading.Thread):

    def __init__(self, resource, q):
        '''
            Method that initate variables

            (str, Queue) -> Note

            As the paraments method accepts
        '''

        threading.Thread.__init__(self)

        self.resource = resource
        self.q = q
        #print '[i] resource %s' % resource

    def form_email_with_attachment(self, filename):
        '''
            Forms e-mail with attachment and returns it.

            (str) -> str
        '''

        msg = MIMEMultipart()

        msg['Subject'] = 'SCAN'
        msg['From'] = creadentials.FROM_EMAIL
        msg['To'] = configs.TO_EMAIL
        msg['Date'] = formatdate()

        # Open the file to scan in binary mode
        fp = open(filename, 'rb')
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(fp.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment; filename="' + filename + '"')
        fp.close()
        msg.attach(attachment)
        print '[i] email with attachment was formed'

        return msg


    def send_attachment(self):
        '''
            Send the email via your own SMTP server.

            None -> None
        '''

        msg = self.form_email_with_attachment(self.resource)

        try:
            s = smtplib.SMTP(configs.SMTP_SERVER, configs.SMTP_PORT)
            print '[i] connected to the smtp'
            s.ehlo()
            s.starttls()
            #print '[i] ttls started'
            s.login(creadentials.LOGIN, creadentials.PASSWORD)
            #print '[i] login done'
            s.sendmail(creadentials.FROM_EMAIL, configs.TO_EMAIL, msg.as_string())
            print '[i] e-mail sent'
            s.quit()
            self.q.put([self.resource, "e-mail sent"])
        except Exception, e:
            print '[e] Error: unable to send email'
            print '[e] Exception: %s' % str(e)
            self.q.put([self.resource, '[e] Exception: %s' % str(e)])

    def run(self):
        '''
            Run method that send speficied attachment
        '''
        self.send_attachment()

class SenderProcessor:

    def files_to_scan(self, root_folder):
        '''
            Itereation particular
            (str) -> (list)
        '''
        f_iterator = FolderIterator()
        print '[i] Following folder will be processed %s \n' % root_folder
        folders = f_iterator.get_all_files(root_folder)

        _files_path = list()
        for folder in folders:
            for _file in folders[folder]:
                tmp_path = folder + "\\" + _file
                _files_path.append(tmp_path)

        return _files_path

    def process(self):
        '''
            Processing files taht should be send via e-mail to the VirusTotal service.
        '''
        q = Queue.Queue()
        threads = []

        files = self.files_to_scan(SCAN_FOLDER)

        # iterating through files list, form e-mail with attachmetn, send
        for resource in files:
            print resource
            thread = VirusTotalAttachmentSender(resource, q)
            threads.append(thread)
            thread.daemon = True
            thread.start()

        # waiting for all threads to be completed
        for thread in threads:
            while thread.is_alive():
                try:
                    thread.join(0.1)
                except KeyboardInterrupt, e:
                    print '[e] Exception: %s' % str(e)

        # forming report as and "txt" file
        f_report = open('virustotal-email-report.txt', 'a')
        while not q.empty():
            resource, msg = q.get()
            f_report.write("=== %s === \n" % (resource, ))
            f_report.write("Msg: \t\t%s\n" % (msg, ))

def main():
    '''
        Running / processing everything.
    '''

    file_sender = SenderProcessor()
    file_sender.process()

if __name__ == "__main__":
    main()
