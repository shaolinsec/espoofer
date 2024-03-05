#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
import time, ssl, base64, re, sys

from io import StringIO

class MailSender(object):
	def __init__(self):
		self.mail_server =""
		self.rcpt_to = ""
		self.email_data = ""
		self.filename = None
		self.verbose = False
		self.email = None
		self.helo = ""
		self.mail_from = ""
		self.starttls = False

		self.client_socket = None
		self.tls_socket = None

	def set_param(self, mail_server, rcpt_to, email_data, helo, mail_from, ccemails=b'', bccemails=b'', verbose=False, toemails=b'', filename=None, starttls=False, mode = "server", username = None, password = None, auth_proto = "LOGIN"):
		self.mail_server = mail_server
		self.rcpt_to = rcpt_to
		self.filename = filename
		self.email_data = email_data
		self.ccemails = ccemails
		self.bccemails = bccemails
		self.verbose = verbose
		self.toemails = toemails
		self.helo = helo
		self.mail_from = mail_from
		self.starttls = starttls

		self.mode = mode
		self.username = username
		self.password = password
		self.auth_proto = auth_proto

	def establish_socket(self):
		client_socket = socket(AF_INET, SOCK_STREAM)
		if self.verbose:
			print("Connecting "+ str(self.mail_server))
		client_socket.connect(self.mail_server)
		self.print_recv_msg(client_socket)

		if self.starttls == True:
			client_socket.send(b"ehlo "+ self.helo +b"\r\n")
			self.print_send_msg("ehlo "+ self.helo.decode("utf-8")+"\r\n")
			self.print_recv_msg(client_socket)

			client_socket.send(b"starttls\r\n")
			self.print_send_msg("starttls\r\n") 
			self.print_recv_msg(client_socket)

			tls_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLS)
			self.tls_socket = tls_socket

		self.client_socket = client_socket

	def print_out_file(self, file_path):
	
		with open(file_path, 'r', encoding='utf-8') as file:
			html_content = file.read()
		
		encoded_html_content = html_content.encode('utf-8')
		
		return encoded_html_content

	def contains_smtp_error(self, response):
		return re.search(r'^[45]\d{2}', response) is not None

	def send_smtp_cmds(self, client_socket):
		
		client_socket.send(b"ehlo "+self.helo+b"\r\n")
		time.sleep(0.1)
		self.print_send_msg("ehlo "+ self.helo.decode("utf-8")+"\r\n") 
		recv_msg = self.print_recv_msg(client_socket)

		if self.mode == "client":
			if "LOGIN".lower() in recv_msg.lower() and self.auth_proto == "LOGIN":
				auth_username = b"AUTH LOGIN " + base64.b64encode(self.username) + b"\r\n"
				client_socket.send(auth_username)
				self.print_send_msg(auth_username.decode("utf-8"))
				self.print_recv_msg(client_socket)
		
				auth_pwd = base64.b64encode(self.password) + b"\r\n"
				client_socket.send(auth_pwd)
				self.print_send_msg(auth_pwd.decode("utf-8"))
				self.print_recv_msg(client_socket)
			else:
				auth_msg = b'AUTH PLAIN '+base64.b64encode(b'\x00'+ self.username+b'\x00'+self.password)+b'\r\n'
				client_socket.send(auth_msg)
				self.print_send_msg(auth_msg.decode("utf-8"))
				self.print_recv_msg(client_socket)

		client_socket.send(b'mail from: '+self.mail_from+b'\r\n')
		time.sleep(0.1)
		self.print_send_msg('mail from: '+self.mail_from.decode("utf-8")+'\r\n')
		self.print_recv_msg(client_socket)

		if self.toemails:
			client_socket.send(b"rcpt to: "+self.toemails+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.toemails.decode('utf-8')+"\r\n")
			self.print_recv_msg(client_socket)
		else:
			client_socket.send(b"rcpt to: "+self.rcpt_to+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.rcpt_to.decode('utf-8')+"\r\n")
			self.print_recv_msg(client_socket)

		if self.ccemails:
			client_socket.send(b"rcpt to: "+self.ccemails+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.ccemails.decode('utf-8')+"\r\n")
			self.print_recv_msg(client_socket)

		elif self.ccemails and self.bccemails:
			client_socket.send(b"rcpt to: "+self.ccemails+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.ccemails.decode('utf-8')+"\r\n")

			self.print_recv_msg(client_socket)
			client_socket.send(b"rcpt to: "+self.bccemails+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.bccemails.decode('utf-8')+"\r\n")
			self.print_recv_msg(client_socket)

		elif self.bccemails:
			client_socket.send(b"rcpt to: "+self.bccemails+b"\r\n")
			time.sleep(0.1)
			self.print_send_msg("rcpt to: "+self.bccemails.decode('utf-8')+"\r\n")
			self.print_recv_msg(client_socket)
		

		client_socket.send(b"data\r\n")
		time.sleep(0.1)
		self.print_send_msg("data\r\n")
		self.print_recv_msg(client_socket)

		if self.filename:
			new_filename = self.print_out_file(self.filename)
			client_socket.send(self.email_data+b"\r\n"+new_filename+b"\r\n.\r\n")
			time.sleep(0.1)
			new_filename_str = new_filename.decode("utf-8") if isinstance(new_filename, bytes) else new_filename
			email_data_str = self.email_data.decode("utf-8") if isinstance(self.email_data, bytes) else self.email_data
			self.print_send_msg(email_data_str + "\r\n" + new_filename_str + "\r\n.\r\n")
			self.print_recv_msg(client_socket)
		else:
			client_socket.send(self.email_data+b"\r\n.\r\n")
			time.sleep(0.1)
			self.print_send_msg(self.email_data.decode("utf-8")+"\r\n.\r\n")
			self.print_recv_msg(client_socket)

	def send_quit_cmd(self, client_socket):
		client_socket.send(b"quit\r\n")
		self.print_send_msg( "quit\r\n")
		self.print_recv_msg(client_socket)

	def close_socket(self):
		if self.tls_socket != None:
			self.tls_socket.close()
		if self.client_socket != None:
			self.client_socket.close()

	def read_line(self, sock):
		buff = StringIO()
		while True:
			data = (sock.recv(1)).decode("utf-8")
			buff.write(data)
			if '\n' in data: break
		return buff.getvalue().splitlines()[0]

	def print_send_msg(self, msg):
		if self.verbose:
			print("<<< " + msg)

	def print_recv_msg(self, client_socket):
		if self.verbose:
			print("\033[91m"+">>> ", end='')
		time.sleep(1)

		timeout = time.time()

		msg = ""
		while True:
			line  = self.read_line(client_socket)
			msg += line
			if self.contains_smtp_error(msg):
				sys.exit("Message failed to send: ", msg)
			if self.verbose:
				print(line) 
			if "-" not in line:
				break
			else:
				if len(line) > 5 and "-" not in line[:5]:
					break
			time.sleep(0.1)
		if self.verbose:
			print("\033[0m")
		return msg

	def send_email(self):
		self.establish_socket()
		try:
			if self.starttls == True:
				self.send_smtp_cmds(self.tls_socket)
				self.send_quit_cmd(self.tls_socket)
			else:
				self.send_smtp_cmds(self.client_socket)
				self.send_quit_cmd(self.client_socket)
			self.close_socket()
		except Exception as e:
			import traceback
			traceback.print_exc()	

	def __del__(self):
		self.close_socket()
