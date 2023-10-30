#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# AD LDAP Fonctions

import sys
from ldap3 import Connection, Server, NTLM, ALL
from threading import *
import socket
import dns.resolver

global online_computers
online_computers = []

def scan(computer, domain, dns_server, port, debug, debugmax):
	# Trying to resolve IP address of the host

	screenLock = Semaphore(value=1)
	answer = ''

	# Create a socket object for TCP IP connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(3)

	try:
	# resolve dns to ip address
		resolver = dns.resolver.Resolver(configure=False)
		resolver.nameservers = [dns_server]
		current_computer     = computer + "." + domain
		# trying dns resolution in TCP and if it fails, we try in UDP
		answer = resolver.resolve(current_computer, "A", tcp=True)
		if len(answer) == 0:
			answer = resolver.resolve(current_computer, "A", tcp=False)
			if len(answer) == 0:
				print("DNS resolution for "+str(current_computer) + " has failed.")
				sys.exit(1)
		else:
			answer = str(answer[0])

        # Set IP and Port to connect
		s.connect((answer, port))

		# Display debug infos
		if debugmax:
			screenLock.acquire()
			print ('Scanning ', answer , 'on port',  port)
			print("Port",port, "is open")
        
		# Closing the socket
		s.close()

        # Call the summary fonction to add the computer to the online_computers list
		summary(computer)
		
	# If it fails
	except socket.timeout:
		if debugmax:
			print("TCP 445 Connection Timeout")
	except:
		# Display offline computer
		if debugmax:
			screenLock.acquire()
			print ('Scanning ', answer , 'on port',  port)
			print("Port",port,"is closed")

    # Free the semaphore object and close the socket
	finally:
		screenLock.release()
		s.close()
		return

# Création d'une boucle pour créer un thread par machine
def SmbScan(computers_list, domain, dns_server, port, debug, debugmax):
	# Définition du tableau de threads
	threads = []

	# Pour chaque port entre min et max
	for computer in computers_list:

		# Création d'un thread faisant appel à la fonciton scan avec l'ip et le port en arguments
		t = Thread(target=scan, args=(computer, domain, dns_server, port, debug, debugmax))

		# Lancement de l'exécution du thread
		t.start()

		# Ajout du thread au tableau des threads
		threads.append(t)
    
	# On attend que tous les threads se terminent puis on quitte la boucle
	[t.join() for t in threads]
	return



# Fonction d'ajout des ordinateurs en ligne dans un tableau
def summary(computer):
	online_computers.append(computer)
	return

def Get_online_computers():
	return online_computers
	

def Connect_AD_ldap(address, domain, username, passLdap, debug, debugmax):
    # try to connect to ldap

	if debug is True or debugmax is True:
		print("Testing LDAP connection...")

	connectionFailed = False
	serv 			 = Server(address, get_info=ALL, use_ssl=True, connect_timeout=15)
	ldapConnection   = Connection(serv, user=f"{domain}\\{username}", password=passLdap, authentication=NTLM)

	try:
		if not ldapConnection.bind():
			print("Error : Could not connect to ldap : bad credentials")
			sys.exit(1)
		if debug is True or debugmax is True:
			print("LDAP connection successfull with SSL encryption.")
	except:
		print("Error : Could not connect to ldap with SSL encryption. Trying without SSL encryption...")
		connectionFailed = True

	if True == connectionFailed:
		try:
			serv = Server(address, get_info=ALL, connect_timeout=15)
			ldapConnection = Connection(serv, user=f"{domain}\\{username}", password=passLdap, authentication=NTLM)
			if not ldapConnection.bind():
				print("Error : Could not connect to ldap : bad credentials")
				sys.exit(1)
			if debug is True or debugmax is True:
				print("LDAP connection successfull without encryption.")
		except:
			print("Error : Could not connect to ldap.")
			if debug is True or debugmax is True:
				import traceback
				traceback.print_exc()
			sys.exit(1)
	
	# Create the baseDN
	baseDN = serv.info.other['defaultNamingContext'][0]
	
	return ldapConnection,baseDN

def Get_AD_users(ldapConnection, baseDN, just_user, debug, debugmax):
	# catch all users in domain or just the specified one
	if just_user is not None :
		searchFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName="+str(just_user)+"))"
		print("Target user will be only " + str(just_user))
	else:
		searchFilter = "(&(objectCategory=person)(objectClass=user))"
	try:
		if debug is True or debugmax is True:
			print("[+] Retrieving user objects in LDAP directory...")
		ldap_users = []
		ldapConnection.search('%s' % (baseDN), searchFilter, attributes=['sAMAccountName', 'objectSID'],paged_size=1000)
		for i in range(len(ldapConnection.entries)):
			ldap_users.append(ldapConnection.entries[i])
		cookie = ldapConnection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
		while cookie:
			ldapConnection.search('%s' % (baseDN), searchFilter, attributes=['sAMAccountName', 'objectSID'],paged_size=1000,paged_cookie=cookie)
			cookie = ldapConnection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
			for i in range(len(ldapConnection.entries)):
				ldap_users.append(ldapConnection.entries[i])
		
		if debug is True or debugmax is True:
			print("Converting ObjectSID in string SID...")
		
		ad_users = []
		for user in ldap_users:
			try:
				ldap_username = str(user['sAMAccountName'])
				sid           = str(user['objectSID'])
				name_and_sid  = [ldap_username.strip(), sid]
				ad_users.append(name_and_sid)
			except:
				pass 
				# some users may not have samAccountName
		if debug is True or debugmax is True:
			print("Found about " + str( len(ldap_users) ) + " users in LDAP directory.")
	except:
		print("Error : Could not extract users from ldap.")
		if debug is True or debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)
	if len(ad_users) == 0:
		print("No user found in LDAP directory")
		sys.exit(1);
    
	return ad_users


def Get_AD_computers(ldapConnection, baseDN, just_computer, debug, debugmax):
    # catch all computers (enabled) in domain or just the specified one
	if debug is True or debugmax is True:
		print("[+] Retrieving computer objects in LDAP directory...")
	ad_computers = []
	ldap_computers = []
	if just_computer is not None :
		ad_computers.append(just_computer)
		print("Target computer will be only " + str(just_computer))
	else:
		try:
			# Filter on enabled computer only
			searchFilter = "(&(objectCategory=computer)(objectClass=computer)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
			search_base = baseDN
			ldapConnection.search(search_base, searchFilter, attributes=['cn'],paged_size=1000)

			for i in range(len(ldapConnection.entries)):
				ldap_computers.append(ldapConnection.entries[i])

			cookie = ldapConnection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
			while cookie:
				ldapConnection.search('%s' % (baseDN), searchFilter, attributes=['cn'],paged_size=1000,paged_cookie=cookie)
				cookie = ldapConnection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
				for i in range(len(ldapConnection.entries)):
					ldap_computers.append(ldapConnection.entries[i])

			for computer in ldap_computers:
				try:
					comp_name = str(computer['cn'])
					ad_computers.append(comp_name.strip())
				except:
					pass
			if debug is True or debugmax is True:
				print("Found about " + str( len(ad_computers) ) + " computers in LDAP directory.")
		except:
			print("Error : Could not extract computers from ldap.")
			if debug is True or debugmax is True:
				import traceback
				traceback.print_exc()
		
	return ad_computers
