""""
             ----------------------------------------
            | WINDOWS SECURITY CHECK - EXPERT SYSTEM |
             ----------------------------------------
Author: Sai Tarun Sathyan (SS4005)

"""""

# Library: windows_tools ; Author: NetInvent - Osiris De Jong
# Library: windows_apps ; Author: Tushar Goyal
# Library: pywin32/win32com ; default

# Note: Many print statements have been commented to make the output cleaner
# uncomment if you would like to see how it works

import win32com
import windowsapps
import winerror
import win32security
import windows_tools.antivirus
import windows_tools.updates
import windows_tools.users
import windows_tools.windows_firewall
from windows_tools.windows_firewall import *



def is_password_blank(username):
    """
    Used to check if the user has password setup
    """
    try:
        log = win32security.LogonUser(username, None, "",
                    win32security.LOGON32_LOGON_INTERACTIVE,
                    win32security.LOGON32_PROVIDER_DEFAULT)
    except win32security.error as e:
        if e.winerror == winerror.ERROR_ACCOUNT_RESTRICTION:
            return True
        elif e.winerror == winerror.ERROR_LOGON_FAILURE:
            return False
        raise
    else:
        log.Close()
        return True


def test_is_firewall_active():
    """
    Used to check if the user has an active firewall
    """
    status = is_firewall_active()
    return status


def main():
    score = 0  # final security score
    analysis = ""  # the final verdict for your system

    print("Starting Checks...")
    print("-------------------\n")

    print("\n1. Checking Device Lock")
    user_name = windows_tools.users.whoami()
    # print("Username :", user_name)
    # print("Password Set: ", not(is_password_blank(user_name)))
    if(is_password_blank(user_name)):
        analysis += "\033[2;31;43m->Your device does not have a password, Please setup a password lock \033[0;0m\n"
    else:
        analysis += "->Your device's is password protected ✓\n"
        score = score + 1

    print("\n2.Checking Antivirus Software")
    antivirus_result = windows_tools.antivirus.get_installed_antivirus_software()
    #print(*antivirus_result, sep="\n")
    if(not len(antivirus_result)):
        analysis += "\033[2;31;43m->Your device does not have an Anti-Virus Software, get one to protect yourself from malware\033[0;0m\n"
    else:
        analysis += "->Your device's has an active Anti-Virus Software ✓\n"
        score = score + 1

    print("\n3. Checking Latest Update")
    update_result = windows_tools.updates.get_windows_updates(filter_duplicates=True, include_all_states=False)
    #[print(key, ':', value) for key, value in update_result[0].items()]
    #print(update_result[0])

    print("\n4. Checking for Available Windows Update")
    wua = win32com.client.Dispatch("Microsoft.Update.Session")
    update_seeker = wua.CreateUpdateSearcher()
    search_available = update_seeker.Search("IsInstalled=1 and Type='Software'")
    if (search_available.Updates.count != 0):
        #for update_available in search_available.Updates:
            #print("Name: {}".format(update_available))
        analysis += "\033[2;31;43m->Your device software is not up-to date, make sure to download the latest updates\033[0;0m\n"
    else:
        #print("No updates necessary ")
        analysis += "->Your device's is up-to date ✓\n"
        score = score + 1

    print("\n5. Firewall Status")
    status = test_is_firewall_active()
    #print("Windows firewall status: ", status)
    if (not status):
        #print('\033[2;31;43m CHEESY \033[0;0m')
        analysis += "\033[2;31;43m->Your device's Firewall is not enabled , make sure to enable it for network safety\033[0;0m\n"
    else:
        analysis += "->Your device's Firewall is enabled ✓\n"
        score = score + 1

    #print("\n6. Trusted Apps")
    installed_applications = windowsapps.get_apps()
    # [print(key, ':', value) for key, value in installed_applications.items()] #print every app
    #compare this list with a store text document to make sure it matches up , will be done in later stages


    print("\n\nYOUR ANALYSIS:\n_______________")
    print("Security Score: ", score, "/4")
    print("Expert Analysis:\n", analysis)

    ex = input("press enter to exit")

if __name__=="__main__":

    try:
        main()
    except Exception:
        import sys
        print(sys.exc_info()[0])
        import traceback
        print(traceback.format_exc())
    finally:
        ex = input("press enter to exit")