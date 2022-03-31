import mysql.connector
import datetime
from _datetime import datetime
import os
from lxml import etree
import smtplib
from email.message import EmailMessage

skaneris_db_user = os.environ.get('SKANERIS_DB_USER')
skaneris_db_pwd = os.environ.get('SKANERIS_DB_PWD')
iDoit_db_user = os.environ.get('IDOIT_DB_USER')
iDoit_db_pwd = os.environ.get('IDOIT_DB_PWD')
send_to = os.environ.get('MANS_EPASTS')
smtp_server = os.environ.get('SMTP_SERVER')

MyDB = mysql.connector.connect(host='localhost', user=skaneris_db_user, passwd=skaneris_db_pwd, database='skaneris')
# pieslēgšanās mysql DB
iDoitDB = mysql.connector.connect(host='192.168.88.203', user=iDoit_db_user, passwd=iDoit_db_pwd, database='iDoit_data')
# pieslēgšanās mysql DB

logtime = datetime.now().strftime('%Y.%m.%d_%H:%M:%S ')  # Laika formāts rakstīšanai logfailā

class Scanner:  # Veic skanesanas darbibu
    def nmap():  # metode nmap skana veiksanai
        scanlog.write(logtime + "Uzsāk Nmap skanu\n")  # Ierakstia loga procesa sakumu
        print("\nUzsāk nmap skanu\n")
        try:
            os.system("/usr/bin/sudo /usr/bin/nmap -sS n --max-retries 1 -Pn -p1-65535 --open --discovery-ignore-rst "
                  "--max-rtt-timeout 60ms --initial-rtt-timeout 10ms -iL ip_to_scan.txt -oX nmap_scan_result.xml")
                # izpilda nmap komandu terminali
        except Exception:
            scanlog.write(logtime + "Error: Nevar veikt nmap skanu\n")  # Ieraksta loga error msg
            print('Error: Nevar veikt nmap skanu')
        print("")
        print("Nmap skans beidzies")
        print("\n****************************************************************")

    def masscan():  # metode masscan skana veiksanai
        scanlog.write(logtime + "Uzsāk Nmap skanu\n")  # Ierakstit loga procesa sakumu
        print("")
        print("Uzsāk masscan skanu")
        print("")
        try:
            os.system("/usr/bin/sudo /usr/bin/masscan -iL scanner_ip_range.txt --open --rate 6000 -p1-65535 "
                      "| awk '{print $6}' > masscan_result_og.txt")
            # izpilda masscan komandu terminali, saglaba tikai atrastās IP adreses
        except Exception:
            print('Error: Nevar veikt masscan skanu')
            scanlog.write(logtime + "Error: Nevar veikt masscanp skanu\n")  # Ieraksta loga error msg
        print("")
        print("Masscan skans beidzies")
        print("\n****************************************************************")

class Converter: # parveido skana rezultatu par lietojamu
        def masscan_result_converter(): #parveido masscan rezultatu, atlasot tikai IP un saglabajot faila
            # Ierakstit loga procesa sakumu
            IP_list = []
            print("")
            print("Sākta masscan rezultātu apstrāde")
            print("")
            delete_ip_to_scan = open('ip_to_scan.txt', 'w')
            delete_ip_to_scan.write('')  # izdzes ieprieksejos datus
            delete_ip_to_scan.close()  # aizver failu
            scan_result = open('masscan_result_og.txt', 'r')
            ip_to_scan = open('ip_to_scan.txt', 'a')
            try:
                for IP in scan_result.readlines():
                    if IP not in IP_list:
                        IP_list.append(IP)  # ieliek IP adresi saraksta
                        ip_to_scan.write(IP)  # ieraksta IP adresi faila
                print(IP_list)
                ip_to_scan.close()  # aizver failu
                scan_result.close()  # aizver failu
            except Exception:
                print('Error: Netika apstradats masscan skana fails')
                scanlog.write(logtime + "Error: Netika apstradats masscan skana fails\n")  # Ieraksta loga error msg
            print("")
            print("Beigta masscan rezultātu apstrāde")
            print("\n****************************************************************")

        def nmap_rfile_rename(vecais_fails):  # nomaina faila nosaukumu, atlasa datus, ko nepieciesams apstradat
            # Ierakstit loga procesa sakumu
            print("")
            print("Sākta nmap skana apstrāde")
            print("")
            datums = datetime.now().strftime('%Y%m%d')
            jaunais_fails = datums + '_' + vecais_fails
            try:
                os.rename(vecais_fails, jaunais_fails)
            except Exception:
                print('Error: Netika atrasts nmap_scan_result.xml fails')
                scanlog.write(logtime + "Error: Netika atrasts nmap_scan_result.xml fails\n")  # Ieraksta loga error msg
            print('Beigta nmap skana apstrāde')

class Parser:  # Atlasa IP, portus un hostname no nmap skana rezultata un ieraksta DB
    def parse_nmap(file_name):
        scanlog.write(logtime + "Uzsākta nmap rezultāta konvertēšana\n")
        print('Uzsākta nmap rezultāta konvertēšana')
        print("\n****************************************************************")
        try:
            doc = etree.parse(file_name)
            root = doc.getroot()
            hosts = []
            for r in root:
                if r.tag == "host":
                    host = dict()
                    for z in r:
                        if z.tag == "hostnames":
                            hns = []
                            for hn in z:
                                hns.append(hn.attrib['name'])
                            host['hostname'] = hns
                        if z.tag == "address" and z.attrib['addrtype'] == "ipv4":
                            host['address'] = z.attrib['addr']
                        if z.tag == "ports":
                            ports = []
                            for port in z:
                                if port.tag == "port":
                                    ports.append(port.attrib['portid'])
                            host['ports'] = ports
                    hosts.append(host)
            try:
                scanlog.write(logtime + 'Uzsakta datu erakstīšana scandbB\n')
                print('Uzsākta datu ierakstīšana scandbB')
                MySQL_search_query = """SELECT ip FROM skaneris.scandb """
                MySQL_record_insert = """INSERT INTO skaneris.scandb (ip, hostname, ports, first_seen) VALUES (%s, %s, %s, curdate()) """
                for record in hosts:
                    cursor = MyDB.cursor()
                    a = record['address']
                    h = ''.join(record['hostname'])
                    p = ', '.join(str(elem) for elem in record['ports'])
                    b = False
                    mysql_record = (a, h, p)
                    cursor.execute(MySQL_search_query)
                    query = list(cursor)
                    for i in query:
                        i = ''.join(i)
                        if a == i:
                            b = True
                            print("IP jau ir DB")
                    if b == False:
                        print("execute record script")
                        cursor.execute(MySQL_record_insert, mysql_record)
                        MyDB.commit()
            except Exception:
                print('Error: Nevar datus ierakstīt scandb')
                scanlog.write(logtime + 'Error: Nevar datus ierakstīt scandb\n')
        except Exception:
            print('Error: Nevar veikt nmap skana parsesanu')
            scanlog.write(logtime + "Error: Nevar veikt nmap skana parsēšanu\n")  # Ieraksta loga error msg

class iDoit_data: # Atvelk datus no uzskaites sistemas
    def pull():
        try:
            scanlog.write(logtime + "Atvelk datus no iDoit DB\n")  # Ierakstit loga procesa sakumu
            print('Atvelk datus no iDoit DB')
            MySQL_pull_from_iDoit = """INSERT INTO skaneris.iDoit_data (ip, name, lietojums) SELECT ip, hostname, bl FROM iDoit_data.iDoit_for_scan """
            MySQL_clear_data = """DELETE FROM skaneris.iDoit_data  """
            cursor = iDoitDB.cursor()
            cursor.execute(MySQL_clear_data)  # Izdzēš vecos datus no tabulas
            iDoitDB.commit()
            cursor.execute(MySQL_pull_from_iDoit)  # Ieraksta jaunos datus tabulā
            iDoitDB.commit()
        except Exception:
            print('Nevar nokopēt datus no iDoit DB')
            scanlog.write(logtime + "Error: Nevar nokopēt datus no iDoit DB\n")  # Ieraksta loga error msg


class Email_sender:  # Nosūta epastu ar jaunatklātajām IP adresēm
    def select_data():
        scanlog.write(logtime + 'Uzsākta e-pasta sagatavošana\n')
        print('Uzsākta epasta sagatavošana')
        print("\n****************************************************************")

        MySQL_select_ip_to_send = """SELECT ip from skaneris.scandb WHERE scandb.first_seen = curdate() """
        MySQL_select_ip_from_scandb = """SELECT ip FROM skaneris.scandb WHERE ip = %s """
        MySQL_select_hn__from_scandb = """SELECT hostname FROM skaneris.scandb WHERE ip = %s """
        MySQL_select_port_from_scandb = """SELECT ports FROM skaneris.scandb WHERE ip = %s """
        MySQL_select_iDoit_hn = """SELECT name FROM skaneris.iDoit_data WHERE ip = %s  """
        MySQL_select_iDoit_bl = """SELECT lietojums FROM skaneris.iDoit_data WHERE ip = %s  """

        cursor = MyDB.cursor()
        cursor.execute(MySQL_select_ip_to_send)
        ip_to_send = cursor.fetchall()
        email = open("email.txt", "w")
        email.write("Atrasti jauni serveri:\n\n")
        email.close()
        try:
            for ip in ip_to_send:
                # Atlasa IP
                cursor.execute(MySQL_select_ip_from_scandb, ip)
                db_ip = cursor.fetchall()
                db_ip = ''.join(str(elem) for elem in db_ip)
                db_ip = db_ip.replace("'", "").replace('(', '').replace(')', '').replace(',', '')

                # Atlasa portus
                cursor.execute(MySQL_select_port_from_scandb, ip)
                port = cursor.fetchall()
                port = ''.join(str(elem) for elem in port)
                port = port.replace("'", "").replace('(', '').replace(')', '')

                # Atlasa hostname
                cursor.execute(MySQL_select_hn__from_scandb, ip)
                hn = cursor.fetchall()
                hn = ''.join(str(elem) for elem in hn)
                hn = hn.replace("'", "").replace('(', '').replace(')', '').replace(',', '')

                # Atlasa iDoit servera nosaukmu
                cursor.execute(MySQL_select_iDoit_hn, ip)
                iDoit_hn = cursor.fetchall()
                iDoit_hn = ''.join(str(elem) for elem in iDoit_hn)
                iDoit_hn = iDoit_hn.replace("'", "").replace('(', '').replace(')', '').replace(',', '')

                # Atlasa iDoit servera biznesa lietojumu
                cursor.execute(MySQL_select_iDoit_bl, ip)
                iDoit_bl = cursor.fetchall()
                iDoit_bl = ''.join(str(elem) for elem in iDoit_bl)
                iDoit_bl = iDoit_bl.replace("'", "").replace('(', '').replace(')', '').replace(',', '')

                # Sagatavo epasta tekstu txt dokumentā
                email = open("email.txt", "a")
                email.write('IP - ' + db_ip + ' / Porti - ' + port + ' / Hostname - ' + hn + ' / iDoit Servera vārds - ' + iDoit_hn + ' / iDoit Biznesa lietojums - ' + iDoit_bl + "\n\n")
                email.close()

            email = open("email.txt", "a")
            email.write("IT risku vadītājs - Toms Užāns \ntoms.uzans@tet.lv\n\n")
            email.close()
        except Exception:
            print('Error: Nevar sagatavot e-pastu')
            scanlog.write(logtime + "Error: Nevar sagatavot e-pastu\n")  # Ieraksta loga error msg

    def send_mail():
        scanlog.write(logtime + 'Uzsākta e-pasta sūtīšana\n')
        print('Uzsākta epasta sūtīšana')
        try:
            with open('email.txt', 'r') as email:
                zina = email.read()

                msg = EmailMessage()
                msg['Subject'] = 'Atrastas jaunas IP adreses!'
                msg['From'] = 'MyHostScanner@cpescan-prd.telekom.lv'
                msg['To'] = send_to
                msg.set_content(zina)

            with smtplib.SMTP(smtp_server, 25) as smtp:
                smtp.send_message(msg)
        except Exception:
            print('Error: Nevar nosūtīt e-pastu')
            scanlog.write(logtime + "Error: Nevar nosūtīt e-pastu\n")  # Ieraksta loga error msg

scanlog = open("scan_log.txt", "a") # Atver skana loga failu
scanlog.write(logtime + "Skans uzsākts\n")
print('Skanēšana uzsākta')
Scanner.masscan() # izsauc masscan metodi
Converter.masscan_result_converter() # izsauc metodi,kas konverte masscan rezultatu uz nmap skana IP sarakstu
Scanner.nmap() # izsauc nmap metodi
Parser.parse_nmap('nmap_scan_result.xml')
print('Dati ierakstīti scandb')
print("\n****************************************************************")
iDoit_data.pull()
print('iDoit dati nokopēti tabulā iDoit_data')
print("\n****************************************************************")

Email_sender.select_data()
Email_sender.send_mail()
print('e-pasts nosūtīts')
print("\n****************************************************************")

Converter.nmap_rfile_rename('nmap_scan_result.xml') # izsauc metodi, kas apstrada nmap skana rezultatus
print("")
print('Skanēšana pabeigta!')
scanlog.write(logtime + "Skans pabeigts\n")  # Ieraksta loga procesa beigas
MyDB.close()  # Aizver DB
scanlog.close()  # Aizver skana loga failu
