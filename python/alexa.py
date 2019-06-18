#! /usr/bin/env python3

from mysql.connector import connect
from multiprocessing import Process, JoinableQueue
from time import time
import sys
import datetime

from cert import cert_from_netloc

DB_HOST = '127.0.0.1'
DB_USER = 'samuelle'
DB_PASSWD = 'samuelle2017'
DB_NAME = 'digitalworks'

NB_PROCESSES = 12
REQ_TIMEOUT = 10


class Consumer(Process):
    def __init__(self, name, queue):
        super().__init__()
        self.daemon = True
        self.name = name
        self.queue = queue

    def timeout(self):
        print('{}: timeout reach', file=sys.stderr)
        self.queue.task_done()

    def run(self):
        while True:
            rid, host = self.queue.get()                        # get rid and hostname from queue
            print('{}: start {} - id {}'.format(self.name, host, rid))

            ssl_cert = cert_from_netloc(netloc=host, pem_cert=False, check_host=False, check_revoc=False)
            if ssl_cert.errors is not None:                     # if cert invalid, task done and continue
                print('{}: {} cert errors {}'.format(self.name, host, ssl_cert.errors), file=sys.stderr)
                conn2 = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWD, database=DB_NAME)    # get rid and hostnames from db
                cursor2 = conn2.cursor()
                cursor2.execute(""" DELETE FROM `ssl_tab` where `id` = %s """, (rid,))
                conn2.commit()
                conn2.close()
                self.queue.task_done()
                continue

            try:
                date = ssl_cert.notAfter                        # get date and issuer format for db
                issuer = ssl_cert.issuer['Common Name']         # get issuer name

                type_ = 'DV'                                    # get type (DV, OV, WC, SAN)
                if 'Common Name' in ssl_cert.subject and '*' in ssl_cert.subject['Common Name']:
                    if 'Organization Name' in ssl_cert.subject:
                        type_ = 'WC OV'
                    else:
                        type_ = 'WC DV'
                elif ssl_cert.subjectAltName is not None and len(ssl_cert.subjectAltName) > 1:
                    if 'Organization Name' in ssl_cert.subject:
                        type_ = 'SAN OV {}'.format(len(ssl_cert.subjectAltName))
                    else:
                        type_ = 'SAN DV {}'.format(len(ssl_cert.subjectAltName))
                elif 'Organization Name' in ssl_cert.subject:
                    type_ = 'OV'

            except:
                print('{}: {} format error'.format(self.name, host), file=sys.stderr)
                self.queue.task_done()
                continue

            # store cert date and issuer in db
            # change by column if date_expire has changed
            try:
                conn = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWD, database=DB_NAME)
                cursor = conn.cursor()
                datenow = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                datenow = str(datenow)
                #print(datenow)
                #sys.exit()
                cursor.execute(""" UPDATE `ssl_tab` SET `by_email` = IF(`date_expire` = %s, `by_email`, ''),
                `date_expire` = %s, `ca` = %s, `LastCheck` = %s,`type` = %s WHERE `id` = %s """, (date, date, issuer, datenow, type_, rid))
                conn.commit()
                conn.close()
            except:
                print('{}: {} sql error'.format(self.name, host), file=sys.stderr)
                self.queue.task_done()
                continue

            print('{}: {} done'.format(self.name, host))    # end of task
            self.queue.task_done()


def main():
    hosts_queue = JoinableQueue()                                   # create queue

    consumers = list()                                              # create and start consumers
    for idx in range(NB_PROCESSES):
        name = 'cons_{}'.format(idx+1)
        consumers.append(Consumer(name=name, queue=hosts_queue))
    for consumer in consumers:
        consumer.start()

    conn = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWD, database=DB_NAME)    # get rid and hostnames from db
    cursor = conn.cursor()
    #cursor.execute(""" SELECT `id`, `domaine` FROM `ssl_tab` where date_expire ='0000-00-00' order by id DESC  """)
    cursor.execute(""" SELECT `id`, `domaine` FROM `ssl_tab` order by id DESC  """)

    row = cursor.fetchone()                                         # add row to queue
    while row is not None:
        rid = int(row[0])
        host = row[1]
        hosts_queue.put((rid, host))
        row = cursor.fetchone()
    conn.close()

    hosts_queue.join()                                              # wait for queue to be empty
    for consumer in consumers:
        consumer.terminate()
    print('END')


if __name__ == '__main__':
    start = time()
    main()
    print('time: {} s'.format(time() - start))
