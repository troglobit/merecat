#!/usr/bin/python3

import cgi
import cgitb
import datetime


cgitb.enable(display=0, logdir="/var/log/onboard")

# Create instance of FieldStorage
form = cgi.FieldStorage()

# Get data from fields
if form.getvalue('username'):
   username = form.getvalue('username')
else:
   username = "username"

if form.getvalue('gecos'):
   gecos = form.getvalue('gecos')
else:
   gecos = "gecos"

if form.getvalue('sshkey'):
   sshkey = form.getvalue('sshkey')
else:
   sshkey = "no_sshkey entered"

mmss = datetime.datetime.now().strftime("%M%S")
f = open("/var/www/onboard/file/%s.text" % mmss, "w")
f.write("# k:v, k:v, separator, line(s)\n")
f.write("username: %s\n"% username)
f.write("gecos: %s\n"% gecos)
f.write("# SSH public key(s)\n")
f.write("%s\n"% sshkey)
f.close()

print("Content-type:text/html")
print()  # separator
print("<html>")
print("<head>")
print("<title>So far</title>")
print("</head>")
print("<body>")
print("<p>Hello %s</p>" % username)
print('<p>There is now <a href="/onboard/file/%s.text">file/%s.text</a>.</p>' % (mmss,mmss))
print("<p>It has to be further processed, outside this <i>web form stuff</i></p>")
print('<p><a href="/onboard/">Back to <b>onboard begin</b></a></p>')
print("</body>")
print("</html>")
