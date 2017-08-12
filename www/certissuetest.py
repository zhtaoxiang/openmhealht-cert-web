import subprocess

request = "Bv0DKwdKCANvcmcIC29wZW5taGVhbHRoCApKOHpYRm9QYmc2CANLRVkIEWtzay0x\nNTAyMTc4MDUzMTcxCAdJRC1DRVJUCAn9AAABXcDKDHsUCRgBAhkEADbugBX9AYQw\nggGAMCIYDzIwMTcwODA4MDc0MDUzWhgPMjAzNzA4MDMwNzQwNTNaMDYwNAYDVQQp\nEy0vb3JnL29wZW5taGVhbHRoL0o4elhGb1BiZzYva3NrLTE1MDIxNzgwNTMxNzEw\nggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQCPi2ZyZ6OODHyZZtOoFusX\nMIlvi9gtUKqpsWQUdaGm2HJ9tjriL3NkfpdD6/6kjMsOkzLc1sTT/CMRm1Q3toQm\n6DzpBF0vwcdpkvLDX54oP5Iu3FBAgsRiUB4pRGU9654euFCIQHnAtDkiVqldh4u5\ncTjzKAW0cKgc9eJf8ke0H6E3zS7PHQIUqdYhWaf3sAf7X4NSkiaGSFgCNLqRuTz1\nB6T1j42G4d1M/GvORtAsBs3h/pVE8v6PHr4Imsh+h3TliE+tG1rqAHHw1Xf7rEja\nQE9zIp+73iHeKH4mwj1PFYBxEPibbsx6snzirY7lIW66Dph0KZa7ANik26uFc7Qz\nAgERFkYbAQEcQQc/CANvcmcIC29wZW5taGVhbHRoCApKOHpYRm9QYmc2CANLRVkI\nEWtzay0xNTAyMTc4MDUzMTcxCAdJRC1DRVJUF/0BAHG6X2Qux8LhpH2w3lagO13T\nJLm+JIc5Li+xooCyFKGgSA7oquZrMPmJ3czV0kJLTSWcW5WcpKECqhLJ0ELjCOGc\nrZgoL2BsKC4FKRZytYnxkm1Qj0f4X+DoTdTBM5UhxT7zfnD0ZXQzsu/DPNoiHl6z\n/X6bVnqFJWEhGzSR44cINoJME8GE8Dxz4gs/H2zzziU3JjxzmScrl60Mmv1H5itE\nuS4hI0PJtx6LdaQHhcIiEdKq50Zq86qUOmmkgF2SYx7lB34PISogIrDNtTacRGyd\ncHRykmKcFxBddOls3Y+hRXn9P66vHSXOlUWz60EA/Cb5qAQ4lUUuWITFGt3pYtw="

cmdline = ['ndnsec-certgen',
           '--not-before', '20170808050533',
           '--not-after',  '20180809050533',
           '--subject-name', 'haitao',

           '--signed-info', '1.2.840.113549.1.9.1 zhtaoxiang@163.com',

           '--sign-id', '/org/openmhealth',
           '--cert-prefix', '/org/openmhealth',
           '--request', '-'
           ]
print cmdline

p = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
cert, err = p.communicate(request)
print cert
print err
print p.returncode
if p.returncode != 0:
    print "ndnsec-certgen error"
print "done"
