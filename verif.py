import OpenSSL.crypto
from datetime import datetime , timedelta


def datetime_to_str(date):

    date = str(date)
    date = date.split(' ')
    date[0] = date[0].split('-')
    date[1] = date[1].split(':')
    
    datestr = date[0][0] + date[0][1] + date[0][2] + date[1][0] + date[1][1] + date[1][2]
    datestr = datestr.split('.')
    datestr = datestr[0]

    return datestr


def notAfter_to_str(notAfter):
    
    notAfter = str(notAfter)
    notAfter = notAfter[2:-2]

    return notAfter

def is_valid(cert):

    now = datetime.utcnow()
    now = datetime_to_str(now)
    date_exp = cert.get_notAfter()
    date_exp = notAfter_to_str(date_exp)

    if (now >= date_exp):
        return False
    else:
        return True

def check_issuer(cert):
        
    issuer = str(cert.get_issuer())
    issuer = issuer.split('/')
    iss = issuer[1].split("'")
    iss = iss[0]
    iss = iss[3:]

    if (iss == 'ca_server'):
        return True
    else:
        return False
    
def check_user(cert,user):
    
    owner = str(cert.get_subject())
    owner = owner.split('/')
    own = owner[1].split("'")
    own = own[0]
    own = own[3:]

    if (own == user):
        return True
    else:
        return False


def verif(cert, user):
    if not check_issuer(cert):
        print('This certificate was not issued by CA')
        return False
    if not check_user(cert,user):
        print('This certificate is not for this user')
        return False
    if not is_valid(cert):
        print('This certificate is expired')
        return False
    
    return True

cert = OpenSSL.crypto.load_certificate(
    OpenSSL.crypto.FILETYPE_PEM, 
    open('youmna.crt').read()
)

user = 'youmna'

print(verif(cert,user))