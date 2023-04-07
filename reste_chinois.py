import math

############ inv###############
def inverse_modulaire_modulo(a, n):
    # Calcule l'inverse multiplicatif de a modulo n
    r, r_prec = n, a
    x, x_prec = 0, 1
    while r != 0:
        q = r_prec // r
        r, r_prec = r_prec - q * r, r
        x, x_prec = x_prec - q * x, x
    if r_prec != 1:
        raise ValueError("a n'a pas d'inverse modulo n")
    return x_prec % n


############### trouver les nbr premier d'un nbr##############
def factorise(n):
    # Retourne la liste des facteurs premiers distincts de n
    facteurs = []
    i = 2
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            if i not in facteurs:
                facteurs.append(i)
    if n > 1 and n not in facteurs:
        facteurs.append(n)
    return facteurs



############ facteur avec le nbr de fois qu'il apparré ###############
def factorisation_comptage(n):
    """
    Factorise un nombre n en nombres premiers.
    Retourne un dictionnaire avec les facteurs premiers comme clés
    et leur nombre d'occurrences comme valeurs.
    """
    # Initialisation des variables
    facteurs = {}
    diviseur = 2

    # Division successive
    while n > 1:
        # Teste si le diviseur est un facteur premier
        while n % diviseur == 0:
            if diviseur in facteurs:
                facteurs[diviseur] += 1
            else:
                facteurs[diviseur] = 1
            n //= diviseur
        diviseur += 1

    return facteurs



########## reste chinois 2###################
def inverse_chenese(a, n):
    # Étape 1 : décomposition de n en facteurs premiers
    facteurs = factorisation_comptage(n)
    facteurs_puissance=[ math.pow(i,facteurs[i]) for i in facteurs]
    facteurs_puissance=[int(facteurs_puissance [i]) for i in range(len(facteurs_puissance))]
    N = [n // facteurs_puissance[i] for i in range(len(facteurs_puissance))]
    #print(N)
    #print(facteurs)
    #print(facteurs_puissance)
    # Étape 2 : calcul des inverses multiplicatifs modulo chaque facteur premier
    x = [inverse_modulaire_modulo(a, facteurs_puissance[i]) for i in range(len(facteurs_puissance))]
    print(x)
    M=[inverse_modulaire_modulo(N[i], facteurs_puissance[i]) for i in range(len(facteurs_puissance))]
    # Étape 3 : calcul de l'inverse modulo n à partir des inverses modulo chaque facteur premier
    res = sum([x[i] * N[i] * M[i] for i in range(len(facteurs_puissance))]) % n
    #print(M)
    #print(res)
    return res

#k=inverse_chenese(17,46*16)
#kk=inverse_modulaire_modulo(7,192)
#print(k)
#print(kk)
#fa=factorisation_comptage(16*46)
fa=inverse_chenese(17,46*16)
verification=inverse_modulaire_modulo(17,46*16)
print(fa)
print(verification)