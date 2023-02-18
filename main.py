import random 
import Crypto.Util.number  

#to install it 
#pip3 install pycryptodome==3.4.3

P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
P = int(P_HEX,16) # to base 16
G = 2
FILE_NAME = "test.txt" 

# inspirer de l'algo pseudocode de Wikipedia 
# https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide_étendu

def Euclide(a,b):
    #initialisation 
    (r, u , v ,r_prim , u_prim, v_prim) = (a,1,0,b,0,1)
    #déroulement de l'algo
    while (r_prim != 0):
        q = r //r_prim
        (r, u , v ,r_prim , u_prim, v_prim) = ( r_prim , u_prim , v_prim ,r-q*r_prim , u-q*u_prim,v-q*v_prim) 
    #le couple de coefficients de bezout 
    return (u,v)


def test_Euclide():
    print  ("\nLancement du test sur la fonction Euclide")
    print  ('\033[93m' + "\033[1mIndication\033[0m : Temps moyen du test est 3 seconds ")

    nb_test = 10000
    file  = open(FILE_NAME,"a")
    file.write("------> Les 5 premières occurences du test de la fonction Euclide()  : \n\n")
    cpt = 0
    for i in range(0,nb_test):

        a = Crypto.Util.number.getRandomNBitInteger(1024)  # generation d'un nombre aléatoire de 1024 bits
        (u,v) = Euclide(a,P)
        if (u*a+v*P) == 1 :  # verifier que (a et P) sont premiers | idem PGCD(a,P) = 1  
            cpt = cpt + 1 
            if i < 5:   # écrire les 5 premiere iterations dans le fichier de test 
                string  =  "Itération "+ str(i+1) + " :\n"+"a = "+ str(a)+"\n"+"p = "+ str(P)+"\n"+"(u,v) = "+ str((u,v))+"\n"
                file.write(string)
        progressionDisplay(i,0.05,nb_test)

    if (cpt == nb_test):
        print ("\nLa fonction Euclide est verifiée\n") 


# Question 4  ------------------------------

def ExpMod(g,a,p):
    if (p == 1):
        return 0
    res = 1
    temp = g % p
    while a >0 :
        if ( a % 2 == 1):
            res = ( res * temp ) %p
        temp = (temp * temp) % p 
        a = a//2
    return res


def test_ExpMod():
    print  ("\n---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----  ")
    print  ("\nLancement du test sur la fonction ExpMod")
    print  ('\033[93m' + "\033[1mIndication\033[0m : Temps moyen du test est 1 min 35 seconds ")

    nb_test = 10000
    file  = open(FILE_NAME,"a")
    file.write("\n\n\n\n------> Les 5 premières occurences du test de la fonction ExpMod()  : \n\n")
    cpt = 0
    for i in range(0,nb_test):
        a = Crypto.Util.number.getRandomNBitInteger(1024)      # generation d'un nombre aléatoire de 1024 bits
        res = ExpMod(G,a,P)
        if res == pow(G,a,P) :  # verifier si le resultat est correcte 
            cpt = cpt + 1 
            if i < 5:   # écrire les 5 premiere iterations dans le fichier de test 
                string  =  "Itération "+ str(i+1) + " :\n"+"g = "+ str(G)+"\n"+"a = "+ str(a)+"\n"+"p = "+ str(P)+"\n"+"res = ExpMod(g,a,p)= "+ str(res)+"\n"
                file.write(string)
        progressionDisplay(i,0.05,nb_test)

    if (cpt == nb_test):
        print ("\nLa fonction ExpMod est verifiée\n") 


# question 5 ----------------------------------

class KeyPublic:
    def __init__(self, p, g, X):
        self.p = p
        self.g = g
        self.X = X

class KeySecret:
    def __init__(self, x):
        self.x = x


def KeyGen(p,g):
    x = Crypto.Util.number.getRandomRange(2,p-2)
    X = ExpMod(g,x,p)
    Kp = KeyPublic(p,g,X)
    Ks = KeySecret(x)
    return (Kp,Ks)



global R # varaible globale utile pour test si tous les R génerer sont différents 

# Kp : la clé secréte de bob
# message : le message à chifrer. 
def Encrypt(Kp,message):
    global R
    R = Crypto.Util.number.getRandomRange(2,Kp.p-2)
    y = ExpMod(Kp.X,R,Kp.p)
    C = (message * y)%Kp.p
    B = ExpMod(Kp.g,R,Kp.p)
    return (C,B)


# Ks : la clé secréte de bob
# data = (C,B) le couple du resulat de la fonction Encrypt(Kp,message) envoyé par alice
# Kp : la clé secréte de bob
def Decrypt(Ks,encryptedData,Kp):   
    (C,B) = encryptedData
    D = ExpMod(B,Ks.x,Kp.p)
    (u,v) = Euclide(D,Kp.p)
    D_1 = u % Kp.p  
    message = (C*D_1)%Kp.p
    return  message


def testEncryptAndDecrypt():
    print  ("\n---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----  ")
    print  ("\nLancement du test sur les fonctions KeyGen ,Encrypt et Decrypt ")
    print  ('\033[93m' + "\033[1mIndication\033[0m : Temps moyen du test est 3 seconds ")

    nb_test = 100
    cpt = 0
    file  = open(FILE_NAME,"a")
    file.write("\n\n\n\n------> Les 5 premières occurences du test des fonctions  KeyGen ,Encrypt et Decrypt  : \n\n")
    RValues = []
    for i in range(0 , 100):
        messageToEncrypt = Crypto.Util.number.getRandomRange(0,P-1)                          #generer un message < P
        (Kp,Ks) = KeyGen(P,G)
        (C,B) = Encrypt(Kp, messageToEncrypt)
        messageDecrypted = Decrypt(Ks, (C,B) ,Kp)
        
        if ( (messageToEncrypt == messageDecrypted)  and (R not in RValues)):   # test si les message sont les meme et aussi si R n'a pas été deja géneré
            RValues.append(R) # ajouter la variable global R 
            cpt = cpt + 1
            if i < 5:   # écrire les 5 premiere iterations dans le fichier de test 
                string  =  "Itération "+ str(i+1) + " :\n"+" messageToEncrypt = "+ str(messageToEncrypt)+"\n"+"(C,B) = ( "+str(C)+" , "+str(B)+" )\n"+"messageDecrypted = "+ str(messageDecrypted)+"\n"
                file.write(string)
        progressionDisplay(i,0.05,nb_test)
    if (cpt == nb_test):
        print ("\nLes fonctions KeyGen ,Encrypt et Decrypt sont verifiées, Ce qui le bon fonctionnement de El Gamel \n") 

# Question 6 ------------------------------------------

def testHomomorphicPropertyOfElGamal():    
    print  ("\n---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----  ")
    print  ("\nLancement du test de la propriété homomorphique de El Gamal ")
    print  ('\033[93m' + "\033[1mIndication\033[0m : Temps moyen du test est 4 seconds ")

    nb_test = 100
    cpt = 0
    for i in range(0,nb_test):
        m1 = Crypto.Util.number.getRandomRange(0,P-1)
        m2 = Crypto.Util.number.getRandomRange(0,P-1)
        (Kp,Ks) = KeyGen(P,G)     
        (C1,B1) = Encrypt(Kp, m1)
        (C2,B2) = Encrypt(Kp, m2)
        C = (C1*C2) % Kp.p
        B = (B1*B2) % Kp.p
        m = Decrypt(Ks, (C,B) ,Kp)
        if ( m ==  (m1*m2) % Kp.p):
            cpt = cpt + 1
        progressionDisplay(i,0.05,nb_test)
    if cpt == nb_test:
        print  ("\nLe test de propriété homomorphique de El Gamal est verifié \n")


def progressionDisplay(currentTest,frequenceDiplay,nbTest):
    if(currentTest == 0):
        print()
        print("Debut de test ") 
    if (currentTest % (frequenceDiplay*nbTest) == 0): 
        print("progression . . . . "+ str(int((currentTest/nbTest)*100)) + " %") 
    if(currentTest == nbTest-1):
        print("Test fini ") 



if __name__ == '__main__':
    open(FILE_NAME,"w")  # créer un nouveau fichier
    test_Euclide()
    test_ExpMod()
    testEncryptAndDecrypt()
    testHomomorphicPropertyOfElGamal()
