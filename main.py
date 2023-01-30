from Crypto.Util.number import getRandomNBitInteger  #https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#module-Crypto.Util.number

#commande to install the Crypto librery 
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
    #le couple de coefficients de bezzout 
    return (u,v)



def test_Euclide():
    nb_test = 10000
    file  = open(FILE_NAME,"a")
    file.write("------> Les 5 premières occurences du test de la fonction Euclide()  : \n\n")
    cpt = 0
    
    for i in range(0,nb_test):
        a = getRandomNBitInteger(1024)    # generation d'un nombre aléatoire de 1024 bits (fonction de la librery Crypto)
        (u,v) = Euclide(a,P)
        
        if (u*a+v*P) == 1 :
            print ( 'iteration '+ str(i) + '  --> correct') 
            cpt = cpt + 1 
            if i < 5:   # écrire les 5 premiere iterations dans le fichier de test 
                string  =  "Itération "+ str(i+1) + " :\n"+"a = "+ str(a)+"\n"+"p = "+ str(P)+"\n"+"(u,v) = "+ str((u,v))+"\n"
                file.write(string)

    if (cpt == nb_test):
        print ("la fonction Euclide est verifiée") 





if __name__ == '__main__':
    open(FILE_NAME,"w")  # créer un nouveau fichier
    test_Euclide()