#!/usr/bin/python3.6
#Aplicacao de administracao de classes de servicos - Versao 7.0
#Manipula uma lista de objetos Classe

import os
from classe import Classe
import pickle

path_home = os.getenv("HOME") #Captura o caminho da pasta HOME
filename = path_home+'/ufjf_AuthFlow/classes.conf'	#Nome do arquivo de classes de servicos
tx_max = 100000000 #100Mb					#Vazao maxima da rede em bps

def persist(classlist):			#Persiste uma lista de objetos Classe no arquivo "filename"
    file = open(filename,'wb')
    pickle.dump(classlist,file)


def retrieve():				#Recupera uma lista de objetos Classe do arquivo "filename"
    file=open(filename,'rb')
    return pickle.load(file)


def isempty(classlist):			#Verifica se ha objetos Classe na lista
    if len(classlist)==0:
        print('\nNao ha classes')
        return 1
    return 0


def search(classlist):			#Procura um objeto Classe na lista
    if isempty(classlist):
        return None
    nome = input('\nDigite o nome da classe: ')
    for c in classlist:
        if c.nome == nome:
            return c
    print('\nClasse nao encontrada')
    return None


def configqos(classlist):		#Aplica as configuracoes de QoS na rede
    index = 0
    queue = []
    os.system('ovs-vsctl -- --all destroy QoS -- --all destroy Queue')
    for c in classlist:
        queue.append(os.popen('ovs-vsctl create queue other-config:min-rate=%s other-config:max-rate=%s' %(c.media,c.pico)).read().strip('\n'))
    qos = os.popen('ovs-vsctl create qos type=linux-htb other-config:max-rate=%d' %tx_max).read().strip('\n')
    for q in queue:
        os.system('ovs-vsctl add qos %s queues %d=%s' %(qos,index,q))
        index+=1

def setQosTodasPortas(): #Aplica as filas criadas no HW
    ports = os.popen("ovs-vsctl show | grep Port | awk '{print $2}'").read().split('\n')
    ports_aux = []
    for i in range(0, len(ports)):
        if len(ports[i]) > 4:
            print("Porta: ",ports[i])
            ports_aux.append(ports[i])
    ports = ports_aux
    qos = os.popen("ovs-vsctl list qos | grep _uuid | awk '{print $3}'").read().strip('\n')
    for port in ports:
        print("Aplicando QoS na porta:", port)
        os.system('ovs-vsctl set port '+ port + ' qos=' + str(qos))



def menu():				#Imprime o menu principal na tela
    print('\nMENU PRINCIPAL:')
    print('1- Incluir classe')
    print('2- Alterar classe')
    print('3- Listar parametros de classe')
    print('4- Listar classes')
    print('9- Sair')
    return int(input('Digite a opcao: '))


if __name__=='__main__':		#Funcao principal
    classlist=[]
    if os.path.isfile(filename):
        classlist=retrieve()
    print('\nCONFIGURACAO INICIAL:')
    #tx_max=int(raw_input('Digite a vazao maxima da rede em bps: '))
    tx_max = 5000000 # 5Mb
    #media=int(raw_input('Digite a taxa media da classe de melhor esforco (be) em bps: '))
    media = 5000000 # 5Mb
    #pico=int(raw_input('Digite a taxa de pico da classe de melhor esforco (be) em bps: '))
    pico = 5000000 # 5Mb
    if len(classlist)==0:
        classlist.append(Classe(0,'be',media,pico))
    else:
        classlist[0]=Classe(0,'be',media,pico)
    while True:
        opcao=menu()

        #classlist.append(Classe(len(classlist),nome,media,pico))
        if opcao == 1:		#Incluir classe
            nome = input('Digite o nome da classe: ')
            media = int(input('Digite a taxa media em Mbps: '))
            media = media * 1000000
            pico = int(input('Digite a taxa de pico em Mbps: '))
            pico = pico * 1000000
            classlist.append(Classe(len(classlist),nome,media,pico))

        if opcao == 2:		#Alterar classe
            c = search(classlist)
            if c == None:
                continue
            media = int(input('Digite a taxa media em Mbps: ')*1000000)
            pico = int(input('Digite a taxa de pico em Mbps: ')*1000000)
            c.media = media
            c.pico = pico

        if opcao == 3:		#Listar parametros de classe
            c = search(classlist)
            if c == None:
                continue
            c.imprime()

        if opcao == 4:		#Listar classes
            if isempty(classlist):
                continue
            for c in classlist:
                c.imprime()

        if opcao == 9:		#Sair
            break

    persist(classlist)
    configqos(classlist)
    print('Aplicando a Filas!!')
    setQosTodasPortas()
    print('Filas Aplicadas!!')
