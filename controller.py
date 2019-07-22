from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from hostapd_socket import HostapdSocket
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

#Pacotes
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

#Extras
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto import ether

#Sistema
import os
import time
import pickle
import json
import classe #Utilizada no pickle

import Tabela as TB

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
ZERO_MAC = '00:00:00:00:00:00'

#IP_SERVIDOR = tb.ip_mac_servidor[0]

#TABELA_IP_PORTAS = tb.tabela_ip_porta

#TABELA_IP_SERVIDORES = tb.tabela_ip_servidores

#MAC_SERVIDOR = tb.mac_servidor




#PORTA_SERVIDOR = porta #ARRUMAR DEPOIS

path_home = os.getenv("HOME") #Captura o caminho da pasta HOME

#Arquivos
filename = path_home+'/Projeto_Prof_Alex_SDN/classes.conf'	#Arquivo de lista de objetos Classe


ETH_TYPE_8021x = 0x888E
'''
Ligacao entre o hostapd_socket e o controlador acontece pelo dict 'portDict', o qual fornece
as informacoes de liberacao do host e sua identidade!!!

1 - Estou acrescento um arquivo chamado portDict.json temporariamente!! Isso para nao precisar logar no hostapd

2 - Mapeamento estatico da rede para as regras iniciais do switch (EVENTO HANDLE SWITCH)
'''

arq_temporario = 'portDict.json'

#Ultima posicao do vetor representa a saida padrao
MAPEAMENTO_ESTATICO_REDE = {
                            1: [('00:00:00:00:00:01', 1), ('00:00:00:00:00:02', 2), 3],
                            2: [('00:00:00:00:00:03', 1), ('00:00:00:00:00:04', 2), 3],
                            3: [('00:00:00:00:00:10', 1), ('00:00:00:00:00:11', 2),('00:00:00:00:00:12',3), ],
                           }


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {1: {'01:80:c2:00:00:03': 3},
                            2: {'01:80:c2:00:00:03': 3},
                            3: {'01:80:c2:00:00:03': 3}} # Onde esta hostapd
        self.ip_to_mac = {}
        self.portDict = {}
        self.hostapd_socket = HostapdSocket(
            self.logger, portDict=self.portDict)
        hub.spawn(self.hostapd_socket.start_socket)

    '''
    INICIO Eventos de Inicio de Topologia ou chegada de Switch
    '''
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        # Apaga regras do swithc
        [self.remove_flows(datapath, n) for n in [0, 1]]

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        #Adicionando manualmente o hosts liberados atraves do arquivo portDict.json
        with open(arq_temporario) as f:
            data = json.load(f)
        self.portDict = data
        dpid = datapath.id

        #DEBUG
        '''
        if dpid == 1:
            print(self.portDict)
        '''
        #QoS
        # Regra de QoS de acordo com a tabela passada
        time.sleep(1)
        print('')
        TABELA_IP_PORTAS = TB.tabela_ip_porta
        for regra in TABELA_IP_PORTAS:
            print(regra)
            # os.system('ovs-ofctl add-flow s1 priority=40000,dl_type=0x0800,nw_dst=' + regra[0] + ',nw_proto=17,tp_dst=' + regra[1] + ',actions=enqueue:' + regra[2] + ':' + self.filaQoS(regra[3]))
            # os.system('ovs-ofctl add-flow s1 priority=40000,dl_type=0x0800,nw_dst=' + regra[0] + ',nw_proto=6,tp_dst=' + regra[1] + ',actions=enqueue:' + regra[2] + ':' + self.filaQoS(regra[3]))
            match1 = parser.OFPMatch(eth_type=0x0800, ipv4_dst=regra[0], ip_proto=6, tcp_dst=int(regra[1]))
            actions1 = [parser.OFPActionSetQueue(int(self.filaQoS(regra[3])[0])),
                        parser.OFPActionOutput(port=regra[2])]
            self.add_flow(datapath, 40000, match1, actions1, 0, 28)
            print('QoS: ' + self.filaQoS(regra[3])[1] + ' aplica na porta: ' + regra[
                1] + ' com destino ao servidor!')

        # Tudo que for TCP envia para o controlador
        match2 = parser.OFPMatch(eth_type=0x0800, ip_proto=6)
        self.add_flow(datapath, 1000, match2, actions, 0, 29)
        print('\nEventos de Entradas Prontos!!!\n')

    '''
    FIM Eventos de Inicio de Topologia ou chegada de Switch
    '''

    '''
    Funcao de de Adicionar Regras
    '''
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, numero=0):
        print('Numero DEBUG: '+ str(numero))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if idle_timeout == 0:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
    '''
    Funcao de de Adicionar Regras
    '''



    '''
    def add_flow(self, datapath, priority, match, actions, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        datapath.send_msg(mod)
    '''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Pega o id para saber o switch Openflow
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        # Obtem o numero da porta recebida da mensagem packet_in.
        in_port = msg.match['in_port']

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src = eth_pkt.src
        dst = eth_pkt.dst


        #print(self.portDict)

        if eth_pkt.ethertype == ETH_TYPE_8021x or src in self.portDict:

            #print("Liberando o host: ", src)
            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            # se o endereço MAC de destino já tiver sido aprendido,
            # decida qual porta enviar o pacote, caso contrário, FLOOD.
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            # lista de acoes de construcao de regra.
            actions = [parser.OFPActionOutput(out_port)]

            # Tipos de pacotes
            pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
            pkt_arp = pkt.get_protocol(arp.arp)
            pkt_icmp = pkt.get_protocol(icmp.icmp)
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            pkt_udp = pkt.get_protocol(udp.udp)
            pkt_tcp = pkt.get_protocol(tcp.tcp)

            if pkt_arp:  # arrumar a funcao
                # aprende o ip e o mac
                self.ip_to_mac[dpid][pkt_arp.src_ip] = [pkt_arp.src_mac,
                                                        in_port]  # Ex: {1: {'10.0.0.7': ['00:00:00:00:00:07', 7], '10.0.0.1': ['00:00:00:00:00:01', 1]}}
                # print(self.ip_to_mac) #DEBUG
                if pkt_arp.opcode == 1:  # Arp Request
                    # print('\nArp Request de ' + pkt_arp.src_ip + ' para ' + pkt_arp.dst_ip + '\n') #DEBUG
                    if dpid in self.ip_to_mac:  # Verifica se ja existe informacao do switch em questao
                        if pkt_arp.dst_ip in self.ip_to_mac[
                            dpid]:  # Se conhece o mac da maquina responde. Se nao, inunda a rede para descobrir
                            self.arp_reply(datapath, in_port, eth_pkt, pkt_arp, dpid)  # Responde o ARP
                            # print('\nResponde o arp \n') #DEBUG
                            return
                        else:  # Inunda a rede
                            # print('\nExiste o dpid, mas nao possui o mac destino ARP!\n') #DEBUG
                            src_mac = src
                            src_ip = pkt_arp.src_ip
                            dst_ip = pkt_arp.dst_ip
                            self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                        'arp_1')
                    else:  # Nao existe, entao vamos coletar
                        # print('\nNao existe o dpid\n') #DEBUG
                        src_mac = src
                        src_ip = pkt_arp.src_ip
                        dst_ip = pkt_arp.dst_ip
                        self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                    'arp_2')

                elif pkt_arp.opcode == 2:  # Arp Reply
                    pass
                    # print('\nArp Reply de ' + pkt_arp.src_ip + ' para ' + pkt_arp.dst_ip + '\n') #DEBUG
                else:
                    pass
            if pkt_ipv4: #Indo para os servidores
                vetor_portas_servidor = []
                for i in TB.tabela_ip_porta:
                    vetor_portas_servidor.append(int(i[1])) # Pega a posicao das portas da tabela
                if pkt_tcp in vetor_portas_servidor:
                    ofp = datapath.ofproto
                    match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=pkt_ipv4.src,
                                            ipv4_dst=pkt_ipv4.dst,
                                            ip_proto=6, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
                    # Caso nao conheca os mac, entao procuro
                    if dpid in self.mac_to_port:
                        # print('\nExiste o dpid\n') #DEBUG
                        if pkt_ipv4.dst in self.ip_to_mac[dpid]:
                            '''
                            Fazer a verificacao do usuario e o destino 
                            Aqui ficara toda logica de regras (TCP)
                            Politica de acesso
                            '''
                            if pkt_ipv4.src in TB.ips_servidores:
                                lista_regras_ip_servidor = []
                                # Pega todas as regras pertecentes aquele ip
                                for i in range(0, len(TB.tabela_ip_porta)):
                                    if  TB.tabela_ip_porta[0][i] == pkt_ipv4.src: # Servidor Origem
                                        lista_regras_ip_servidor.append(TB.tabela_ip_porta[i])
                                # Aplica as regras
                                for regra in lista_regras_ip_servidor:
                                    match1 = parser.OFPMatch(eth_type=0x0800, ipv4_dst=regra[0], ip_proto=6,
                                                             tcp_dst=int(regra[1]))
                                    actions1 = [parser.OFPActionSetQueue(int(self.filaQoS(regra[3])[0])),
                                                parser.OFPActionOutput(port=out_port)]
                                    self.add_flow(datapath, 40000, match1, actions1, 0, 28)
                                    print('QoS: ' + self.filaQoS(regra[3])[1] + ' aplica na porta: ' + regra[
                                        1] + ' com destino ao servidor!')



                            #for regra in TB.tabela_ip_porta:
                            #    if int(regra[1]) == pkt_tcp.src_port:
                            #        qos = self.filaQoS(regra[3])
                            #        actions = [parser.OFPActionSetQueue(int(qos[0])), parser.OFPActionOutput(
                            #            port=self.mac_to_port[dpid][dst])]
                            #        self.add_flow(datapath, 1005, match, actions, 30, 27)
                            #        print('\nAdicionado a regra TCP com QoS')
                            #        print('Tudo que for de ' + str(pkt_ipv4.src) + ' para ' + str(
                            #            pkt_ipv4.dst) + ' na porta ' + str(
                            #            pkt_tcp.dst_port) + ' enqueue ' + qos[1])
                            #        print('')
                            #        break
                            return
                            '''
                            FIM das Regras de verificacao
                            '''





                        else:
                            # print('\nMAC: '+str(dst)+' nao encontrado na lista...\nProcurando o MAC...\n') #DEBUG
                            src_mac = src
                            src_ip = pkt_ipv4.src
                            dst_ip = pkt_ipv4.dst
                            self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                        'tcp_1')
                    else:
                        src_mac = src
                        src_ip = pkt_ipv4.src
                        dst_ip = pkt_ipv4.dst
                        self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                    'tcp_2')
                        return


                else: # Pacote sem QoS. Cai na fila Zero (0)
                    if dpid in self.mac_to_port:  # Existe o switch na tabela
                        print(pkt_ipv4, 'Toaqui!!!\n')
                        if pkt_ipv4.dst in self.ip_to_mac[dpid]:
                            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=pkt_ipv4.src,
                                                    ipv4_dst=pkt_ipv4.dst,
                                                    ip_proto=6, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
                            actions = [parser.OFPActionOutput(port=self.mac_to_port[dpid][dst])]
                            self.add_flow(datapath, 1005, match, actions, 30, 27)
                            print('\nRegra comum aplicada!!\nTudo que for de ' + str(src) + ' para ' + str(
                                dst) + ' sai na porta ' + str(out_port) + '\n')
                        else:
                            src_mac = src
                            src_ip = pkt_ipv4.src
                            dst_ip = pkt_ipv4.dst
                            self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                        'tcp_2')
                    else:
                        src_mac = src
                        src_ip = pkt_ipv4.src
                        dst_ip = pkt_ipv4.dst
                        self.envia_pkt_broadcasting(datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip,
                                                    'tcp_3')
            # Serve para demais regras que nao sao tcp
            # instala um fluxo no switch para evitar o packet_in na proxima vez
            if pkt_udp or pkt_icmp:
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                    self.add_flow(datapath, 1, match, actions, 30)
                    print('\nRegra comum aplicada!!\nTudo que for de ' + str(src) + ' para ' + str(
                        dst) + ' sai na porta  ' + str(
                        out_port) + '\n')


            '''
            # construct action list.
            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time.
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, eth_type=eth_pkt.ethertype)
                self.add_flow(datapath, 2, match, actions)

            # construct packet_out message and send it.
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions,
                data=msg.data)
            datapath.send_msg(out)
        else:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_type=eth_pkt.ethertype)
            self.add_flow(datapath, 1, match, [], 1)  # drop
        '''

    '''
    Fila requerida para QoS
    '''

    def filaQoS(self, nome):
        # Acha qual fila eh a QoS pedida
        # Carregamento da lista de objetos Classe
        classlist = []
        if os.path.isfile(filename):
            filec = open(filename, 'rb')
            classlist = pickle.load(filec)
            filec.close()
        fila_saida = '0'  # Fila a ser aplicada
        nome_fila = ''
        for c in classlist:
            if c.nome == nome:
                fila_saida = c.id
                nome_fila = c.nome
        # print('Fila saida: ' + str(fila_saida))
        return [str(fila_saida), nome_fila]

    '''
    FIM Fila requerida para QoS
    '''

    '''
    Pacote Broadcasting
    '''
    def envia_pkt_broadcasting(self, datapath, parser, ofproto, in_port, src_mac, src_ip, dst_ip, debug_proto=''):
        # print(debug_proto) #DEBUG
        e = ethernet.ethernet(dst=BROADCAST_MAC,
                              src=src_mac,
                              ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x800, hlen=6, plen=4, opcode=1,
                    src_mac=src_mac, src_ip=src_ip,
                    dst_mac=ZERO_MAC, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions4 = [parser.OFPActionOutput(ofproto.OFPP_FLOOD, 0)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions4,
                                  data=p.data)
        datapath.send_msg(out)
        # print('\nInunda a rede \n') #DEBUG

    '''
    FIM Pacote Broadcasting
    '''

    '''
    Arp Reply
    '''
    def arp_reply(self, datapath, in_port, eth_pkt, arp_pkt, dpid):
        # Browse Target hardware adress from ip_to_mac table.
        target_hw_addr = self.ip_to_mac[dpid][arp_pkt.dst_ip][0]
        target_ip_addr = arp_pkt.dst_ip

        pkt = packet.Packet()
        # Create ethernet packet
        pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                           dst=eth_pkt.src,
                                           src=target_hw_addr))
        # Create ARP Reply packet
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=target_hw_addr,
                                 src_ip=target_ip_addr,
                                 dst_mac=arp_pkt.src_mac,
                                 dst_ip=arp_pkt.src_ip))

        self._send_packet(datapath, in_port, pkt)

    '''
    FIM Arp Reply
    '''

    '''
    Apaga Regras Swithc
    '''
    def remove_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                           empty_match, instructions)
        # print "deleting all flow entries in table ", table_id
        datapath.send_msg(flow_mod)

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
    '''
    FIM Apaga Regras Swithc
    '''

    '''
    Envia Pacote para Host
    '''

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    '''
    FIM Envia Pacote para Host
    '''