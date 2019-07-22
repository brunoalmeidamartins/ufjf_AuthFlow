ips_servidores = ['10.0.0.10', '10.0.0.12']
info_servidores = {
                            ips_servidores[0]:'00:00:00:00:00:10',
                            ips_servidores[1]:'00:00:00:00:00:12',
                         }
portas_servidores = [('"s3-eth1"',),( '"s3-eth2"')]

#ip_mac_servidor = [ip_servidor, mac_placa_servidor]
#mac_servidor = [mac_placa_servidor, porta_servidor]

tabela_ip_porta = [
                   [ips_servidores[0], '2002', portas_servidores[0], 'Classe10Mb'],
                   [ips_servidores[1], '2002', portas_servidores[1], 'Classe5Mb']
                  ]
#tabela_ip_servidores = [ip_servidor, porta_servidor]

usuarios_prioritarios = ['bob']