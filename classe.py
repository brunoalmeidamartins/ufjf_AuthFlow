#Define uma classe de servico - Versao 7.0
class Classe:
    def __init__(self,id,nome,media,pico):
        self.id=id
        self.nome=nome
        self.media=media
        self.pico=pico

    def imprime(self):
        print('\nID:',self.id)
        print('Nome:',self.nome)
        print('Taxa media:',self.media)
        print('Taxa de pico:',self.pico)

