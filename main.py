import click
import os
import scapy.all as scapy
import sys
import json
import yara
import matplotlib.pyplot
import shutil

def check_path(path):
    return (os.path.exists(path.split('/')[:-1]) or os.path.exists(path.split('\\')[:-1])) and os.access(path.split('/')[:-1], os.F_OK)
 
_ROOT = os.path.abspath(os.path.dirname(__file__))
def list_packets(cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    for i in range(len(cap)):
        term_size = os.get_terminal_size()
        print('=' * (term_size.columns // 2 - len(str(i))//2-4) + "Packet: " + str(i) + '=' * (term_size.columns // 2 -(len(str(i))+1)//2-4) + '=' * (term_size.columns % 2 and len(str(i))%2))
        cap[i].show()  
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def list_short_packets(cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    for i in cap:
        print(i)
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def print_packet(packet, cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    cap[packet].show()
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def display_length_graph(cap, extract):
    print('Для продолжения закройте график...')
    lengths = [len(packet) for packet in cap]
    res = matplotlib.pyplot.hist(lengths, bins=50)
    matplotlib.pyplot.xlabel("Длина пакетов")
    matplotlib.pyplot.ylabel("Количество пакетов")
    matplotlib.pyplot.legend(["Длина пакетов"])
    if extract:
        matplotlib.pyplot.savefig(extract)
    else:
        matplotlib.pyplot.show()


def display_communication_map(cap, extract):
    if extract:
        res = cap.conversations('')
    else:
        res = cap.conversations()

def display_communication(filename, extract, protocol = ''):
    PROTOCOLS = ['bluetooth', 'eth', 'ip', 'ipv6', 'tcp', 'udp', 'usb', 'wlan', 'fc', 'fddi', 'ipx', 'jxta', 'ncp', 'sctp', 'rstp']
    out = ''
    if protocol == '':
        while True:
            choose = input("""Выберете протокол(все протоколы доступны при помощи ручной активации через autoshark -c):
1) Bluetooth
2) Ethernet
3) IPv4
4) IPv6
5) TCP
6) UDP
7) USB
8) Wlan(IEEE 802.11)
>""")[0]
            if choose.isdigit() and int(choose) in range(1, 9):
                out = os.popen(f"tshark -r {filename} -z conv,{PROTOCOLS[int(choose)-1]}").read()
                break
            else:
                print("Пожалуйста, выберете правильный вариант ответа!")
    else:
        if protocol in PROTOCOLS:
            out = os.popen(f"tshark -r {filename} -z conv,{protocol}").read()
        else:
            print("Неверный протокол")
    out = out.split("=")
    new_out = [] 
    for i in out:
        if i != '' and i != '\n':
            new_out.append(i)
    out = new_out[:]
    if extract:
        sys.stdout = open(extract, 'w') 
    print(out[1])
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def extract_files(file):
    filename = file.split('/')[-1]
    while True:
        choose = input("""Выберете формат экспорта:
1) В одну папку
2) В папки, разделённые по протоколам
> """)[0]
        if os.path.exists(f"{filename}_extracted"):
            shutil.rmtree(f'{filename}_extracted')
        os.mkdir(f"{filename}_extracted")
        if choose == '1':
            os.popen(f'tshark -r {file} --export-objects "smb,{filename}_extracted/"')
            os.popen(f'tshark -r {file} --export-objects "dicom,{filename}_extracted/"')
            os.popen(f'tshark -r {file} --export-objects "ftp-data,{filename}_extracted/"')
            os.popen(f'tshark -r {file} --export-objects "tftp,{filename}_extracted/"')
            os.popen(f'tshark -r {file} --export-objects "imf,{filename}_extracted/"')
            os.popen(f'tshark -r {file} --export-objects "http,{filename}_extracted/"')
            break
        elif choose == '2':
            os.mkdir(f"{filename}_extracted/smb/")
            os.mkdir(f"{filename}_extracted/dicom/")
            os.mkdir(f"{filename}_extracted/ftp-data/")
            os.mkdir(f"{filename}_extracted/tftp/")
            os.mkdir(f"{filename}_extracted/imf/")
            os.mkdir(f"{filename}_extracted/http/")
            os.popen(f'tshark -r {file} --export-objects "smb,{filename}_extracted/smb/"')
            os.popen(f'tshark -r {file} --export-objects "dicom,{filename}_extracted/dicom/"')
            os.popen(f'tshark -r {file} --export-objects "ftp-data,{filename}_extracted/ftp-data/"')
            os.popen(f'tshark -r {file} --export-objects "tftp,{filename}_extracted/tftp/"')
            os.popen(f'tshark -r {file} --export-objects "imf,{filename}_extracted/imf/"')
            os.popen(f'tshark -r {file} --export-objects "http,{filename}_extracted/http/"')
            break
        else:
            print("Пожалуйста, выберете правильный вариант ответа!")
    print(f"Файлы успешно экспортированы в папку {filename}_extracted")

def filterfunc(filter, extract, file):
    if extract:
        sys.stdout = open(extract, 'w') 
    print(os.popen(f'tshark -r {file} -Y "{filter}"').read())
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def endpointsfunc(filename, extract, protocol=''):
    PROTOCOLS = ['bluetooth', 'eth', 'ipv4', 'ipv6', 'tcp', 'udp', 'usb', 'wlan', 'fc', 'fddi', 'ipx', 'jxta', 'ncp', 'sctp', 'rstp']
    out = ''
    if protocol == '':
        while True:
            choose = input("""Выберете протокол(все протоколы доступны при помощи ручной активации через autoshark -c):
1) Bluetooth
2) Ethernet
3) IPv4
4) IPv6
5) TCP
6) UDP
7) USB
8) Wlan(IEEE 802.11)
>""")[0]
            if choose.isdigit() and int(choose) in range(1, 9):
                out = os.popen(f"tshark -r {filename} -z endpoints,{PROTOCOLS[int(choose)-1]}").read()
                break
            else:
                print("Пожалуйста, выберете правильный вариант ответа!")
    else:
        if protocol in PROTOCOLS:
            out = os.popen(f"tshark -r {filename} -z endpoints,{protocol}").read()
        else:
            print("Неверный протокол")
    out = out.split("=")
    new_out = [] 
    for i in out:
        if i != '' and i != '\n':
            new_out.append(i)
    out = new_out[:]
    if extract:
        sys.stdout = open(extract, 'w') 
    print(out[1])
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

def streamsfunc(filename, extract, streams = ''):
    streamsl = []
    if streams == '':
        while True:
            streams = input("""Введите протокол, тип вывода и номер начального потока через запятую без пробелов:
Протоколы:
dccp, http, http2, quic, sip, tcp, tls, udp, websocket

Типы вывода:
hex, ascii, ebcdic, raw

> """)
            streamsl = streams.split(',')
            if len(streamsl) == 3:
                if streamsl[0] in ['dccp', 'http', 'http2', 'quic', 'sip', 'tcp', 'tls', 'udp', 'websocket']:
                    if streamsl[1] in ['hex', 'ascii', 'ebcdic', 'raw']:
                        if streamsl[2].isdigit():
                            break
                        else:
                            print('Номер начального пакета не является числом')
                    else:
                        print('Неправильный тип вывода')
                else:
                    print('Неправильный протокол')
            else:
                print('Неверное количество элементов(3).')
    
    else:
        if len(streamsl) == 3:
            if streamsl[0] in ['dccp', 'http', 'http2', 'quic', 'sip', 'tcp', 'tls', 'udp', 'websocket']:
                if streamsl[1] in ['hex', 'ascii', 'ebcdic', 'raw']:
                    if streamsl[2].isdigit():
                        pass
                    else:
                        print('Номер начального пакета не является числом')
                else:
                    print('Неправильный тип вывода')
            else:
                print('Неправильный протокол')
        else:
            print('Неверное количество элементов(3).')
    while True:
        out = os.popen(f'tshark -r {filename} -z "follow,{",".join(streamsl)}"').read()
        out = out.split("=")
        new_out = [] 
        for i in out:
            if i != '' and i != '\n':
                new_out.append(i)
        out = new_out[:]
        if out[-1].split('\n')[-3:] == ['Node 0: :0', 'Node 1: :0', '']:
            print('Нечего не найдено')
        else:
            print(out[-1])
        print(f'Поток номер {streamsl[2]}')
        choose = ''
        if extract:
            choose = input("""Выберете действие:
1) Следуйщий поток
2) Предидущий поток
3) Перейти на другой поток
4) Сохранить в файл
q) Выйти
""")[0]
        else:                    
            choose = input("""Выберете действие:
1) Следуйщий поток
2) Предидущий поток
3) Перейти на другой поток
q) Выйти
""")[0]
        if choose == '1':
            streamsl[2] = str(int(streamsl[2])+1)
        elif choose == '2':
            if streamsl[2] == '0':
                print('Предидущего пакета несуществует')
            streamsl[2] = str(int(streamsl[2])-1)
        elif choose == '3':
            stream = input("Введите номер пакета: ")
            if not stream.isdigit():
                print('Неправильный номер пакета')
                continue
            streamsl[2] = stream
        elif choose == '4' and extract:
            sys.stdout = open(extract, 'w') 
            print(out[1])
            sys.stdout.close()
            sys.stdout = sys.__stdout__
        elif choose.lower() == 'q':
            break

def autoanalyzefunc(filename, extract, path):
    yara_rules = yara.compile(path)
    if extract:
        sys.stdout = open(extract, 'w') 
    print("Найдены следуйшие правила", *yara_rules.match(filename))
    if extract:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

class interface:
    def __init__(self, name, yara_rules, extract):
        self.name = name
        self.yara = yara.compile(yara_rules)
        self.i = 0
        self.extract = extract

    def check_yara(self, packet):
        print(self.i)
        file = scapy.PcapWriter(f'tmp_{self.name}_autoshark')
        file.write(packet)
        if self.yara.match(f'tmp_{self.name}_autoshark'):
            if self.extract:
                sys.stdout = open(self.extract, 'w+') 
                print(f'Обнаружены правила {self.yara.match(f"tmp_{self.name}_autoshark")} в пакете {self.i}')
                sys.stdout.close()
                sys.stdout = sys.__stdout__
            else:
                print(f'Обнаружены правила {self.yara.match(f"tmp_{self.name}_autoshark")} в пакете {self.i}')
        self.i += 1
    
    def sniff(self):
        print(f'Сбор пакетов с интерфейса {self.name}')
        try:
            scapy.sniff(iface=self.name, prn=lambda x: self.check_yara(x))
        except KeyboardInterrupt:
            pass
        except OSError as e:
            if e.errno == 19: 
                print("Ошибка: Указанный интерфейс не найден. Проверьте название интерфейса и попробуйте снова.")

def interfacefunc(yara_rules, extract, interface_name):
    if not os.path.isdir(f'tmp_{interface_name}_autoshark') and not os.path.isfile(f'tmp_{interface_name}_autoshark') or (os.access(f'tmp_{interface_name}_autoshark', os.W_OK) and os.access(f'tmp_{interface_name}_autoshark', os.R_OK)):
        interface_obj = interface(interface_name, yara_rules, extract)
        interface_obj.sniff()
        os.remove(f'tmp_{interface_name}_autoshark')
    else:
        print(f"Ошибка доступа к файлу tmp_{interface_name}_autoshark. Этот файл нужен для промежуточного хранения пакетов. Выдайте доступ к этому файлу на чтение и запись для работы программы")

@click.command()
@click.help_option('-h', '--help', help='Показывает эту документацию.')
@click.option('-l', '--list', is_flag=True, help='Печатает на экран всю информацию обо пакетах.')
@click.option('-s', '--short-list', is_flag=True, help='Печатает на экран краткую информацию обо всех пакетах.')
@click.option('-p', '--packet', type=int, help='Выводит всю информацию о выбранном пакете. Список протоколов совпадает с списком из tshark.')
@click.option('--len-graph', is_flag=True, help='Открывает окно с графиком по длине пакетов.')
@click.option('--conversations-graph', is_flag=True, help='Открывает окно с картой по общению между адресами')
@click.option('-c', '--conversations', type=str, help='Выводит статистику об общении между адресами в выбранном протоколе. Список протоколов совпадает с списком из tshark.')
@click.option('--endpoints', type=str, help='Показывает статистику о конечных адресатах в выбранном протоколе. Список протоколов совпадает с списком из tshark.')
@click.option('-f', '--files', is_flag=True, help='Экспортирует все файлы в дампе, передоваемые в открытом виде. Список протоколов совпадает с списком из tshark.')
@click.option('--streams', type=int, help='Показывает потоки пакетов по указаному протоколу и позволяет интерактивно их листать. Список протоколов и типов вывода совпадает с списком из tshark.')
@click.option('--filter', type=str, help='Фильтрует пакеты по указанному фильтру.')
@click.option('-a', '--autoanalyze', type=click.Path(exists=True), help='Автоматический анализ при помощи правил yara из выбранного файла.')
#@click.option('-i', '--interface', type=(click.Path(exists=True) ,str), nargs=2, help='')
@click.option('-e', '--extract', type=click.Path(), help='Экпортирует вывод/фото в указанный файл, перезаписывая его.')
@click.argument('file', type=click.Path(exists=True), metavar='Путь к файлу для анализа. Если используется режим интерфейса, то оставить пустым', required=False)
def main(file, list, short_list, extract, len_graph, conversations_graph, conversations, autoanalyze, packet, files, filter, endpoints, streams):
    interface = False
    if extract:
        if '/' in extract or '\\' in extract:
            if check_path(extract):
                print("Нет доступа к директории для экспорта")
                return
        if os.path.exists(extract):
            try:
                open(extract, 'w')
            except:
                print("Файл для экспорта уже существует и не доступен для записи")
                return
    if not file and not interface:
        print("Файл не выбран")
        return
    elif file:
        print("Считываем файл")
        try:
            cap = scapy.rdpcap(file)
        except scapy.error.Scapy_Exception:
            print("Ошибка при чтении файла. Убедитесь что файл является дампом сетевого трафика")
            return
        print(f"Считано {len(cap)} пакетов")
    if not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        cli(extract, cap, file)
    elif list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        list_packets(cap, extract)
    elif short_list and not list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        list_short_packets(cap, extract)
    elif len_graph and not list and not short_list and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        display_length_graph(cap, extract)
    elif conversations_graph and not list and not short_list and not len_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        display_communication_map(cap, extract)
    elif conversations and not list and not short_list and not len_graph and not conversations_graph and not autoanalyze and not files and not packet and not endpoints and not filter and not streams and not interface:
        display_communication(file, extract, conversations)
    elif autoanalyze and not list and not short_list and not len_graph and not conversations_graph and not conversations and not files and not packet and not endpoints and not filter and not streams and not interface:
        autoanalyzefunc(file, extract, autoanalyze)
    elif files and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not packet and not endpoints and not filter and not streams and not interface:
        extract_files(file)
    elif packet and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not endpoints and not filter and not streams and not interface:
        print_packet(packet, cap, extract)
    elif endpoints and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not filter and not streams and not interface:
        endpointsfunc(file, extract)
    elif filter and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not streams and not interface:
        filterfunc(filter, extract, file)
    elif streams and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not interface:
        streamsfunc(extract, file, streams)
    #elif interface and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyze and not files and not packet and not endpoints and not filter and not streams:
        #interfacefunc(interface[0], extract, interface[1])
    else:
        print('Выберите 1 задачу на запрос.')

def cli(extract, cap, file):
    while True:
        choose = input("""Для сохранения в файл используйте autoshark -e (файл для экспорта)
При запуске с экпортом существующий файл, он будет ПЕРЕЗАПИСАН!
Выберете действие: 
1) Вывести все пакеты
2) Вывести краткую информацию о пакетах
3) Вывести пакет
4) Вывести график по длинам пакетов (для показа требуется графический интерфейс)
5) Вывести карту по общению между адресами(для показа требуется графический интерфейс)(рекомендуется экспортировать из за возможных размеров сети)
6) Вывести общения между адресами                       
7) Извлечь все файлы из дампа
8) Применить фильтр для пакетов(для продвинутых)
9) Вывести конечных адресатов дампа 
10) Вывести потоки пакетов
a) Автоматический анализ пакетов по правилам yara
q) Выход
> """)[:2]    
        if choose == '1':
            list_packets(cap, extract)
        elif choose == '2':
            list_short_packets(cap, extract)
        elif choose == '3':
            packet = input("Введите номер пакета: ")
            if not packet.isdigit():
                print('Неправильный номер пакета')
                continue
            print_packet(packet, cap, extract)
        elif choose == '4':
            display_length_graph(cap, extract)
        elif choose == '5':
            display_communication_map(cap, extract)
        elif choose == '6':
            display_communication(file, extract)
        elif choose == '7':
            extract_files(file)
        elif choose == '8':
            filter = input("Введите фильтр для пакетов: ")
            filterfunc(filter, extract, file)
        elif choose == '9':
            endpointsfunc(file, extract)
        elif choose == '10':
            streamsfunc(file, extract)
        elif choose.lower() == 'a' or choose.lower() == 'а':
            option = input("Введите путь к файлу правил yara: ")
            autoanalyzefunc(file, extract, option)
        elif choose.lower() == 'q':
            break
        else:
            print("Неверный выбор. Пожалуйста, выберите действие из списка.")



if __name__ == '__main__':
    print("Пожалуйста установите программу для корректной работы")
try:
    with open(os.path.join(_ROOT, 'permision.txt'), 'r') as file:
        perm = json.loads(''.join(file.readlines()[3:]))
        if perm["Напишите здесь да"].lower() != "да":
            print(f"Подтвердите согласие в файле {os.path.join(_ROOT, 'permision.txt')}")
            exit(0)
except Exception as e:
    print(e)
    text = """#Это файл для подтверждения согласия на обработку дампа и отказ от ответственности за хранение результат.
#Ознакомтесь с согласием в файле agreement.txt
#Я согласен на обработку данных.
{
    "Напишите здесь да": "нет"
}"""
    try:
        os.mkdir(_ROOT)
    except:
        pass
    with open(os.path.join(_ROOT, "permision.txt"), 'w') as f:
        f.write(text)
    print(f"Произошла ошибка в чтении файла подтверждения согласия. Попробуйте подтвердить ещё раз в файле {os.path.join(_ROOT, 'permision.txt')}")
    exit(0)