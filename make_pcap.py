import scapy.all as scapy

name = input("Введите название файла для записи/дозаписи(если существует): ")
pktdump = scapy.PcapWriter(name, append=True, sync=True)
inter = input("Введите название интерфейса для записи: ")
print('Нажмите Ctrl+C для завершения записи...')
try:
    scapy.sniff(iface=inter, prn=lambda x: pktdump.write(x))
except KeyboardInterrupt:
    pktdump.close()
except OSError as e:
    if e.errno == 19:
        print("Ошибка: Указанный интерфейс не найден. Проверьте название интерфейса и попробуйте снова.")
    else:
        print(f"Необработанная ошибка: {e}")
except Exception as e:
    print(f"Неизвестная ошибка: {e}")
