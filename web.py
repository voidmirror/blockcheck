from flask import Flask, render_template, request, json
import sys

import blockcheck

app = Flask(__name__)
dnsv4 = 0
dnsv6 = 0
http_v4 = 0
http_v6 = 0
https = 0


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/start', methods=['GET'])
def button_clicked():
    print("BUTTON CLICK!")
    blockcheck.main()
    msg = "Для получения корректных результатов используйте DNS-сервер провайдера и отключите средства обхода блокировок."
    return json.dumps({'msg': msg})


@app.route('/get-ip', methods=['GET'])
def get_ip_and_isp():
    ip_isp = blockcheck.get_ip_and_isp()
    msg = ''
    if ip_isp:
        msg = "IP: {}, провайдер: {}".format(blockcheck.mask_ip(ip_isp[0]), ip_isp[1])
    return json.dumps({'msg': msg})


@app.route('/dns', methods=['GET'])
def dns():
    global dnsv4
    dnsv4 = blockcheck.test_dns(blockcheck.DNS_IPV4)
    global dnsv6
    dnsv6 = 0
    if blockcheck.ipv6_available:
        dnsv6 = blockcheck.test_dns(blockcheck.DNS_IPV6)
    result_msg = ""
    if dnsv4 == 5:
        result_msg = "[⚠] Не удалось определить способ блокировки IPv4 DNS Если вы используете DNS провайдера, возможно, ответы DNS модифицирует вышестоящий провайдер.\nВам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, HTTPS/Socks прокси или DNSCrypt."
    elif dnsv4 == 4:
        result_msg = "[⚠] Ваш провайдер блокирует сторонние IPv4 DNS-серверы.\n" + \
                     "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
                     "HTTPS/Socks прокси или DNSCrypt."
    elif dnsv4 == 3:
        result_msg = "[⚠] Ваш провайдер подменяет DNS-записи, но не перенаправляет сторонние IPv4 DNS-серверы на свой.\n" + \
                     "Вам поможет смена DNS, например, на Яндекс.DNS 77.88.8.8 или Google DNS 8.8.8.8 и 8.8.4.4."
    elif dnsv4 == 2:
        result_msg = "[⚠] Ваш провайдер подменяет DNS-записи и перенаправляет сторонние IPv4 DNS-серверы на свой.\n" + \
                     "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
                     "HTTPS/Socks прокси или DNSCrypt."
    elif dnsv4 == 1:
        result_msg = "[⚠] Ваш провайдер перенаправляет сторонние IPv4 DNS-серверы на свой, но не подменяет DNS-записи.\n" + \
                     "Это несколько странно и часто встречается в мобильных сетях.\n" + \
                     "Если вы хотите использовать сторонний DNS, вам следует использовать шифрованный канал до " + \
                     "DNS-серверов, например, через VPN, Tor, HTTPS/Socks прокси или DNSCrypt, но обходу " + \
                     "блокировок это не поможет."
    elif dnsv4 == 0:
        result_msg = "[✓] DNS-записи не подменяются \n[✓] DNS не перенаправляется"

    if blockcheck.ipv6_available:
        if dnsv6 == 5:
            result_msg += "[⚠] Не удалось определить способ блокировки IPv6 DNS.\n" + \
                          "Верните настройки DNS провайдера, если вы используете сторонний DNS-сервер." + \
                          "Если вы используете DNS провайдера, возможно, ответы DNS модифицирует вышестоящий" + \
                          "провайдер.\n" + \
                          "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
                          "HTTPS/Socks прокси или DNSCrypt."
        elif dnsv6 == 4:
            result_msg += "[⚠] Ваш провайдер блокирует сторонние IPv6 DNS-серверы.\n" + \
                          "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
                          "HTTPS/Socks прокси или DNSCrypt."
        elif dnsv6 == 3:
            result_msg += "[⚠] Ваш провайдер подменяет DNS-записи, но не перенаправляет сторонние IPv6 DNS-серверы на свой.\n" + \
                          "Вам поможет смена DNS, например, на Яндекс.DNS 2a02:6b8::feed:0ff или Google DNS 2001:4860:4860::8888."
        elif dnsv6 == 2:
            result_msg += "[⚠] Ваш провайдер подменяет DNS-записи и перенаправляет сторонние IPv6 DNS-серверы на свой.\n" + \
                          "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
                          "HTTPS/Socks прокси или DNSCrypt."
        elif dnsv6 == 1:
            result_msg += "[⚠] Ваш провайдер перенаправляет сторонние IPv6 DNS-серверы на свой, но не подменяет DNS-записи.\n" + \
                          "Это несколько странно и часто встречается в мобильных сетях.\n" + \
                          "Если вы хотите использовать сторонний DNS, вам следует использовать шифрованный канал до " + \
                          "DNS-серверов, например, через VPN, Tor, HTTPS/Socks прокси или DNSCrypt, но обходу " + \
                          "блокировок это не поможет."
    return json.dumps({'msg': result_msg})


@app.route('/https', methods=['GET'])
def https_check():
    global https
    https = blockcheck.test_https_cert()
    result_msg = ""

    if https == 1:
        result_msg = "[⚠] Ваш провайдер подменяет HTTPS-сертификат на свой для сайтов из реестра."
    elif https == 2:
        result_msg = "[⚠] Ваш провайдер полностью блокирует доступ к HTTPS-сайтам из реестра."
    elif https == 3:
        result_msg = "[⚠] Доступ по HTTPS проверить не удалось, повторите тест позже."
    elif https == 0:
        result_msg = "[✓] Доступ по HTTPS не блокируется."

    return json.dumps({'msg': result_msg})


@app.route('/http', methods=['GET'])
def http_check():
    global http_v4
    global http_v6
    http_v4, http_v6, http_isup, subdomain_blocked = blockcheck.test_http_access((dnsv4 != 0) or (dnsv6 != 0))
    subdomain_msg = "[✓] Ваш провайдер не блокирует поддомены у заблокированного домена."
    if subdomain_blocked:
        subdomain_msg = "[⚠] Ваш провайдер блокирует поддомены у заблокированного домена."
    http_isup_msg = "Все проверяемые сайты работают согласно {}".format(blockcheck.isup_server)
    if http_isup == blockcheck.HTTP_ISUP_BROKEN:
        http_isup_msg = "[⚠] {0} даёт неожиданные ответы или недоступен. Рекомендуем " \
                        "повторить тест, когда он начнёт работать. Возможно, эта " \
                        "версия программы устарела. Возможно (но маловероятно), " \
                        "что сам {0} уже занесён в чёрный список.".format(blockcheck.isup_server)
    elif http_isup == blockcheck.HTTP_ISUP_ALLDOWN:
        http_isup_msg = "[⚠] Согласно {}, все проверяемые сайты сейчас не работают. " \
                        "Убедитесь, что вы используете последнюю версию программы, и " \
                        "повторите тест позже.".format(blockcheck.isup_server)
    elif http_isup == blockcheck.HTTP_ISUP_SOMEDOWN:
        http_isup_msg = "[⚠] Согласно {}, часть проверяемых сайтов сейчас не работает. " \
                        "Убедитесь, что вы используете последнюю версию программы, и " \
                        "повторите тест позже.".format(blockcheck.isup_server)
    elif http_isup != blockcheck.HTTP_ISUP_ALLUP:
        http_isup_msg = "[⚠] ВНУТРЕННЯЯ ОШИБКА ПРОГРАММЫ, http_isup = {}".format(blockcheck.http_isup)

    def get_http_result(symbol, message):
        if http_isup == blockcheck.HTTP_ISUP_ALLUP:
            return "{} {}".format(symbol, message)
        else:
            return "{} Если проигнорировать {}, то {}".format(symbol, blockcheck.isup_server,
                                                              message[0].lower() + message[1:])

    http_result = ""
    if http_v4 == blockcheck.HTTP_ACCESS_IPBLOCK:
        if (blockcheck.ipv6_available and http_v6 == blockcheck.HTTP_ACCESS_IPBLOCK) or not blockcheck.ipv6_available:
            http_result = get_http_result("[⚠]", "Ваш провайдер блокирует по IP-адресу. " \
                                                 "Используйте любой способ обхода блокировок.")
        elif blockcheck.ipv6_available and http_v6 != blockcheck.HTTP_ACCESS_IPBLOCK:
            http_result = get_http_result("[⚠]", "Ваш провайдер блокирует IPv4-сайты по IP-адресу. " \
                                     "Используйте любой способ обхода блокировок.")
    elif http_v4 == blockcheck.HTTP_ACCESS_FULLDPI:
        if (blockcheck.ipv6_available and http_v6 == blockcheck.HTTP_ACCESS_FULLDPI) or not blockcheck.ipv6_available:
            http_result = get_http_result("[⚠]", "У вашего провайдера \"полный\" DPI. Он " \
                                     "отслеживает ссылки даже внутри прокси, " \
                                     "поэтому вам следует использовать любое " \
                                     "шифрованное соединение, например, " \
                                     "VPN или Tor.")
        elif blockcheck.ipv6_available and http_v6 != blockcheck.HTTP_ACCESS_FULLDPI:
            http_result = get_http_result("[⚠]", "У вашего провайдера \"полный\" DPI для IPv4. Он " \
                                     "отслеживает ссылки даже внутри прокси, " \
                                     "поэтому вам следует использовать любое " \
                                     "шифрованное соединение, например, " \
                                     "VPN или Tor.")
    elif http_v4 == blockcheck.HTTP_ACCESS_IPDPI:
        if (blockcheck.ipv6_available and http_v6 == blockcheck.HTTP_ACCESS_IPDPI) or not blockcheck.ipv6_available:
            http_result = get_http_result("[⚠]", "У вашего провайдера \"обычный\" DPI. " \
                                     "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
        elif blockcheck.ipv6_available and http_v6 != blockcheck.HTTP_ACCESS_IPDPI:
            http_result = get_http_result("[⚠]", "У вашего провайдера \"обычный\" DPI для IPv4. " \
                                     "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
    elif http_isup == blockcheck.HTTP_ISUP_ALLUP and http_v4 == blockcheck.HTTP_ACCESS_NOBLOCKS \
            and https == 0:
        http_result = get_http_result("[☺]", "Ваш провайдер не блокирует сайты.")

    return json.dumps({
        'subdomain': subdomain_msg,
        'http_isup': http_isup_msg,
        'http': http_result
    })


@app.route('/dpi', methods=['GET'])
def dpi_check():
    if http_v4 > 0 or http_v6 > 0 or blockcheck.force_dpi_check:
        dpi = blockcheck.test_dpi()
        print(dpi)
        return json.dumps({'msg': dpi})


def run_app():
    app.debug = True
    app.config['JSON_AS_ASCII'] = False
    app.run()


if __name__ == "__main__":
    blockcheck.setup_args()
    run_app()
