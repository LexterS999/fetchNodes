import asyncio
import aiohttp
import pybase64
import base64
import requests
import binascii
import os
import re
import zipfile
import socket
import shutil
import IP2Location
import ipaddress
import concurrent.futures
from urllib.parse import urlparse, parse_qs

# Фиксированное время ожидания для HTTP-запросов (в секундах)
TIMEOUT = 30

def decode_base64(encoded):
    decoded = ""
    for encoding in ["utf-8", "iso-8859-1"]:
        try:
            decoded = pybase64.b64decode(encoded + b"=" * (-len(encoded) % 4)).decode(encoding)
            break
        except (UnicodeDecodeError, binascii.Error):
            pass
    return decoded

async def fetch_link(session, url):
    """Асинхронная загрузка ссылки и декодирование контента через base64."""
    try:
        async with session.get(url, timeout=TIMEOUT) as resp:
            content = await resp.read()
            decoded = decode_base64(content)
            return decoded
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""

async def fetch_dir_link(session, url):
    """Асинхронная загрузка ссылки директории (текстовый контент)."""
    try:
        async with session.get(url, timeout=TIMEOUT) as resp:
            text = await resp.text()
            return text
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""

async def fetch_all_links(links, dir_links):
    """Параллельная загрузка всех ссылок и директорий."""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in links:
            tasks.append(fetch_link(session, url))
        for url in dir_links:
            tasks.append(fetch_dir_link(session, url))
        results = await asyncio.gather(*tasks)
        return results

def is_valid_ipv4(host):
    """Проверка, что host является валидным IPv4-адресом (без доменных имен и IPv6)."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.version == 4
    except ValueError:
        return False

def filter_for_allowed_protocols(data, allowed_protocols):
    """
    Фильтрация записей: оставляем только те, что начинаются с разрешенных протоколов
    и у которых host является валидным IPv4-адресом.
    """
    filtered_data = []
    for entry in data:
        entry = entry.strip()
        if any(entry.startswith(proto) for proto in allowed_protocols):
            m = re.search(r'^(vless|trojan|tuic|hy2)://(?:[^@]+@)?([^:/?#]+)(?::(\d+))', entry, re.IGNORECASE)
            if m:
                host = m.group(2)
                if is_valid_ipv4(host):
                    filtered_data.append(entry)
    return filtered_data

def remove_duplicates(configs):
    """
    Удаление дубликатов по совпадению хоста и порта.
    При обнаружении дубликата оставляется запись с большей длиной.
    """
    unique = {}
    pattern = re.compile(r'^(vless|trojan|tuic|hy2)://(?:[^@]+@)?([^:/?#]+)(?::(\d+))', re.IGNORECASE)
    for config in configs:
        match = pattern.search(config)
        if match:
            host = match.group(2)
            port = match.group(3)
            key = (host, port)
            if key in unique:
                if len(config) > len(unique[key]):
                    unique[key] = config
            else:
                unique[key] = config
        else:
            unique[config] = config
    return list(unique.values())

def get_flag_emoji(country_code):
    """Преобразование кода страны в эмодзи флаг."""
    if not country_code or len(country_code) != 2:
        return ""
    offset = 127397
    return ''.join(chr(ord(c) + offset) for c in country_code.upper())

def setup_ip2location(db_url, temp_dir):
    """
    Загрузка и распаковка базы IP2Location.
    Возвращает путь к BIN-файлу и путь к zip-архиву.
    """
    response = requests.get(db_url, stream=True, timeout=TIMEOUT)
    zip_path = os.path.join(temp_dir, "IP2LOCATION-LITE-DB1.BIN.ZIP")
    with open(zip_path, "wb") as f:
        f.write(response.content)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)
    bin_file = os.path.join(temp_dir, "IP2LOCATION-LITE-DB1.BIN")
    return bin_file, zip_path

def format_profile(config, ip2_db):
    """
    Форматирование профиля в требуемый вид.
    Извлекаются параметры URL, определяется сокращенное название протокола,
    добавляется эмодзи флага страны, и формируется комментарий в формате:
    "#🔒 TR-WS-TLS | <флаг> | 104.19.223.79:443"
    """
    try:
        parsed = urlparse(config)
        scheme = parsed.scheme.lower()
        proto_map = {"trojan": "TR", "vless": "VL", "tuic": "TC", "hy2": "HY"}
        proto_abbr = proto_map.get(scheme, scheme.upper())
        netloc = parsed.netloc
        if "@" in netloc:
            _, host_port = netloc.split("@", 1)
        else:
            host_port = netloc
        if ":" in host_port:
            host, port = host_port.split(":", 1)
        else:
            host = host_port
            port = ""
        qs = parse_qs(parsed.query)
        type_val = qs.get("type", [""])[0].upper()
        security_val = qs.get("security", [""])[0].upper()
        profile_label = f"{proto_abbr}"
        if type_val:
            profile_label += f"-{type_val}"
        if security_val:
            profile_label += f"-{security_val}"
        flag = ""
        try:
            rec = ip2_db.get_all(host)
            country_code = rec.country_short
            flag = get_flag_emoji(country_code)
        except Exception:
            flag = ""
        final_comment = f"🔒 {profile_label} | {flag} | {host}:{port}"
        if "#" in config:
            base_part = config.split("#", 1)[0]
            new_config = f"{base_part}#{final_comment}"
        else:
            new_config = f"{config}#{final_comment}"
        return new_config
    except Exception:
        return config

def enrich_configs(configs, ip2_db):
    """
    Обогащение и форматирование всех конфигураций с использованием многопоточной обработки.
    """
    enriched = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(format_profile, config, ip2_db): config for config in configs}
        for future in concurrent.futures.as_completed(futures):
            try:
                enriched.append(future.result())
            except Exception:
                pass
    return enriched

def separate_and_sort_configs(configs):
    """
    Разделение конфигураций по протоколам и сортировка внутри каждой группы по убыванию длины.
    """
    protocols = ["vless", "trojan", "tuic", "hy2"]
    separated = {proto: [] for proto in protocols}
    pattern = re.compile(r'^(vless|trojan|tuic|hy2)://', re.IGNORECASE)
    for config in configs:
        match = pattern.match(config)
        if match:
            proto = match.group(1).lower()
            separated[proto].append(config)
    for proto in separated:
        separated[proto].sort(key=lambda x: len(x), reverse=True)
    return separated

def ensure_output_dir():
    """
    Создание единственной директории для сохранения результатов:
    'Splitted-By-Protocol'
    """
    output_dir = os.path.join(os.path.abspath(os.getcwd()), "Splitted-By-Protocol")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def write_results(separated_configs, output_dir):
    """
    Сохранение конфигураций по протоколам в файлы:
      - vless.txt
      - trojan.txt
      - tuic.txt
      - hy2.txt
    Все файлы сохраняются в директории output_dir.
    После записи выводится информативное сообщение с результатами.
    """
    summary = {}
    for proto, configs in separated_configs.items():
        file_path = os.path.join(output_dir, f"{proto}.txt")
        with open(file_path, "w", encoding='utf-8') as f:
            for config in configs:
                f.write(config + "\n")
        summary[proto] = len(configs)
    print("\nОбработка завершена.")
    print("Ссылки, указанные в коде, успешно скачаны и обработаны.")
    print("Сохранено конфигураций:")
    for proto in ["vless", "trojan", "tuic", "hy2"]:
        print(f"  {proto}: {summary.get(proto, 0)} записей")
    print(f"Файлы сохранены в директории: {output_dir}")

def cleanup_ip2location(bin_file, zip_file, temp_dir):
    """Удаление временных файлов базы IP2Location."""
    try:
        os.remove(bin_file)
        os.remove(zip_file)
        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Ошибка при удалении временных файлов: {e}")

async def async_main():
    output_dir = ensure_output_dir()
    
    # Загрузка и подготовка базы IP2Location
    ip2location_url = "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.BIN.ZIP"
    temp_dir = os.path.join(os.path.abspath(os.getcwd()), "temp_ip2location")
    os.makedirs(temp_dir, exist_ok=True)
    bin_file, zip_file = setup_ip2location(ip2location_url, temp_dir)
    ip2_db = IP2Location.IP2Location(bin_file)
    
    # Списки ссылок (для подписок и директорий)
    links = [
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/refs/heads/main/server.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/lagzian/SS-Collector/refs/heads/main/VLESS/VL100.txt",
        "https://raw.githubusercontent.com/lagzian/new-configs-collector/main/protocols/hysteria",
        "https://raw.githubusercontent.com/lagzian/SS-Collector/main/reality.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/protocols/vl.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/protocols/tr.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/hysteria",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/trojan",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/tuic",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/vless",
        "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-protocol-vl",
        "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-protocol-tr",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/tuic",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
        "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
        "https://raw.githubusercontent.com/Vauth/node/main/Main",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/output/converted.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/selector/random",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/ws_tls/proxies/wstls",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/custom/udp.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/one_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/two_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/three_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/four_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/five_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/six_file_vpn.txt",
        "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/seven_file_vpn.txt",
        "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
        "https://raw.githubusercontent.com/dimzon/scaling-sniffle/main/all-sort.txt",
        "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/United%20States/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Italy/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Germany/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Finland/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Sweden/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/United%20Kingdom/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Poland/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Netherlands/config.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Ireland/config.txt",
        "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/a11",
        "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
        "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/main/nodes/yudou66.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mci1.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mci2.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mci3.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mci4.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mtn1.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mtn2.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mtn3.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/mtn4.txt",
        "https://raw.githubusercontent.com/40OIL/domain.club/refs/heads/main/07pr4n27.txt",
    ]
    dir_links = []
    
    raw_data = await fetch_all_links(links, dir_links)
    print("Все ссылки, указанные в коде, успешно скачаны и обработаны.")
    
    combined_data = []
    for data in raw_data:
        if data:
            combined_data.extend(data.splitlines())
    
    allowed_protocols = ["vless://", "trojan://", "tuic://", "hy2://"]
    filtered_configs = filter_for_allowed_protocols(combined_data, allowed_protocols)
    unique_configs = remove_duplicates(filtered_configs)
    enriched_configs = enrich_configs(unique_configs, ip2_db)
    separated_configs = separate_and_sort_configs(enriched_configs)
    write_results(separated_configs, output_dir)
    cleanup_ip2location(bin_file, zip_file, temp_dir)

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
