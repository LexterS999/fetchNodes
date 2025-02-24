import pybase64
import base64
import requests
import binascii
import os
from more_thread_sort import sort_nodes

# Define a fixed timeout for HTTP requests
TIMEOUT = 20  # seconds


# Base64 decoding function
def decode_base64(encoded):
    decoded = ""
    for encoding in ["utf-8", "iso-8859-1"]:
        try:
            decoded = pybase64.b64decode(encoded + b"=" * (-len(encoded) % 4)).decode(encoding)
            break
        except (UnicodeDecodeError, binascii.Error):
            pass
    return decoded


# Function to decode base64-encoded links with a timeout
def decode_links(links):
    decoded_data = []
    for link in links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            encoded_bytes = response.content
            decoded_text = decode_base64(encoded_bytes)
            # base64解码
            decoded_data.append(decoded_text)
            print(f'获取links {link}\n订阅成功！')
        except requests.RequestException:
            pass  # If the request fails or times out, skip it
    return decoded_data


# Function to decode directory links with a timeout
def decode_dir_links(dir_links):
    decoded_dir_links = []
    for link in dir_links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            decoded_text = response.text
            decoded_dir_links.append(decoded_text)
            print(f'获取dir_links {link}\n订阅成功！')
        except requests.RequestException:
            pass  # If the request fails or times out, skip it
    return decoded_dir_links


# Filter function to select lines based on specified protocols
def filter_for_protocols(data, protocols):
    filtered_data = []
    for line in data:
        if any(protocol in line for protocol in protocols):
            filtered_data.append(line)
    return filtered_data


# Create necessary directories if they don't exist
def ensure_directories_exist():
    output_folder = os.path.abspath(os.path.join(os.getcwd()))
    base64_folder = os.path.join(output_folder, "Base64")
    SUB_folder = os.path.join(output_folder, "Subs")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    if not os.path.exists(base64_folder):
        os.makedirs(base64_folder)
    if not os.path.exists(SUB_folder):
        os.makedirs(SUB_folder)

    return output_folder, base64_folder, SUB_folder


# Main function to process links and write output files
def main():
    output_folder, base64_folder, SUB_folder = ensure_directories_exist()  # Ensure directories are created

    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp://"]
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
    dir_links = [
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

    decoded_links = decode_links(links)
    decoded_dir_links = decode_dir_links(dir_links)

    combined_data = decoded_links + decoded_dir_links
    merged_configs = filter_for_protocols(combined_data, protocols)

    # Clean existing output files
    output_filename = os.path.join(output_folder, "All_Subs.txt")

    if os.path.exists(output_filename):
        os.remove(output_filename)

    for i in range(20):
        filename = os.path.join(SUB_folder, f"Sub{i}.txt")
        if os.path.exists(filename):
            os.remove(filename)

    # Write merged configs to output file
    with open(output_filename, "w", encoding='utf-8') as f:
        # f.write(fixed_text)
        for config in merged_configs:
            f.write(config + "\n")

    # Split merged configs into smaller files (no more than 600 configs per file)
    with open(output_filename, "r", encoding='utf-8') as f:
        lines = f.readlines()

    num_lines = len(lines)
    max_lines_per_file = 600
    num_files = (num_lines + max_lines_per_file - 1) // max_lines_per_file

    for i in range(num_files):
        input_filename = os.path.join(SUB_folder, f"Sub{i + 1}.txt")
        with open(input_filename, "w", encoding='utf-8') as f:
            start_index = i * max_lines_per_file
            end_index = min((i + 1) * max_lines_per_file, num_lines)
            for line in lines[start_index:end_index]:
                f.write(line)

        with open(input_filename, "r", encoding='utf-8') as input_file:
            config_data = input_file.read()

        output_filename = os.path.join(base64_folder, f"Sub{i + 1}_base64.txt")
        with open(output_filename, "w", encoding='utf-8') as output_file:
            encoded_config = base64.b64encode(config_data.encode()).decode()
            output_file.write(encoded_config)


if __name__ == "__main__":
    # 获取订阅
    main()
    # 订阅分类
    sort_nodes()


