import pybase64
import base64
import requests
import binascii
import os
import logging  # Добавлен модуль logging
# from more_thread_sort import sort_nodes # Закомментировано, пока не выясним назначение

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Конфигурация (можно вынести в отдельный файл или аргументы командной строки)
TIMEOUT = 30  # seconds
PROTOCOLS = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp://"]
LINKS = [
    "https://raw.githubusercontent.com/lagzian/SS-Collector/refs/heads/main/VLESS/VL100.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/security/tls",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Configs_TLS.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/two_file_vpn.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/output/converted.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/refs/heads/master/sub",
]
DIR_LINKS = LINKS  # Используем LINKS, если dir_links должны быть идентичны, иначе укажите другой список
MAX_LINES_PER_FILE = 6000
OUTPUT_FOLDER = "Output" # Имя выходной папки
BASE64_FOLDER_NAME = "Base64"
SUB_FOLDER_NAME = "Subs"


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


# Function to fetch and decode data from links
def fetch_and_decode_links(links, decode_content=True):
    decoded_data = []
    for link in links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            encoded_bytes = response.content
            if decode_content:
                decoded_text = decode_base64(encoded_bytes)
            else:
                decoded_text = response.text
            decoded_data.append(decoded_text)
            logging.info(f'Успешно получены данные из {link}')
        except requests.exceptions.RequestException as e:
            logging.error(f'Ошибка при получении данных из {link}: {e}')
    return decoded_data


# Filter function to select lines based on specified protocols
def filter_for_protocols(data, protocols):
    filtered_data = []
    for line in data:
        if any(protocol in line for protocol in protocols):
            filtered_data.append(line)
    return filtered_data


# Create necessary directories if they don't exist
def ensure_directories_exist(output_folder_name, base64_folder_name, sub_folder_name):
    output_folder = os.path.abspath(os.path.join(os.getcwd(), output_folder_name))
    base64_folder = os.path.join(output_folder, base64_folder_name)
    sub_folder = os.path.join(output_folder, sub_folder_name)

    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(base64_folder, exist_ok=True)
    os.makedirs(sub_folder, exist_ok=True)

    return output_folder, base64_folder, sub_folder


# Main function to process links and write output files
def main():
    output_folder, base64_folder, sub_folder = ensure_directories_exist(OUTPUT_FOLDER, BASE64_FOLDER_NAME, SUB_FOLDER_NAME)

    decoded_links_data = fetch_and_decode_links(LINKS, decode_content=True) # Для links декодируем base64
    decoded_dir_links_data = fetch_and_decode_links(DIR_LINKS, decode_content=False) # Для dir_links не декодируем base64

    combined_data = decoded_links_data + decoded_dir_links_data

    # Удаление дубликатов
    unique_data = list(set(combined_data))
    logging.info(f"Удалено дубликатов: {len(combined_data) - len(unique_data)}")

    merged_configs = filter_for_protocols(unique_data, PROTOCOLS)

    # Clean existing output files
    output_filename = os.path.join(output_folder, "All_Subs.txt")

    if os.path.exists(output_filename):
        os.remove(output_filename)

    for i in range(20): # Увеличьте диапазон, если нужно больше файлов Sub{i}.txt
        filename = os.path.join(sub_folder, f"Sub{i+1}.txt")
        if os.path.exists(filename):
            os.remove(filename)

    # Write merged configs to output file
    with open(output_filename, "w", encoding='utf-8') as f:
        for config in merged_configs:
            f.write(config + "\n")

    # Split merged configs into smaller files
    with open(output_filename, "r", encoding='utf-8') as f:
        lines = f.readlines()

    num_lines = len(lines)
    num_files = (num_lines + MAX_LINES_PER_FILE - 1) // MAX_LINES_PER_FILE

    for i in range(num_files):
        input_filename = os.path.join(sub_folder, f"Sub{i + 1}.txt")
        with open(input_filename, "w", encoding='utf-8') as f:
            start_index = i * MAX_LINES_PER_FILE
            end_index = min((i + 1) * MAX_LINES_PER_FILE, num_lines)
            for line in lines[start_index:end_index]:
                f.write(line)

        with open(input_filename, "r", encoding='utf-8') as input_file:
            config_data = input_file.read()

        output_filename = os.path.join(base64_folder, f"Sub{i + 1}_base64.txt")
        with open(output_filename, "w", encoding='utf-8') as output_file:
            encoded_config = base64.b64encode(config_data.encode()).decode()
            output_file.write(encoded_config)


if __name__ == "__main__":
    # 获取 и обработка подписок
    main()
    # Классификация подписок (если необходимо, раскомментируйте и уточните назначение sort_nodes)
    # sort_nodes()
