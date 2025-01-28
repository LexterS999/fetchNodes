import pybase64
import base64
import requests
import binascii
import os
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Конфигурация
TIMEOUT = 30  # seconds
PROTOCOLS = ["vless", "trojan", "tuic", "hy2"]
ALLOWED_PROTOCOLS_PREFIXES = [protocol + "://" for protocol in PROTOCOLS]
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
DIR_LINKS = LINKS
MAX_LINES_PER_FILE = 6000

# Измененная конфигурация директорий
OUTPUT_FOLDER = "fetchNodes"  # Корневая папка теперь "fetchNodes"
BASE64_FOLDER_NAME = "Splitted-By-Protocol" # Папка для base64 файлов
SUB_FOLDER_NAME = "Subs" # Папка для обычных текстовых файлов


# Base64 decoding function
def decode_base64(encoded):
    decoded = ""
    try:
        decoded = pybase64.b64decode(encoded + b"=" * (-len(encoded) % 4)).decode("utf-8")
    except (UnicodeDecodeError, binascii.Error, LookupError) as e:
        logging.error(f"Ошибка декодирования Base64: {e}")
        pass
    return decoded


# Function to fetch and decode data from links
def fetch_and_decode_links(links, decode_content=True):
    decoded_data = []
    for link in links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            response.raise_for_status()
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


# Filter function to select lines based on specified protocols (start of line)
def filter_for_protocols(data, allowed_protocol_prefixes):
    filtered_data = []
    for line in data:
        if any(line.startswith(prefix) for prefix in allowed_protocol_prefixes):
            filtered_data.append(line)
    return filtered_data

# Функция для определения протокола из строки
def get_protocol_from_line(line, protocols):
    for protocol_prefix in ALLOWED_PROTOCOLS_PREFIXES:
        if line.startswith(protocol_prefix):
            return protocol_prefix[:-3]
    return "other"

# Функция сортировки данных по протоколу, затем по алфавиту
def sort_data_by_protocol(data, protocols):
    def protocol_sort_key(line):
        protocol = get_protocol_from_line(line, protocols)
        protocol_priority = protocols.index(protocol) if protocol != "other" and protocol in protocols else len(protocols)
        return (protocol_priority, line)

    return sorted(data, key=protocol_sort_key)

# Функция для переименования профилей в списке конфигураций
def rename_profiles(configs):
    renamed_configs = []
    for index, config in enumerate(configs):
        hash_index = config.rfind("#")
        if hash_index != -1:
            base_config = config[:hash_index].rstrip()
            renamed_config = f"{base_config} #({index + 1})"
            renamed_configs.append(renamed_config)
        else:
            renamed_configs.append(config.rstrip() + f" #({index + 1})")
    return renamed_configs


# Create necessary directories if they don't exist
def ensure_directories_exist(output_folder_name, base64_folder_name, sub_folder_name):
    output_folder = os.path.abspath(os.path.join(os.getcwd(), output_folder_name))
    base64_folder = os.path.join(output_folder, base64_folder_name)
    sub_folder = os.path.join(output_folder, sub_folder_name)

    os.makedirs(output_folder, exist_ok=True, mode=0o777) # Ensure write permissions
    os.makedirs(base64_folder, exist_ok=True, mode=0o777) # Ensure write permissions
    os.makedirs(sub_folder, exist_ok=True, mode=0o777) # Ensure write permissions

    return output_folder, base64_folder, sub_folder


# Main function to process links and write output files
def main():
    output_folder, base64_folder, sub_folder = ensure_directories_exist(OUTPUT_FOLDER, BASE64_FOLDER_NAME, SUB_FOLDER_NAME)

    decoded_links_data = fetch_and_decode_links(LINKS, decode_content=True)
    decoded_dir_links_data = fetch_and_decode_links(DIR_LINKS, decode_content=False)

    combined_data = decoded_links_data + decoded_dir_links_data

    logging.info(f"Исходное количество строк: {len(combined_data)}")

    # Удаление дубликатов
    unique_data = list(set(combined_data))
    logging.info(f"Удалено дубликатов: {len(combined_data) - len(unique_data)}, осталось уникальных: {len(unique_data)}")

    filtered_configs = filter_for_protocols(unique_data, ALLOWED_PROTOCOLS_PREFIXES)
    logging.info(f"После фильтрации протоколов осталось: {len(filtered_configs)}")
    logging.debug(f"Первые 5 строк после фильтрации: {filtered_configs[:5]}") # Лог первых 5 строк после фильтрации

    # Сортировка по протоколу
    sorted_configs = sort_data_by_protocol(filtered_configs, PROTOCOLS)

    logging.info("Применяется переименование профилей...")
    # Переименование профилей
    renamed_configs = rename_profiles(sorted_configs)
    logging.info(f"Переименовано профилей: {len(renamed_configs)}")
    logging.debug(f"Первые 5 строк после переименования: {renamed_configs[:5]}") # Лог первых 5 строк после переименования


    # Clean existing output files
    output_filename = os.path.join(output_folder, "All_Subs.txt")
    base64_output_filename_pattern = os.path.join(base64_folder, "Sub{}_base64.txt") # Pattern for base64 files
    sub_output_filename_pattern = os.path.join(sub_folder, "Sub{}.txt") # Pattern for sub files

    if os.path.exists(output_filename):
        os.remove(output_filename)
        logging.info(f"Удален старый файл: {output_filename}")

    for i in range(20): # Увеличьте диапазон при необходимости
        sub_filename = sub_output_filename_pattern.format(i+1)
        base64_filename = base64_output_filename_pattern.format(i+1)
        if os.path.exists(sub_filename):
            os.remove(sub_filename)
            logging.info(f"Удален старый файл: {sub_filename}")
        if os.path.exists(base64_filename):
            os.remove(base64_filename)
            logging.info(f"Удален старый файл: {base64_filename}")


    # Write merged configs to output file
    output_filename = os.path.join(output_folder, "All_Subs.txt")
    logging.info(f"Запись в файл All_Subs.txt, первые 5 строк для записи:") # Лог перед записью All_Subs
    logging.debug(f"Первые 5 строк для записи в All_Subs.txt: {renamed_configs[:5]}") # Детальный лог
    with open(output_filename, "w", encoding='utf-8') as f:
        for config in renamed_configs:
            f.write(config + "\n")
        logging.info(f"Записан файл: {output_filename}, строк: {len(renamed_configs)}")

    # Split merged configs into smaller files
    with open(output_filename, "r", encoding='utf-8') as f:
        lines = f.readlines()

    num_lines = len(lines)
    num_files = (num_lines + MAX_LINES_PER_FILE - 1) // MAX_LINES_PER_FILE

    for i in range(num_files):
        sub_filename = sub_output_filename_pattern.format(i + 1) # Using pattern
        sub_file_lines = lines[i * MAX_LINES_PER_FILE:min((i + 1) * MAX_LINES_PER_FILE, num_lines)]
        logging.info(f"Запись в файл Sub{i+1}.txt, первые 5 строк для записи:") # Лог перед записью Sub{i}.txt
        logging.debug(f"Первые 5 строк для записи в Sub{i+1}.txt: {sub_file_lines[:5]}") # Детальный лог
        with open(sub_filename, "w", encoding='utf-8') as f:
            f.writelines(sub_file_lines) # Use writelines for efficiency
            logging.info(f"Записан файл: {sub_filename}, строк: {len(sub_file_lines)}")

        base64_filename = base64_output_filename_pattern.format(i + 1) # Using pattern
        with open(base64_filename, "w", encoding='utf-8') as output_file:
            with open(sub_filename, "r", encoding='utf-8') as input_file:
                config_data = input_file.read()
            encoded_config = base64.b64encode(config_data.encode()).decode()
            output_file.write(encoded_config)
            logging.info(f"Записан файл: {base64_filename}, base64 версия файла: {sub_filename}")


if __name__ == "__main__":
    # Получение и обработка подписок
    main()
