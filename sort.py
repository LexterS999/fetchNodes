from pprint import pprint
import requests
import os
import base64
import logging  # Добавим logging для консистентности и отладки

# Настройка логирования (если еще не настроено в вызывающем скрипте, лучше добавить)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Function to generate base64 encoded header text for each protocol
def generate_header_text(protocol_name):
    titles = {
        'vmess': "8J+GkyB3b3JsZCB8IHZtZXNz8J+ltw==",  # 🌐 World | vmess🌐
        'vless': "8J+GkyB3b3JsZCB8IHZsZXNz8J+ltw==",  # 🌐 World | vless🌐
        'trojan': "8J+GkyB3b3JsZCB8IHRyb2phbvCfpbc=", # 🌐 World | trojan🗝
        'ss': "8J+GkyB3b3JsZCB8IHNz8J+ltw==",    # 🌐 World | ss🌐
        'ssr': "8J+GkyB3b3JsZCB8IHNzcvCfpbc=",   # 🌐 World | ssr🗝
        'tuic': "8J+GkyB3b3JsZCB8IHR1aWPwn6W3",   # 🌐 World | tuic🔑
        'hy2': "8J+GkyB3b3JsZCB8IGh5MvCfpbc="    # 🌐 World | hy2🗝
    }
    base_text = f'{titles.get(protocol_name, "")}'
    return base_text


def sort_nodes():
    protocols = {
        'vmess': 'vmess.txt',
        'vless': 'vless.txt',
        'trojan': 'trojan.txt',
        'ss': 'ss.txt',
        'ssr': 'ssr.txt',
        'tuic': 'tuic.txt',
        'hy2': 'hysteria2.txt'
    }

    # Конфигурация директорий - используем те же переменные, что и в main.py
    OUTPUT_FOLDER = "fetchNodes"  # Корневая папка
    BASE64_FOLDER_NAME = "Splitted-By-Protocol" # Папка для base64 файлов

    base_path = os.path.abspath(os.path.join(os.getcwd(), OUTPUT_FOLDER)) # Путь к корневой папке fetchNodes
    splitted_path = os.path.join(base_path, BASE64_FOLDER_NAME) # Путь к Splitted-By-Protocol

    # Ensure the directory exists
    os.makedirs(splitted_path, exist_ok=True)

    protocol_data = {protocol: generate_header_text(protocol) for protocol in protocols}
    pprint(protocol_data)

    # Input file path - берем All_Subs.txt из OUTPUT_FOLDER, как результат работы main.py
    input_file_path = os.path.join(base_path, "All_Subs.txt")

    # Fetching the configuration data
    if not os.path.exists(input_file_path):
        logging.error(f"Входной файл не найден: {input_file_path}. Сначала запустите main.py.")
        return # Важно выйти, если входной файл не существует

    with open(input_file_path, "r", encoding="utf-8") as file:
        total_lines = sum(1 for _ in file)
        logging.info(f'Всего строк для обработки: {total_lines}')

    with open(input_file_path, "r", encoding="utf-8") as file:
        content = file.read()
        current_line = 0
        # 处理和分类配置数据
        for config in content.splitlines():
            if not config.strip():  # Skip empty lines
                continue
            protocol_found = None

            # Determine protocol type
            for protocol in protocols.keys():
                if config.startswith(protocol + "://"): # Убедимся, что проверяем префикс протокола "://"
                    protocol_found = protocol
                    break

            # If a protocol is matched, add to the corresponding protocol data
            if protocol_found:
                protocol_data[protocol_found] += config + "\n"
            current_line += 1
            if current_line % 100 == 0: # Логируем прогресс каждые 100 строк
                logging.info(f'Обработано строк: {current_line}/{total_lines}, текущий протокол: {protocol_found}')

        # Encoding and writing the data to files
    for protocol, data in protocol_data.items():
        file_path = os.path.join(splitted_path, protocols[protocol])
        encoded_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(encoded_data)
            logging.info(f"Файл записан: {file_path}, протокол: {protocol}, размер base64: {len(encoded_data)}") # Логируем запись файла


if __name__ == '__main__':
    sort_nodes()
