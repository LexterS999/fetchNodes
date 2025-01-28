from pprint import pprint

import requests
import os
import base64


# Function to generate base64 encoded header text for each protocol
def generate_header_text(protocol_name):
    titles = {
        'vmess': "8J+GkyB3b3JsZCB8IHZtZXNz8J+ltw==",
        'vless': "8J+GkyB3b3JsZCB8IHZsZXNz8J+ltw==",
        'trojan': "8J+GkyB3b3JsZCB8IHRyb2phbvCfpbc=",
        'ss': "8J+GkyB3b3JsZCB8IHNz8J+ltw==",
        'ssr': "8J+GkyB3b3JsZCB8IHNzcvCfpbc=",
        'tuic': "8J+GkyB3b3JsZCB8IHR1aWPwn6W3",
        'hy2': "8J+GkyB3b3JsZCB8IGh5MvCfpbc="
    }
    base_text = "#profile-title: base64:{base64_title}"
    base_text = f'{titles.get(protocol_name, "")}'
    # return base_text.format(base64_title=titles.get(protocol_name, ""))
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

    ptt = os.path.abspath(os.path.join(os.getcwd()))
    splitted_path = os.path.join(ptt, 'Splitted-By-Protocol')

    # Ensure the directory exists
    os.makedirs(splitted_path, exist_ok=True)

    protocol_data = {protocol: generate_header_text(protocol) for protocol in protocols}
    pprint(protocol_data)
    # Fetching the configuration data
    with open("All_Configs_Sub.txt", "r", encoding="utf-8") as file:
        total_lines = sum(1 for _ in file)
        print(f'总共{total_lines}行')

    with open("All_Configs_Sub.txt", "r", encoding="utf-8") as file:
        content = file.read()
        current_line = 0
        # 处理和分类配置数据
        for config in content.splitlines():
            if not config.strip():  # 跳过空行
                continue
            protocol_found = None

            # 确定协议类型
            for protocol in protocols.keys():
                if config.startswith(protocol):
                    protocol_found = protocol
                    break

            # 如果匹配到协议，添加到对应的协议数据
            if protocol_found:
                protocol_data[protocol_found] += config + "\n"
            current_line += 1
            print(f'正在处理第{current_line}行，共{total_lines}行，协议：{protocol}')

        # Encoding and writing the data to files
    for protocol, data in protocol_data.items():
        file_path = os.path.join(splitted_path, protocols[protocol])
        encoded_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(encoded_data)


if __name__ == '__main__':
    sort_nodes()
