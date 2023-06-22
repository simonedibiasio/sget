import re
import requests
from html import unescape
from argparse import ArgumentParser


def extract_shellcode(content: str) -> str:
    chunks = re.findall(r'"([\\x0-9a-f]+)"', content)
    return "".join(chunks)


def main(args):
    if args.url:
        url = args.url
        if "exploit-db.com/shellcodes" in url:
            url = args.url.replace("shellcodes", "raw")
        try:
            headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0"}
            response = requests.get(url, headers=headers)
            content = response.content.decode("utf-8")
        except requests.RequestException as e:
            print("Error:", str(e))
    elif args.file:
        with open(args.file, "r") as f:
            content = f.read()

    shellcode = extract_shellcode(unescape(content))
    print(f"shellcode = b'{shellcode}'")
    print(f"({len(shellcode)//4} bytes)")


if __name__ == "__main__":
    parser = ArgumentParser(description="")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", dest="url", type=str, help="URL")
    group.add_argument("-f", dest="file", type=str, help="File path")
    args = parser.parse_args()

    main(args)
