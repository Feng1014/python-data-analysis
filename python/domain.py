from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import sys
import time
import requests
import pandas as pd
import webbrowser
import time
import tldextract


def obtain_new_domain_everyday(input_file, output_file):
    # 读取Excel文件
    data_frame = pd.read_excel(input_file)

    # 获取指定列的数据
    column_data = data_frame['域名']

    # 将数据存放到数组中
    data_array = column_data.values.tolist()
    urllist = []
    id = 0
    for url in data_array:
        if '.' in str(url):
            id = id+1
            if url.split('.')[-2] + '.' + url.split('.')[-1] == 'com.cn' or url.split('.')[-2] + '.' + url.split('.')[-1] == 'org.cn':
                a = url.split('.')[-3] + '.' + \
                    url.split('.')[-2] + '.' + url.split('.')[-1]
                urllist.append(a)
            else:
                b = url.split('.')[-2] + '.' + url.split('.')[-1]
                urllist.append(b)

    # 使用Counter进行计数
    counter = Counter(urllist)

    # 将计数结果转换为列表，并根据计数进行排序
    # 先按计数降序排序，如果计数相同则按元素名升序排序
    sorted_counter = sorted(counter.items(), key=lambda x: (-x[1], x[0]))

    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for key, _ in sorted_counter:
                file.write(str(key).lower().strip() + '\n')
    except IOError as e:
        print(f"Error writing to file: {e}")
    print(str(id))


def run_obtain_new_domain_everyday():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        obtain_new_domain_everyday(input_file, output_file)


def obtain_new_domain(old_domain, new_domain, no_repeat_domain):

    # 读取第一个文件，存入集合以便快速查找
    with open(old_domain, 'r', encoding='utf-8') as olds:
        present_in_file = set(line.strip() for line in olds)

    # 读取第二个文件，找出不在第一个文件中的行
    with open(new_domain, 'r', encoding='utf-8') as news, open(no_repeat_domain, 'w', encoding='utf-8') as outfile:
        for line in news:
            stripped_line = line.strip()
            if stripped_line and stripped_line not in present_in_file:
                outfile.write(stripped_line + '\n')


def run_obtain_new_domain():
    if len(sys.argv) != 4:
        print("Usage: python script.py old.json new.json output.json")
    else:
        old_domain = sys.argv[1]
        new_domain = sys.argv[2]
        no_repeat_domain = sys.argv[3]
        obtain_new_domain(old_domain, new_domain, no_repeat_domain)


def send_to_browser_request(input_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                webbrowser.open(url)
                time.sleep(1)  # 在打开每个 URL 之间等待 1 秒
    except FileNotFoundError:
        print(f"文件未找到: {input_file}")
    except Exception as e:
        print(f"发生错误: {e}")


def run_send_to_browser_request():
    if len(sys.argv) != 2:
        print("Usage: python script.py input.json")
    else:
        input_file = sys.argv[1]
        send_to_browser_request(input_file)


def remove_duplicate_and_combine(whitelist_old, whitelist_new):
    first_set = set()
    try:
        with open(whitelist_old, 'r', encoding='utf-8') as f:
            for line in f:
                first_set.add(line.lower().strip())
    except FileNotFoundError:
        print("第一个输入文件未找到。")
        exit()
    second_set = set()
    try:
        with open(whitelist_new, 'r', encoding='utf-8') as f:
            for line in f:
                second_set.add(line.lower().strip())
    except FileNotFoundError:
        print("第二个输入文件未找到。")
        exit()
    diff = second_set - first_set
    first_set.update(diff)

    try:
        with open(whitelist_old, 'w', encoding='utf-8') as f:
            for item in sorted(first_set):
                f.write(item + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_remove_duplicate_and_combine():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        whitelist_old = sys.argv[1]
        whitelist_new = sys.argv[2]
        remove_duplicate_and_combine(whitelist_old, whitelist_new)


def remove_duplicate_and_combine_and_obtain_different(whitelist_old, whitelist_new):
    first_set = set()
    try:
        with open(whitelist_old, 'r', encoding='utf-8') as f:
            for line in f:
                first_set.add(line.lower().strip())
    except FileNotFoundError:
        print("第一个输入文件未找到。")
        exit()
    second_set = set()
    try:
        with open(whitelist_new, 'r', encoding='utf-8') as f:
            for line in f:
                second_set.add(line.lower().strip())
    except FileNotFoundError:
        print("第二个输入文件未找到。")
        exit()
    diff = second_set - first_set
    first_set.update(diff)

    try:
        with open(whitelist_new, 'w', encoding='utf-8') as f:
            for item in sorted(diff):
                f.write(item + '\n')
    except IOError:
        print("无法写入输出文件。")

    try:
        with open(whitelist_old, 'w', encoding='utf-8') as f:
            for item in sorted(first_set):
                f.write(item + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_remove_duplicate_and_combine_and_obtain_different():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        whitelist_old = sys.argv[1]
        whitelist_new = sys.argv[2]
        remove_duplicate_and_combine_and_obtain_different(
            whitelist_old, whitelist_new)


def counte_white_domain_suffix(input_file, output_file):
    # 从文件读取域名
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
        domains = [domain.strip()
                   for domain in content.split() if domain.strip()]

    # 提取每个域名的后缀
    suffixes = []
    for domain in domains:
        try:
            ext = tldextract.extract(domain)
            suffixes.append(ext.suffix)
        except Exception as e:
            print(f"处理域名 '{domain}' 时出错: {e}")

    # 统计后缀出现次数
    suffix_count = Counter(suffixes)

    # 按出现次数降序排序，相同次数按后缀字母顺序排序
    sorted_suffixes = sorted(suffix_count.items(), key=lambda x: (-x[1], x[0]))

    # 将结果写入输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for suffix, count in sorted_suffixes:
            f.write(f"域名后缀: {suffix}, 计数: {count}\n")


def run_counte_white_domain_suffix():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.json")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        counte_white_domain_suffix(input_file, output_file)


def check_combine_is_right(old_file, combine_file):
    first_set = set()
    try:
        with open(old_file, 'r', encoding='utf-8') as f:
            for line in f:
                first_set.add(line.strip())
    except FileNotFoundError:
        print("第一个输入文件未找到。")
        exit()
    second_set = set()
    try:
        with open(combine_file, 'r', encoding='utf-8') as f:
            for line in f:
                second_set.add(line.strip())
    except FileNotFoundError:
        print("第二个输入文件未找到。")
        exit()
    # 找到交集（即第二组中存在于第一组的内容）
    intersection = first_set.intersection(second_set)
    try:
        with open('.\\intersection.json', 'w', encoding='utf-8') as f:
            for item in sorted(intersection):
                f.write(item + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_check_combine_is_right():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        old_file = sys.argv[1]
        combine_file = sys.argv[2]
        check_combine_is_right(old_file, combine_file)


def read_file_to_set_and_sorted(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File {input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    unique_domains = sorted(set(domains))

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for domain in unique_domains:
                f.write(domain + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_read_file_to_set_and_sorted():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        read_file_to_set_and_sorted(input_file, output_file)


def read_domains(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            domains = [domain.lower() for domain in content.split()]
        return domains
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return None


def compare_domain():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python compare_domain_lists.py <file1> <file2> [mode]")
        print("mode: 'list' (default) or 'set'")
        sys.exit(1)
    file1 = sys.argv[1]
    file2 = sys.argv[2]
    mode = 'list' if len(sys.argv) == 3 else sys.argv[3]
    print(f"Comparing domain {mode}s from {file1} and {file2}...")
    list1 = read_domains(file1)
    list2 = read_domains(file2)
    if list1 is None or list2 is None:
        print("Could not read one or both files.")
    else:
        if mode == 'list':
            if list1 == list2:
                print("The domain lists are identical.")
            else:
                print("The domain lists are different.")
        elif mode == 'set':
            if set(list1) == set(list2):
                print("The domain sets are identical.")
            else:
                print("The domain sets are different.")
        else:
            print("Invalid mode. Use 'list' or 'set'.")


def extract_domain(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
        for line in infile:
            if line.startswith('#'):
                content = line[1:].strip()
                outfile.write(f"http://{content}\n")


def run_extract_check_domain():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        extract_domain(input_file, output_file)


def check_url(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.head(url, headers=headers,
                                 timeout=100, allow_redirects=True)
        if response.status_code == 200 and len(response.content) > 0:
            print(f"[OK] {url}")
            return url
        else:
            print(f"[FAIL {response.status_code}] {url}")
        return None
    except requests.exceptions.RequestException:
        return None


def check_url_with_threadpool(input_file, output_file):
    urls = []
    # Read URLs from file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if domain:
                    url = f'http://{domain}'
                    urls.append(url)
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    if not urls:
        print("No URLs found in the file.")
        return

    start_time = time.time()

    # Check URLs in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_url, urls))

    # Filter successful URLs (non-None results)
    successful_urls = [url for url in results if url]

    # Write successful URLs to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        for url in successful_urls:
            f.write(url + '\n')

    # Print summary to console
    print(f"Found {len(successful_urls)} successful URLs out of {len(urls)}.")
    print(f"Results saved to {output_file}")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")


def run_check_url_with_threadpool():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        check_url_with_threadpool(input_file, output_file)


def delete_duplicate_by_char(input_file, output_file):
    # 读取输入文件
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("输入文件未找到。")
        exit()

    # 去除每行开头的 "http://" 并清理空格
    modified_lines = [line.replace("http://", "").strip() for line in lines]

    # 去除重复项，保持顺序
    unique_lines = []
    seen = set()
    for line in modified_lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)

    # 写入输出文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in unique_lines:
                f.write(line + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_delete_duplicate_by_char():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        delete_duplicate(input_file, output_file)


def delete_duplicate(input_file, output_file):
    # 读取输入文件
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("输入文件未找到。")
        exit()

    # 去除重复项，保持顺序
    unique_lines = []
    seen = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)

    # 写入输出文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in unique_lines:
                f.write(line)
    except IOError:
        print("无法写入输出文件。")


def run_delete_duplicate():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        delete_duplicate(input_file, output_file)


def combine_domain(whitelist_old, whitelist_new):
    # 读取第一个文件并处理
    try:
        with open(whitelist_old, 'r', encoding='utf-8') as f:
            old_lines = [line.strip() for line in f]
    except FileNotFoundError:
        print("第一个输入文件未找到。")
        exit()

    # 删除以#开头的行并去除重复项
    filtered_lines = [line for line in old_lines if not line.startswith('#')]
    unique_lines = []
    seen = set()
    for line in filtered_lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)

    # 读取第二个文件
    try:
        with open(whitelist_new, 'r', encoding='utf-8') as f:
            new_lines = [line.strip() for line in f]
    except FileNotFoundError:
        print("第二个输入文件未找到。")
        exit()

    # 找到第二个文件中不在第一个文件中的内容
    unique_set = set(unique_lines)
    additional_lines = [line for line in new_lines if line not in unique_set]

    # 合并结果
    result = unique_lines + additional_lines

    # 写入输出文件
    try:
        with open(whitelist_old, 'w', encoding='utf-8') as f:
            for line in result:
                f.write(line + '\n')
    except IOError:
        print("无法写入输出文件。")


def run_combine_domain():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        whitelist_old = sys.argv[1]
        whitelist_new = sys.argv[2]
        combine_domain(whitelist_old, whitelist_new)


def find_domain_difference_and_put_newfile(domain, white_domain, gray_domain):
    try:
        # 读取第一个文件，转换为小写并去掉空格，忽略空行
        with open(domain, 'r', encoding='utf-8') as domain:
            domain = set(line.strip().lower()
                         for line in domain if line.strip())

        # 读取第二个文件，转换为小写并去掉空格，忽略空行
        with open(white_domain, 'r', encoding='utf-8') as white_domain:
            white_domain = set(line.strip().lower()
                               for line in white_domain if line.strip())

        # 找出在第一个文件中但不在第二个文件中的域名
        difference = domain - white_domain

        # 将结果写入新文件，每行一个域名
        with open(gray_domain, 'w', encoding='utf-8') as gray_domain:
            for item in sorted(difference):  # 按顺序输出以便阅读
                gray_domain.write(item + '\n')

        print(f"结果已输出到 {gray_domain.json}")

    except FileNotFoundError:
        print("错误：文件未找到，请检查文件路径。")
    except Exception as e:
        print(f"发生错误：{e}")


def run_find_domain_difference_and_put_newfile():
    if len(sys.argv) != 4:
        print("Usage: python script.py old.json new.json output.json")
    else:
        domain = sys.argv[1]
        white_domain = sys.argv[2]
        gray_domain = sys.argv[3]
        find_domain_difference_and_put_newfile(
            domain, white_domain, gray_domain)


if __name__ == "__main__":
    # run_obtain_new_domain_everyday()
    # run_remove_duplicate_and_combine_and_obtain_different()
    # run_obtain_new_domain()
    run_send_to_browser_request()
    # run_read_file_to_set_and_sorted()
    # run_remove_duplicate_and_combine()
    # run_counte_white_domain_suffix()
    # run_find_domain_difference_and_put_newfile()
    # compare_domain()
    # run_delete_duplicate()
    # run_domain_to_lower()
    # run_check_combine_is_right()
    # run_check_url_with_threadpool()
