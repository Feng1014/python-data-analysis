import json
import re
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import time


def read_file(input_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'objects' not in data:
            print("Error: 'objects' key not found in JSON.")
            return
        objects = data['objects']
        if not isinstance(objects, list):
            print("Error: 'objects' is not a list.")
            return
        patterns = [obj.get('pattern') for obj in objects if 'pattern' in obj]
        return patterns
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
    except json.JSONDecodeError:
        print(f"Error: {input_file} is not a valid JSON file.")
    except Exception as e:
        print(f"An error occurred: {e}")


def extract_patterns(input_file, output_file):
    try:
        patterns = read_file(input_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            for pattern in patterns:
                f.write(pattern + '\n')
        print(f"Successfully extracted {len(patterns)} patterns.")
    except Exception as e:
        print(f"An error occurred: {e}")


def extract_patterns_start_with_url(input_file, output_file):
    try:
        patterns = read_file(input_file)
        pattern_grep = r"\[url:value='https?://(?!\d+\.\d+\.\d+\.\d+)(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::[0-9]{1,5})?(?:\/[\w./?%&=-]*)?'\]"
        url_list = []
        with open(output_file, 'w', encoding='utf-8') as f:
            for pattern in patterns:
                matches = re.findall(pattern_grep, pattern)
                for match in matches:
                    url_list.append(match)
            for url in url_list:
                f.write(url + '\n')
        print(f"Total patterns added to list and saved: {len(url_list)}")
    except Exception as e:
        print(f"An error occurred: {e}")


def extract_patterns_include_domain(input_file, output_file):
    try:
        patterns = read_file(input_file)
        # pattern_grep = r"https?://(?!\d+\.\d+\.\d+\.\d+)(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::[0-9]{1,5})?(?:\/[\w./?%&=-]*)?"
        pattern_grep = r"https?://(?!\d+\.\d+\.\d+\.\d+)(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::[0-9]{1,5})?"
        with open(output_file, 'w', encoding='utf-8') as f:
            total = 0
            for pattern in patterns:
                matches = re.findall(pattern_grep, pattern)
                total += len(matches)
                for match in matches:
                    f.write(match + '\n')
            print(f"Total domains extracted: {total}")
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
    except json.JSONDecodeError:
        print(f"Error: {input_file} is not a valid JSON file.")
    except Exception as e:
        print(f"An error occurred: {e}")


def analyze_domains(input_file, output_file):
    keywords = {'baidu', 'google', 'microsoft', 'apple'}
    matched_urls = []  # List to store (pattern, status) tuples
    try:
        with open(input_file, 'r', encoding='utf-8') as f_in:
            for line in f_in:
                if any(keyword in line.lower() for keyword in keywords):
                    matched_urls.append(line)
        # Save results to output file
        with open(output_file, 'w', encoding='utf-8') as f_out:
            for url in matched_urls:
                f_out.write(url.strip() + '\n')
        print(f"Total URLs matched: {len(matched_urls)}")

    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def check_url(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            print(f"[OK] {url}")
            return url
        else:
            print(f"[FAIL {response.status_code}] {url}")
        return None
    except requests.exceptions.RequestException:
        return None


def check_url_with_threadpool(input_file, output_file):

    # Read URLs from file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
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


def check_duplicate_urls(input_file):
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        counts = Counter(urls)
        duplicates = [url for url, count in counts.items() if count > 1]

        if duplicates:
            print("found duplicated URL:")
            for url in duplicates:
                print(url)
        else:
            print("not found duplicated URL")
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        # extract_patterns_include_domain(input_file, output_file)
        # analyze_domains(input_file, output_file)
        check_url_with_threadpool(input_file, output_file)

    # read_file('.\\stix-white.json')

    # if len(sys.argv) != 2:
    #     print("Usage: python script.py input.json")
    # else:
    #     input_file = sys.argv[1]
    #     check_duplicate_urls(input_file)
