import pandas as pd
import sys
from docx import Document
import openpyxl
import json
from flatten_json import flatten


def sort_by_columns(file_path, column_to_sort):
    try:
        # 读取 Excel 文件
        df = pd.read_excel(file_path)

        # 按指定列排序，默认为升序
        sorted_df = df.sort_values(by=column_to_sort, ascending=False)

        # 打印排序后的数据
        # print("排序后的数据：")
        # print(sorted_df)

        sorted_df.to_excel('sorted_data.xlsx', index=False)

    except FileNotFoundError:
        print("错误：找不到指定的 Excel 文件，请检查文件路径。")
    except KeyError:
        print("错误：指定的列名不存在，请检查 column_to_sort 是否正确。")
    except Exception as e:
        print(f"发生错误：{e}")


def run_sort_by_columns():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        file_path = sys.argv[1]
        column_to_sort = sys.argv[2]
        sort_by_columns(file_path, column_to_sort)


def add_comma_to_weak_password(input_file, output_file):
    # 打开输入文件读取，输出文件写入
    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        # 读取每行，移除尾部空白（包括换行符）
        lines = [line.strip() for line in infile]
        # 将所有行用逗号连接，并写入输出文件
        outfile.write(','.join(lines))


def run_add_comma_to_weak_password():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        add_comma_to_weak_password(input_file, output_file)


def convert_word_table_to_excel(word_file_path, excel_file_path):
    # 加载Word文档
    doc = Document(word_file_path)

    # 假设文档中只有一个表格，或者我们取第一个表格
    # 如果有多个表格，可以根据需要调整索引
    table = doc.tables[0]

    # 创建一个新的Excel工作簿
    wb = openpyxl.Workbook()
    ws = wb.active

    # 遍历Word表格的行和列
    for row_idx, row in enumerate(table.rows, start=1):
        for col_idx, cell in enumerate(row.cells, start=1):
            # 将单元格文本写入Excel对应位置
            ws.cell(row=row_idx, column=col_idx, value=cell.text.strip())

    # 保存Excel文件
    wb.save(excel_file_path)
    print(f"转换完成：{word_file_path} -> {excel_file_path}")


def run_convert_word_table_to_excel():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        convert_word_table_to_excel(input_file, output_file)


def flatten_json_to_excel(input_file, output_file):
    # 读取JSON文件
    with open(input_file, 'r') as f:
        json_data = json.load(f)

    # 如果JSON数据是一个列表，处理每个对象
    if isinstance(json_data, list):
        all_flattened = [flatten(item) for item in json_data]
    else:
        all_flattened = [flatten(json_data)]

    # 将所有键值对转换为DataFrame
    rows = []
    for idx, flattened in enumerate(all_flattened):
        for key, value in flattened.items():
            rows.append({'Index': idx, 'Key': key, 'Value': value})

    df = pd.DataFrame(rows)

    # 保存到Excel文件
    df.to_excel(output_file, index=False, engine='openpyxl')

    print(f"数据已保存到 {output_file}")


def run_flatten_json_to_excel():
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.txt")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        flatten_json_to_excel(input_file, output_file)


if __name__ == "__main__":
    # run_sort_by_columns()
    # run_add_comma_to_weak_password()
    # run_convert_word_table_to_excel()
    run_flatten_json_to_excel()
