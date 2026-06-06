raw_logs = []
processed_logs = []

def clean_data(str_input):
    new_str = str.maketrans('','','!@#$')
    new_list = str_input.translate(new_str)

    list_log = [log.strip() for log in new_list.split(';')]
    global raw_logs
    raw_logs.extend(list_log)
    return len(list_log)

def filter_data(raw_logs):
    result = [
                log for log in raw_logs
                if "error" in log.lower() or "critical" in log.lower()
              ]
    for log in result:
        processed_logs.append(log)
    return len(result)

def mask_ip_data(danger_logs):
    masked_result = []
    for log in danger_logs:
        words = log.split()
        for i in range(len(words)):
            if '.' in words[i] and len(words[i].split('.')) == 4:
                ip_parts = words[i].split('.')
                ip_parts[2] = '*'
                ip_parts[3] = '*'
                words[i] = '.'.join(ip_parts)
        masked_result.append(' '.join(words))
    return masked_result

def show_menu():
    print('\n============= SECURITY LOG ANALYZER =============')
    print('1. Nhập và làm sạch dữ liệu Log thô')
    print('2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)')
    print('3. Mã hóa địa chỉ IP (Masking)')
    print('4. Đóng hệ thống')
    print('=================================================')

def main():
    option = ''
    while option != '4':
        show_menu()
        option = input('Chọn chức năng(1-4): ')
        match option:
            case '1':
                print()
                str_input = input('Nhập chuỗi log thô (cách nhau bởi dấu ;): ')
                len = clean_data(str_input)
                
                if len > 0:
                    print(f'Đã làm sạch và lưu {len} dòng log vào hệ thống.')
            case '2':
                print()
                result = filter_data(raw_logs)   
                print(f'Tìm thấy {result} cảnh báo nguy hiểm:')
                for log in processed_logs:
                    print(f'- {log}')
            case '3':
                print()
                print('\n--- MÃ HÓA IP ---')
                if not processed_logs:
                    print('Không có log nguy hiểm nào để mã hóa. Vui lòng chạy chức năng 2 trước!')
                else:
                    final_report = mask_ip_data(processed_logs)
                    
                    print('Báo cáo log an toàn:')
                    for index, log in enumerate(final_report, 1):
                        print(f'{index}. {log}')
            case '4':
                print('\nCảm ơn đã sử dụng chương trình!\n')
            case _:
                print('\nLựa chọn không hợp lệ, vui lòng nhập lại!\n')
main()

