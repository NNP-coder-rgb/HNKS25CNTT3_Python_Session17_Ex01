# Khởi tạo kho lưu trữ log toàn cục
raw_logs = []
processed_logs = []

def clean_data(str_input: str) -> int:
    """Làm sạch chuỗi log thô bằng cách loại bỏ các ký tự đặc biệt (!@#$)
    và phân tách chúng thành danh sách các log riêng biệt.
    """
    if not str_input.strip():
        return 0

    # Loại bỏ các ký tự đặc biệt ! @ # $
    translation_table = str.maketrans('', '', '!@#$')
    cleaned_string = str_input.translate(translation_table)

    # Tách chuỗi bằng dấu chấm phẩy và loại bỏ khoảng trắng thừa
    list_log = [log.strip() for log in cleaned_string.split(';') if log.strip()]
    
    global raw_logs
    raw_logs.extend(list_log)
    return len(list_log)

def filter_data(logs_list: list) -> int:
    """Lọc các dòng log có chứa từ khóa nguy hiểm (ERROR hoặc CRITICAL)."""
    global processed_logs
    processed_logs = []

    if not logs_list:
        return 0

    result = [
        log for log in logs_list
        if "error" in log.lower() or "critical" in log.lower()
    ]
    
    processed_logs.extend(result)
    return len(result)

def mask_ip_data(danger_logs: list) -> list:
    """Tìm và làm mờ 2 Octet cuối của địa chỉ IPv4 bằng cách tách chuỗi thủ công,
    không sử dụng thư viện re (Regex).
    """
    masked_result = []
    
    for log in danger_logs:
        # Tách dòng log thành từng từ để kiểm tra xem từ nào là IP
        words = log.split()
        for i in range(len(words)):
            word = words[i]
            
            # Tách các dấu câu dính ở đầu hoặc cuối từ (ví dụ: "192.168.1.1,", "10.0.0.1:")
            prefix = ""
            suffix = ""
            while word and not word[0].isdigit():
                prefix += word[0]
                word = word[1:]
            while word and not word[-1].isdigit():
                suffix = word[-1] + suffix
                word = word[:-1]
                
            # Kiểm tra xem từ này có cấu trúc giống IPv4 (X.X.X.X) không
            parts = word.split('.')
            if len(parts) == 4:
                # Kiểm tra cả 4 phần có phải là số từ 0 - 255 không
                is_ip = True
                for part in parts:
                    if not part.isdigit() or not (0 <= int(part) <= 255):
                        is_ip = False
                        break
                
                # Nếu đúng là IP, tiến hành che 2 octet cuối (*.*)
                if is_ip:
                    masked_ip = f"{parts[0]}.{parts[1]}.*.*"
                    words[i] = prefix + masked_ip + suffix
                    
        # Ghép các từ lại thành dòng log hoàn chỉnh
        masked_result.append(" ".join(words))
        
    return masked_result

def show_menu():
    """Hiển thị menu giao diện điều khiển của hệ thống."""
    print('\n============= SECURITY LOG ANALYZER =============')
    print('1. Nhập và làm sạch dữ liệu Log thô')
    print('2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)')
    print('3. Mã hóa địa chỉ IP (Masking)')
    print('4. Đóng hệ thống')
    print('=================================================')

def main():
    """Hàm điều khiển luồng chạy chính của chương trình."""
    option = ''
    while option != '4':
        show_menu()
        option = input('Chọn chức năng (1-4): ').strip()
        
        match option:
            case '1':
                print()
                str_input = input('Nhập chuỗi log thô (cách nhau bởi dấu ;): ')
                logs_count = clean_data(str_input)
                
                if logs_count > 0:
                    print(f'==> Thành công: Đã làm sạch và lưu {logs_count} dòng log vào hệ thống.')
                else:
                    print('==> Cảnh báo: Không có log nào dữ liệu hợp lệ được nhập!')
                    
            case '2':
                print()
                if not raw_logs:
                    print('==> Thông báo: Bộ nhớ trống. Vui lòng chạy chức năng 1 để nhập log trước!')
                else:
                    result_count = filter_data(raw_logs)   
                    if result_count > 0:
                        print(f'Tìm thấy {result_count} cảnh báo nguy hiểm:')
                        for log in processed_logs:
                            print(f'- {log}')
                    else:
                        print('==> Thông báo: Tuyệt vời! Không tìm thấy log nào có mức độ ERROR hay CRITICAL.')
                        
            case '3':
                print()
                print('--- MÃ HÓA IP ---')
                if not processed_logs:
                    print('==> Thông báo: Không có log nguy hiểm nào để mã hóa. Vui lòng chạy chức năng 2 trước!')
                else:
                    final_report = mask_ip_data(processed_logs)
                    print('Báo cáo log an toàn sau khi Masking:')
                    for index, log in enumerate(final_report, 1):
                        print(f'{index}. {log}')
                        
            case '4':
                print('\nCảm ơn đã sử dụng chương trình!\n')
                
            case _:
                print('\nLựa chọn không hợp lệ, vui lòng nhập lại từ 1 đến 4!\n')

if __name__ == '__main__':
    main()
