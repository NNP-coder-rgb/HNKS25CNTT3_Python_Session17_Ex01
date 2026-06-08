import re

# Khởi tạo kho lưu trữ log toàn cục
raw_logs = []
processed_logs = []

def clean_data(str_input: str) -> int:
    """Làm sạch chuỗi log thô bằng cách loại bỏ các ký tự đặc biệt (!@#$)
    và phân tách chúng thành danh sách các log riêng biệt.

    Args:
        str_input (str): Chuỗi log thô nhận vào từ người dùng.

    Returns:
        int: Số lượng dòng log hợp lệ đã được làm sạch và thêm vào hệ thống.
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
    """Lọc các dòng log có chứa từ khóa nguy hiểm (ERROR hoặc CRITICAL).
    Kết quả sẽ làm mới và cập nhật vào danh sách processed_logs.

    Args:
        logs_list (list): Danh sách các log thô cần kiểm tra.

    Returns:
        int: Số lượng log nguy hiểm tìm thấy.
    """
    global processed_logs
    # Làm mới danh sách processed_logs để tránh trùng lặp dữ liệu khi chạy lại nhiều lần
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
    """Tìm và làm mờ 2 Octet cuối của địa chỉ IPv4 trong danh sách log bằng dấu '*'.
    Sử dụng Regular Expression để đảm bảo độ chính xác ngay cả khi IP dính dấu câu.

    Args:
        danger_logs (list): Danh sách các log chứa cảnh báo cần che dấu IP.

    Returns:
        list: Danh sách log mới đã được mã hóa địa chỉ IP.
    """
    masked_result = []
    # Regex nhận diện IPv4 dạng X.X.X.X
    ip_pattern = r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'

    for log in danger_logs:
        # Thay thế octet thứ 3 và 4 thành '*'
        masked_log = re.sub(ip_pattern, r'\1.\2.*.*', log)
        masked_result.append(masked_log)
        
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
