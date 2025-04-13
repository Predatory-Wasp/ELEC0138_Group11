import os
import pandas as pd


def add_label_column_from_filename(csv_path):
    """
    讀取 Wireshark 匯出的 CSV（如含 No., Time, Source, Destination, Protocol, Length, Info）
    並依檔名自動新增 'label' 欄位，標記該流量是 Normal 還是特定攻擊。

    :param csv_path: CSV 檔案路徑，如 'data/syn.csv'、'data/normal.csv' 等
    :return: 回傳含新欄位 label 的 DataFrame
    """
    # 1. 讀取原始 CSV
    df = pd.read_csv(csv_path)

    # 2. 依照檔案名稱來判斷是何種攻擊或正常流量
    #    這裡可自行擴充 mapping，或以一連串 if/elif... 撰寫
    filename = os.path.basename(csv_path).lower()  # 取出檔名並轉小寫，方便比對
    if "normal" in filename:
        label_value = "Normal"
    elif "syn" in filename:
        label_value = "SYN_Flood"
    elif "udp" in filename:
        label_value = "UDP_Flood"
    elif "icmp" in filename:
        label_value = "ICMP_Flood"
    elif "http" in filename:
        label_value = "HTTP_Flood"
    else:
        label_value = "Unclassified"

    # 3. 新增 'label' 欄位
    df['label'] = label_value

    # 4. （可選）可以重新命名欄位，讓後續好做特徵處理
    #    例如改名: Time -> timestamp, Source -> src_ip, Destination -> dst_ip, Length -> packet_len
    df = df.rename(columns={
        'Time': 'timestamp',
        'Source': 'src_ip',
        'Destination': 'dst_ip',
        'Protocol': 'protocol',
        'Length': 'packet_len',
        'Info': 'info'  # 依需求可保留或刪除
    })

    # 5. 回傳 DataFrame，或可在這裡直接另存成新的 CSV
    # df.to_csv("xxx_labeled.csv", index=False)
    return df


if __name__ == "__main__":
    # 假設有幾個檔案
    csv_files = [
        "C:/Users/ASUS/Desktop/normal traffic.csv",
        "C:/Users/ASUS/Desktop/tcp syn flood attack.csv",
        "C:/Users/ASUS/Desktop/UDP flood attack.csv",
        "C:/Users/ASUS/Desktop/ICMP attack.csv",
        "C:/Users/ASUS/Desktop/http flood attack.csv"
        # ...
    ]

    # 逐一處理，每個 CSV 自動加上 label 欄位
    for f in csv_files:
        labeled_df = add_label_column_from_filename(f)
        print(f"檔案 {f} 已新增 label='{labeled_df['label'].unique()[0]}'")
        print("前五筆資料:")
        print(labeled_df.head())
        print("-" * 50)

        # 若需存成新檔，可自行指定輸出路徑
        out_name = f.replace(".csv", "_labeled.csv")
        labeled_df.to_csv(out_name, index=False)
