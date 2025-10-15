import os
import zipfile
from pathlib import Path
import shutil

# 외장하드 폴더 경로 (압축 파일들이 있는 곳)
source_folder = r"E:\10. 작업"

# 추출된 문서를 저장할 로컬 폴더
target_folder = "data_docs"

os.makedirs(target_folder, exist_ok=True)

# 재귀적으로 모든 zip 파일 탐색
for root, _, files in os.walk(source_folder):
    for file in files:
        if file.lower().endswith(".zip"):
            zip_path = os.path.join(root, file)
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    for zip_info in zip_ref.infolist():
                        if zip_info.filename.lower().endswith(('.docx', '.txt')):
                            # 중복 방지 이름 생성
                            filename = Path(zip_info.filename).name
                            target_path = os.path.join(target_folder, filename)

                            # 이름 중복 시 고유한 이름으로
                            base, ext = os.path.splitext(filename)
                            count = 1
                            while os.path.exists(target_path):
                                target_path = os.path.join(target_folder, f"{base}_{count}{ext}")
                                count += 1

                            with zip_ref.open(zip_info) as src, open(target_path, "wb") as dest:
                                shutil.copyfileobj(src, dest)
            except Exception as e:
                print(f"❌ 오류 - {zip_path}: {e}")
