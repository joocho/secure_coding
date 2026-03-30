# 실습 1: 드론/CCTV 영상 객체 탐지 (OpenCV & Pre-trained Model)

## 목표

+ 이미 학습된 모델(YOLO 등)을 활용하여 경계 감시 영상 속에서 사람이나 차량을 식별하고 박스를 그리는 실습


+ 핵심 기술: OpenCV를 이용한 이미지 처리, 기초 딥러닝 모델 로드 및 추론(Inference).

## 실습 도구

+ 언어: Python (기초)

+ 환경: Google Colab (GPU 사용 권장)

+ 핵심 라이브러리: OpenCV (cv2) - 이미지/영상 처리

+ AI 모델: Ultralytics YOLOv8 (설치와 사용이 가장 간편함)

## 실행 순서

### 1단계: 환경 설정 

Colab에서 라이브러리 설치(!pip), 모델 로드.

```python

# 1. 라이브러리 설치 (Colab에서는 맨 처음 한 번만)
!pip install ultralytics

# 2. 모델 불러오기 (가장 가벼운 nano 버전 사용)
from ultralytics import YOLO
model = YOLO('yolov8n.pt') # 자동으로 모델 다운로드 및 로드

print("AI 모델 준비 완료!")
```

### 2단계: 이미지 한 장에서 객체 탐지하기 

모델에 이미지 입력하기, 결과(Bounding Box) 확인, OpenCV로 이미지 읽기/쓰기.

```python
import cv2
from google.colab.patches import cv2_imshow
from ultralytics import YOLO
import os

# 1. 모델 로드
model = YOLO('yolov8n.pt')

# 2. 파일 존재 여부 확인 및 자동 지정 (안전한 방법)
# 만약 파일이 없다면 공식 URL에서 직접 가져오도록 설정합니다.
source_img = 'https://ultralytics.com/images/bus.jpg'

# 3. AI 추론 실행
# save=True를 하면 'runs/detect/predict/' 폴더에 결과가 저장됩니다.
results = model.predict(source=source_img, save=True)

# 4. 결과 시각화 (첫 번째 결과물 가져오기)
res_plotted = results[0].plot()

# 5. 화면에 출력
cv2_imshow(res_plotted)

```


### 3 단계: 비디오 영상 분석하기

```python
import cv2
from ultralytics import YOLO
from ultralytics.utils.downloads import download
from pathlib import Path

# 1. 모델 로드
model = YOLO('yolov8n.pt')

# 2. 영상 소스 설정 (YOLO 공식 샘플 URL)
video_url = 'https://videos.pexels.com/video-files/854671/854671-hd_1920_1080_25fps.mp4'
video_path = '854671-hd_1920_1080_25fps.mp4'

# 3. 파일이 없거나 깨졌을(9B) 경우를 대비해 확실히 다운로드
if not Path(video_path).exists() or Path(video_path).stat().st_size < 100:
    print("영상 파일을 다운로드 중...")
    download(video_url)

# 4. 비디오 읽기 설정
cap = cv2.VideoCapture(video_path)

# 영상 정보 추출
w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
fps = int(cap.get(cv2.CAP_PROP_FPS))

# 5. 결과 저장 설정 (output_monitoring.mp4)
fourcc = cv2.VideoWriter_fourcc(*'mp4v')
out = cv2.VideoWriter('output_monitoring.mp4', fourcc, fps, (w, h))

print("영상 분석 시작...")

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    # AI 분석 (추론)
    results = model(frame, verbose=False)

    # 박스 그려진 이미지 가져오기
    res_plotted = results[0].plot()

    # 결과 파일에 프레임 쓰기
    out.write(res_plotted)

# 자원 해제
cap.release()
out.release()

print("\n--- 분석 완료! ---")
print("왼쪽 폴더 메뉴에서 'output_monitoring.mp4'를 확인하세요.")
```


### 4단계: 간단한 변형

현재 프레임에서 탐지된 객체 수 파악하고 영상 좌측 상단에 실시간으로 **"Detected: N"**이라는 문구를 삽입.


```python
import cv2
from ultralytics import YOLO
from ultralytics.utils.downloads import download
from pathlib import Path

# 1. 모델 로드
model = YOLO('yolov8n.pt')

# 2. 영상 소스 설정 (YOLO 공식 샘플 URL)
video_url = 'https://videos.pexels.com/video-files/854671/854671-hd_1920_1080_25fps.mp4'
video_path = '854671-hd_1920_1080_25fps.mp4'

# 3. 파일이 없거나 깨졌을(9B) 경우를 대비해 확실히 다운로드
if not Path(video_path).exists() or Path(video_path).stat().st_size < 100:
    print("영상 파일을 다운로드 중...")
    download(video_url)

# 4. 비디오 읽기 설정
cap = cv2.VideoCapture(video_path)

# 영상 정보 추출
w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
fps = int(cap.get(cv2.CAP_PROP_FPS))

# 5. 결과 저장 설정 (output_monitoring.mp4)
fourcc = cv2.VideoWriter_fourcc(*'mp4v')
out = cv2.VideoWriter('output_monitoring.mp4', fourcc, fps, (w, h))

print("영상 분석 시작...")

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    # AI 분석 (추론)
    results = model(frame, verbose=False)

    # 1. 현재 프레임에서 탐지된 객체 수 파악
    obj_count = len(results[0].boxes)

    # 2. 박스 그려진 이미지 가져오기
    res_plotted = results[0].plot()

    # 3. 영상 위에 텍스트 정보 기입 (OpenCV 활용)
    # 문구, 위치(x,y), 폰트, 크기, 색상(B,G,R), 두께 순서
    text = f"DETECTED: {obj_count}"
    cv2.putText(res_plotted, text, (50, 80),
                cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 0, 255), 3)


    # 결과 파일에 프레임 쓰기
    out.write(res_plotted)

# 자원 해제
cap.release()
out.release()

print("\n--- 분석 완료! ---")
print("왼쪽 폴더 메뉴에서 'output_monitoring.mp4'를 확인하세요.")

```

### 5단계: 실제 필요로 하는 로직을 간단하게 구현

파이썬의 조건문(If)과 리스트를 활용합니다.

#### 아이디어 A: 특정 객체(사람/차량)만 탐지하기

YOLO는 80가지 객체를 탐지하지만, 어떤 경우는 사람(class 0), 차량(class 2)만 중요할 수 있습니다.

model('image.jpg', classes=[0, 2]) 처럼 옵션을 주어 필터링

#### 아이디어 B: 침입 감지 알람 (객체 수 카운팅)

"경계 구역 내에 사람이 3명 이상 포착되면 경보를 울린다."

추론 결과 데이터 구조를 분해하여, 탐지된 '사람'의 수를 세고 조건문을 처리

```python
while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    # 1. AI 분석 (추론)
    results = model(frame, verbose=False)
    
    # 2. '사람(Class 0)'만 필터링하여 숫자 세기
    # results[0].boxes.cls에 탐지된 모든 물체의 ID가 들어있습니다.
    person_count = 0
    for box in results[0].boxes:
        class_id = int(box.cls[0]) # 객체의 클래스 번호 추출
        if class_id == 0:          # 0번은 'person' (사람)
            person_count += 1

    # 3. 시각화 (기본 박스 그리기)
    res_plotted = results[0].plot()

    # 4. 조건문 처리: 3명 이상일 때 경보 문구 표시
    if person_count >= 3:
        # 경고 문구 (빨간색)
        alert_text = f"ALERT: {person_count} PERSONS DETECTED!"
        cv2.putText(res_plotted, alert_text, (50, 100), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1.5, (0, 0, 255), 4)
        
        # 실제 실무라면 여기서 이메일 발송, 경보음 재생, 혹은 SMS 전송 함수를 호출합니다.
        # print("경보 발령: 거동수상자 다수 포착!") 
    else:
        # 정상 상태 표시 (녹색)
        cv2.putText(res_plotted, f"Monitoring... (Count: {person_count})", (50, 100), 
                    cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 255, 0), 2)

    # 결과 프레임 저장
    out.write(res_plotted)
```
