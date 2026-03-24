# 🔒 병리팀 PC 보안점수 IP 지도 시스템

## 빠른 시작

### 1. 설치
```bash
pip install fastapi uvicorn pandas openpyxl python-multipart
```

### 2. 실행
```bash
cd backend
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

### 3. 접속
브라우저에서 `http://localhost:8000` 접속

### 4. 초기 설정
사이드바에서 정보보호실 엑셀 파일 업로드 → 검사실/PC 자동 등록

## 사용법

### 보안점수 조회
- 전체 맵 / 검사실별 상세 조회
- 🟢 정상(100점) · 🔴 미달 · ⚪ 미등록
- 미달 PC 클릭 시 해당 검사실로 이동

### 보안점수 업로드
- 사이드바 하단 "보안점수 엑셀 업로드"
- 정보보호실 엑셀 그대로 업로드

### 관리
- **검사실**: 추가/수정(이름, 그리드 크기)/삭제
- **PC 관리**: 드래그로 위치 이동, 빈 셀 클릭으로 추가, 선택 후 수정/삭제
- **초기화**: 엑셀 재업로드로 전체 리셋

## 병원 내부망 배포
```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```
다른 PC에서 `http://서버IP:8000` 접속

## 파일 구조
```
backend/
├── server.py           # FastAPI 서버 + DB
├── static/
│   └── index.html      # React 프론트엔드
└── data/
    └── security_map.db # SQLite (자동 생성)
```
