import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import bcrypt
import sqlite3
import os
import pytz

# 데이터베이스 연결
def get_db_connection():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    return conn

# 데이터베이스 초기화
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY, password TEXT, is_admin INTEGER, first_login INTEGER)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS attendance
                    (username TEXT, timestamp TEXT)''')
    
    # 기존 사용자 확인
    existing_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    
    if existing_users == 0:
        # 관리자 계정 생성
        admin_password = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt())
        conn.execute('INSERT INTO users (username, password, is_admin, first_login) VALUES (?, ?, ?, ?)',
                     ('admin1', admin_password, 1, 0))
        
        # 학생 계정 생성
        for class_num in range(1, 8):
            for student_num in range(1, 26):
                user_id = f'1{class_num:02d}{student_num:02d}'  # 예: 1학년 1반 1번 -> '10101'
                initial_password = f'{user_id}'  # 초기 비밀번호를 사용자 ID와 동일하게 설정
                password = bcrypt.hashpw(initial_password.encode(), bcrypt.gensalt())
                conn.execute('INSERT INTO users (username, password, is_admin, first_login) VALUES (?, ?, ?, ?)',
                             (user_id, password, 0, 1))
        
        conn.commit()
        st.success("데이터베이스가 성공적으로 초기화되었습니다.")
    else:
        st.info("데이터베이스가 이미 초기화되어 있습니다.")
    
    conn.close()

# 로그인 함수
def login(username, password):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user:
        stored_password = user['password']
        if bcrypt.checkpw(password.encode(), stored_password):
            return user
        else:
            st.error(f"비밀번호가 일치하지 않습니다.")
            return None
    else:
        st.error(f"사용자 '{username}'을(를) 찾을 수 없습니다.")
        return None

# 비밀번호 변경 함수
def change_password(username, new_password):
    conn = get_db_connection()
    new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    conn.execute('UPDATE users SET password = ?, first_login = 0 WHERE username = ?', (new_password_hash, username))
    conn.commit()
    conn.close()

# 출석 체크 함수
def check_attendance(username):
    # 한국 시간대 설정
    korea_tz = pytz.timezone('Asia/Seoul')
    now = datetime.now(korea_tz)
    
    if now.weekday() < 5:  # 월요일부터 금요일까지
        if (19 <= now.hour < 20) or (now.hour == 20 and now.minute <= 20) or \
           (20 <= now.hour < 21) or (now.hour == 21 and now.minute <= 50):
            conn = get_db_connection()
            conn.execute('INSERT INTO attendance (username, timestamp) VALUES (?, ?)',
                         (username, now.strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            conn.close()
            return True
    return False

# 비밀번호 초기화 함수
def reset_password(username):
    conn = get_db_connection()
    initial_password = f'{username}'  # 초기 비밀번호를 사용자 ID와 동일하게 설정
    new_password_hash = bcrypt.hashpw(initial_password.encode(), bcrypt.gensalt())
    conn.execute('UPDATE users SET password = ?, first_login = 1 WHERE username = ?', (new_password_hash, username))
    conn.commit()
    conn.close()
    return initial_password

# 메인 앱
def main():
    st.title('야간 자율학습 출석 체크 시스템')

    if not os.path.exists('attendance.db'):
        st.warning("데이터베이스 파일이 없습니다. 초기화를 진행합니다.")
        init_db()

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        username = st.text_input('아이디')
        password = st.text_input('비밀번호', type='password')
        if st.button('로그인'):
            user = login(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.first_login = user['first_login']
                st.session_state.is_admin = user['is_admin']
                st.success('로그인 성공!')
                st.rerun()
            else:
                st.error('로그인 실패. 아이디와 비밀번호를 확인해주세요.')
    else:
        if st.session_state.first_login:
            st.warning('첫 로그인입니다. 비밀번호를 변경해주세요.')
            new_password = st.text_input('새 비밀번호', type='password')
            if st.button('비밀번호 변경'):
                change_password(st.session_state.username, new_password)
                st.session_state.first_login = False
                st.success('비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.')
                st.session_state.logged_in = False
                st.rerun()
        else:
            if st.session_state.is_admin:
                admin_view()
            else:
                student_view()

        if st.button('로그아웃'):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

def student_view():
    st.write(f'안녕하세요, {st.session_state.username}님!')
    
    if st.button('출석 체크'):
        if check_attendance(st.session_state.username):
            st.success('출석이 완료되었습니다.')
        else:
            st.error('현재 출석 체크 가능한 시간이 아닙니다.')
    
    if st.button('비밀번호 변경'):
        new_password = st.text_input('새 비밀번호', type='password')
        if st.button('변경 확인'):
            change_password(st.session_state.username, new_password)
            st.success('비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.')
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

def admin_view():
    st.write('관리자 페이지')
    
    # 비밀번호 초기화 섹션
    st.subheader('비밀번호 초기화')
    reset_username = st.text_input('초기화할 사용자의 아이디')
    if st.button('비밀번호 초기화'):
        if reset_username:
            initial_password = reset_password(reset_username)
            st.success(f"사용자 {reset_username}의 비밀번호가 초기화되었습니다.")
            st.info(f"초기 비밀번호: {initial_password}")
        else:
            st.error('사용자 아이디를 입력해주세요.')
    
    # 출석 데이터 표시 섹션
    st.subheader('출석 데이터')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(attendance)")
    columns = [column[1] for column in cursor.fetchall()]
    st.write("데이터베이스 테이블 구조:", columns)

    attendance_data = conn.execute('SELECT * FROM attendance ORDER BY timestamp DESC').fetchall()
    conn.close()

    if attendance_data:
        df = pd.DataFrame(attendance_data, columns=columns)
        st.write("DataFrame 열:", df.columns)
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df['week'] = df['timestamp'].dt.to_period('W').astype(str)

            weeks = sorted(df['week'].dropna().unique(), reverse=True)
            if weeks:
                selected_week = st.selectbox('주 선택', weeks)
                filtered_df = df[df['week'] == selected_week]
                st.write(filtered_df)
            else:
                st.write('유효한 날짜 데이터가 없습니다.')
        else:
            st.error("출석 데이터에 'timestamp' 열이 없습니다.")
            st.write("사용 가능한 열:", df.columns)
    else:
        st.write('출석 데이터가 없습니다.')


if __name__ == '__main__':
    main()
