import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import bcrypt
import sqlite3
import os

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
                user_id = f'1{class_num:02d}{student_num:02d}'
                initial_password = f'init{user_id}'  # 초기 비밀번호를 'init' + 사용자 ID로 설정
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
            st.error(f"비밀번호가 일치하지 않습니다. (입력된 비밀번호: {password})")
            st.error(f"저장된 해시: {stored_password}")
            return None
    else:
        st.error(f"사용자 '{username}'을(를) 찾을 수 없습니다.")
        return None

# 사용자 정보 확인
def check_user_info(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user:
        st.write(f"사용자 정보: {dict(user)}")
    else:
        st.write(f"사용자 '{username}'을(를) 찾을 수 없습니다.")

# 메인 앱
def main():
    st.title('야간 자율학습 출석 체크 시스템')

    if not os.path.exists('attendance.db'):
        st.warning("데이터베이스 파일이 없습니다. 초기화를 진행합니다.")
        init_db()
    
    # 디버그 모드
    if st.sidebar.checkbox('디버그 모드'):
        st.sidebar.write("데이터베이스 내용:")
        conn = get_db_connection()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.close()
        for user in users:
            st.sidebar.write(dict(user))

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
                st.success('로그인 성공!')
                st.rerun()
        
        # 사용자 정보 확인 버튼
        if st.button('사용자 정보 확인'):
            check_user_info(username)

    # 나머지 코드는 그대로 유지...

if __name__ == '__main__':
    main()
