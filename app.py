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
                    (username TEXT PRIMARY KEY, password TEXT, is_admin INTEGER)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS attendance
                    (username TEXT, timestamp TEXT)''')
    
    # 관리자 계정 생성
    admin_password = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt())
    conn.execute('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                 ('admin1', admin_password, 1))
    
    # 학생 계정 생성
    for class_num in range(1, 8):
        for student_num in range(1, 26):
            user_id = f'1{class_num:02d}{student_num:02d}'
            password = bcrypt.hashpw(user_id.encode(), bcrypt.gensalt())
            conn.execute('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                         (user_id, password, 0))
    
    conn.commit()
    conn.close()

# 로그인 함수
def login(username, password):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode(), user['password']):
        return True
    return False

# 비밀번호 변경 함수
def change_password(username, new_password):
    conn = get_db_connection()
    new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    conn.execute('UPDATE users SET password = ? WHERE username = ?', (new_password_hash, username))
    conn.commit()
    conn.close()

# 출석 체크 함수
def check_attendance(username):
    now = datetime.now()
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

# 메인 앱
def main():
    if not os.path.exists('attendance.db'):
        init_db()

    st.title('야간 자율학습 출석 체크 시스템')

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        username = st.text_input('아이디')
        password = st.text_input('비밀번호', type='password')
        if st.button('로그인'):
            if login(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success('로그인 성공!')
                st.experimental_rerun()
            else:
                st.error('아이디 또는 비밀번호가 잘못되었습니다.')
    else:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (st.session_state.username,)).fetchone()
        conn.close()

        if user['is_admin']:
            admin_view()
        else:
            student_view()

        if st.button('로그아웃'):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.experimental_rerun()

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
            st.success('비밀번호가 변경되었습니다.')

def admin_view():
    st.write('관리자 페이지')
    
    conn = get_db_connection()
    attendance_data = conn.execute('SELECT * FROM attendance ORDER BY timestamp DESC').fetchall()
    conn.close()

    if attendance_data:
        df = pd.DataFrame(attendance_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['week'] = df['timestamp'].dt.to_period('W').astype(str)

        weeks = sorted(df['week'].unique(), reverse=True)
        selected_week = st.selectbox('주 선택', weeks)

        filtered_df = df[df['week'] == selected_week]
        st.write(filtered_df)
    else:
        st.write('출석 데이터가 없습니다.')

if __name__ == '__main__':
    main()
