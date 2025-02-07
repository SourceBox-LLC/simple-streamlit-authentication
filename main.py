import streamlit as st
import bcrypt

# Mock database
users = {}

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def authenticate(username, password):
    if username in users:
        hashed_password = users[username]
        if verify_password(password, hashed_password):
            return True
    return False

def register_user(username, password):
    if username not in users:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password
        return True
    return False

def main():
    st.title("Login/Registration System")

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate(username, password):
                st.success(f"Welcome, {username}!")
            else:
                st.error("Invalid username or password")

    elif choice == "Register":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        if st.button("Register"):
            if password == confirm_password:
                if register_user(username, password):
                    st.success("Registration successful!")
                else:
                    st.error("Username already exists")
            else:
                st.error("Passwords do not match")

if __name__ == "__main__":
    main()
