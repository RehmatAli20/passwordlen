import streamlit as st
import re

# Function to check password strength
def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password should be at least 8 characters"
    
    if not any(char.isdigit() for char in password):
        return "Weak: Password should have at least one digit"
    
    if not any(char.isupper() for char in password):
        return "Weak: Password should have at least one uppercase letter"
    
    if not any(char.islower() for char in password):
        return "Weak: Password should have at least one lowercase letter"
    
    if not re.search(r'[!@#$%^&*()_+.?<>,;:]', password):
        return "Medium: Password should have at least one special character"
    
    return "Strong"

# Main Streamlit app
def main():
    st.title("Password Strength Checker 🔐")
    st.write("Welcome to the Password Strength Checker! Enter a password to check its strength.")

    # Initialize session state to store saved passwords
    if 'saved_passwords' not in st.session_state:
        st.session_state.saved_passwords = []

    # Input for password
    password = st.text_input("Enter a password:", type="password")

    if password:
        # Check password strength
        result = check_password_strength(password)
        st.write(f"**Result:** {result}")

        # Save password if it's strong
        if result == "Strong":
            if st.button("Save Password"):
                st.session_state.saved_passwords.append(password)
                st.success("✅ Password saved successfully!")

    # Show saved passwords
    if st.session_state.saved_passwords:
        st.write("### 🔑 Saved Passwords:")
        for idx, saved_pass in enumerate(st.session_state.saved_passwords, start=1):
            st.write(f"{idx}. {saved_pass}")
    else:
        st.write("⚠️ No passwords saved yet.")

    # Option to clear saved passwords
    if st.session_state.saved_passwords:
        if st.button("Clear Saved Passwords"):
            st.session_state.saved_passwords = []
            st.success("Saved passwords cleared!")

# Run the app
if __name__ == "__main__":
    main()