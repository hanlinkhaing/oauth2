const togglePassword = document.getElementById('togglePassword');
const password = document.getElementById('password');

togglePassword.onclick = () => {
    const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
    password.setAttribute('type', type);

    if (type !== 'password') {
        togglePassword.setAttribute('class', 'fa-solid fa-eye');
    } else {
        togglePassword.setAttribute('class', 'fa-solid fa-eye-slash');
    }
};
