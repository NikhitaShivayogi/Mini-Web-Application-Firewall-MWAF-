// Password Strength Logic
const passwordInput = document.getElementById('password');
const strengthBar = document.getElementById('strengthBar');

if (passwordInput && strengthBar) {
    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        let score = 0;
        
        if (val.length >= 8) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const colors = ['#ff4d4d', '#ffb703', '#ffd60a', '#64ffda', '#00b48a'];
        const width = (score / 5) * 100;
        
        strengthBar.style.width = width + '%';
        strengthBar.style.backgroundColor = colors[score - 1] || '#233554';
    });
}
