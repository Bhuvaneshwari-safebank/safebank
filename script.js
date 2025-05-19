// static/js/script.js

// Password Eye Toggle
function togglePassword(id, eyeId) {
    var passwordInput = document.getElementById(id);
    var eyeIcon = document.getElementById(eyeId);
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.textContent = "🙈";
    } else {
        passwordInput.type = "password";
        eyeIcon.textContent = "👁️";
    }
}

// Password Strength Check
function checkPasswordStrength() {
    var password = document.getElementById("password").value;
    var strengthText = document.getElementById("strengthText");

    var strongRegex = new RegExp("^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})");

    if (strongRegex.test(password)) {
        strengthText.innerHTML = "Strong Password ✅";
        strengthText.style.color = "green";
    } else {
        strengthText.innerHTML = "Weak Password ❌";
        strengthText.style.color = "red";
    }
}
