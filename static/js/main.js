// Validaciones básicas del lado cliente (HU-07, HU-08)
document.addEventListener('DOMContentLoaded', function(){
  const reg = document.getElementById('registerForm');
  if (reg){
    reg.addEventListener('submit', function(e){
      const pwd = reg.querySelector('input[name=password]').value;
      const errs = [];
      if (pwd.length < 8) errs.push('Contraseña mínimo 8 caracteres');
      if (!/[A-Z]/.test(pwd)) errs.push('Debe contener mayúscula');
      if (!/[a-z]/.test(pwd)) errs.push('Debe contener minúscula');
      if (!/[0-9]/.test(pwd)) errs.push('Debe contener número');
      if (!/[!@#$%^&*()\-_=+\[{\]};:\'",<.>/?`~\\|]/.test(pwd)) errs.push('Debe contener carácter especial');
      if (errs.length){
        e.preventDefault();
        alert('Errores:\n' + errs.join('\n'));
      }
    });
  }
});
