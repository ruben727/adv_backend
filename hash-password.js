const bcrypt = require('bcrypt');

const password = 'RubenMendoza';
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error al generar el hash:', err);
        return;
    }

    console.log('Contraseña:', password);
    console.log('Hash generado:', hash);
});