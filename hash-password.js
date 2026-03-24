const bcrypt = require('bcrypt');

const password = process.argv[2]; // toma el argumento de la línea de comandos
const saltRounds = 10;

bcrypt.hash(password, saltRounds, function(err, hash) {
  if (err) {
    console.error('Error al generar el hash:', err);
    return;
  }
  console.log('Hash generado:', hash);
});
