-- ============================================================

CREATE TABLE IF NOT EXISTS usuarios (
  id                    SERIAL PRIMARY KEY,
  nombre                VARCHAR(100)  NOT NULL,
  apellidos             VARCHAR(150)  NOT NULL,
  correo                VARCHAR(255)  NOT NULL UNIQUE,
  contrasena            VARCHAR(255)  NOT NULL,   
  confirm_token         VARCHAR(255)  DEFAULT NULL,
  confirm_token_expires TIMESTAMPTZ   DEFAULT NULL,
  activo                BOOLEAN       NOT NULL DEFAULT TRUE,
  creado_en             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  actualizado_en        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Índice en correo para búsquedas rápidas
CREATE INDEX IF NOT EXISTS idx_usuarios_correo ON usuarios(correo);

-- Trigger: actualiza automáticamente "actualizado_en" al hacer UPDATE
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.actualizado_en = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_usuarios_updated_at
BEFORE UPDATE ON usuarios
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


INSERT INTO usuarios (nombre, apellidos, correo, contrasena)
VALUES (
  'Rubn',
  'Mendoza Dorantes',
  'ribendorantes11@gmail.com',
  '$2b$10$FkwxYn7rASwzN5orwaDe5eWFO9au9elTAKWNW2/k.A2xoPpfOuKSO'   
)
ON CONFLICT (correo) DO NOTHING;

SELECT id, nombre, apellidos, correo, activo, creado_en
FROM usuarios;



DROP TABLE IF EXISTS predicas;

CREATE TABLE predicas (
  id             SERIAL PRIMARY KEY,
  titulo         VARCHAR(255)  NOT NULL,
  predicador     VARCHAR(150)  NOT NULL,
  youtube_url    VARCHAR(500)  NOT NULL,
  imagen_url     VARCHAR(500)  NOT NULL,
  fecha          DATE          NOT NULL,
  activo         BOOLEAN       NOT NULL DEFAULT TRUE,
  creado_en      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  actualizado_en TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE TRIGGER trg_predicas_updated_at
BEFORE UPDATE ON predicas
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();