CREATE TABLE IF NOT EXISTS admins (
  id BIGSERIAL PRIMARY KEY,
  login_id VARCHAR(100) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS employees (
  id BIGSERIAL PRIMARY KEY,
  employee_code VARCHAR(100) UNIQUE NOT NULL,
  employee_name VARCHAR(150) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ot_settings (
  id SMALLINT PRIMARY KEY CHECK (id = 1),
  standard_rate NUMERIC(10,2) NOT NULL DEFAULT 75,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ot_entries (
  id BIGSERIAL PRIMARY KEY,
  employee_id BIGINT NOT NULL REFERENCES employees(id),
  ot_date DATE NOT NULL,
  ot_from TIME NOT NULL,
  ot_to TIME NOT NULL,
  hours NUMERIC(8,2) NOT NULL,
  multiplier NUMERIC(4,2) NOT NULL DEFAULT 1,
  rate NUMERIC(10,2) NOT NULL,
  amount NUMERIC(12,2) NOT NULL,
  cycle_key VARCHAR(7) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(employee_id, ot_date)
);

CREATE INDEX IF NOT EXISTS idx_ot_entries_employee_date
  ON ot_entries(employee_id, ot_date);

CREATE INDEX IF NOT EXISTS idx_ot_entries_cycle
  ON ot_entries(cycle_key);

INSERT INTO ot_settings(id, standard_rate)
VALUES (1, 75)
ON CONFLICT (id) DO NOTHING;
