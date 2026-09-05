-- Схема и синтетические данные invest-server. Все клиенты, счета и цифры вымышленные —
-- перенесены построчно из mcp-invest/data.py (CLIENTS/POSITIONS/TAX_RECORDS/OPERATIONS/CLIENT_TRAINING).

CREATE TABLE clients (
    cus  TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    cus        TEXT NOT NULL REFERENCES clients(cus),
    cash_rub   NUMERIC NOT NULL
);

CREATE TABLE positions (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    isin       TEXT NOT NULL,
    amount     NUMERIC NOT NULL
);

CREATE TABLE tax_records (
    account_id      TEXT NOT NULL REFERENCES accounts(account_id),
    year            INT NOT NULL,
    income          NUMERIC NOT NULL,
    tax_accrued     NUMERIC NOT NULL,
    tax_paid        NUMERIC NOT NULL,
    tax_to_pay      NUMERIC NOT NULL,
    tax_to_return   NUMERIC NOT NULL,
    PRIMARY KEY (account_id, year)
);

CREATE TABLE operations (
    id         SERIAL PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    date       DATE NOT NULL,
    type       TEXT NOT NULL,
    isin       TEXT NOT NULL,
    amount     NUMERIC NOT NULL,
    sum        NUMERIC NOT NULL
);

CREATE TABLE client_training (
    cus        TEXT NOT NULL REFERENCES clients(cus),
    test_id    TEXT NOT NULL,
    test_name  TEXT NOT NULL,
    completed  BOOLEAN NOT NULL,
    PRIMARY KEY (cus, test_id)
);

INSERT INTO clients (cus, name) VALUES
    ('1001', 'Иванов Иван Иванович'),
    ('1002', 'Петрова Мария Сергеевна'),
    ('1003', 'Сидоров Алексей Викторович'),
    ('1004', 'Кузнецова Ольга Дмитриевна'),
    ('1005', 'Морозов Дмитрий Павлович');

INSERT INTO accounts (account_id, cus, cash_rub) VALUES
    ('10234567', '1001', 152340.50),
    ('10345678', '1002', 87200.00),
    ('10456789', '1003', 2450000.00),
    ('10567890', '1004', 34500.00),
    ('10678901', '1005', 615000.00);

INSERT INTO positions (account_id, isin, amount) VALUES
    ('10234567', 'RU0009029540', 200),
    ('10234567', 'RU0007661625', 500),
    ('10234567', 'RU000A105EX7', 50),
    ('10345678', 'RU000A0JXQ82', 10),
    ('10345678', 'RU0008943394', 5),
    ('10345678', 'RU000A103X66', 100),
    ('10456789', 'RU0009024277', 30),
    ('10456789', 'RU0009084396', 1000),
    ('10456789', 'RU000A0JWQV5', 20),
    ('10456789', 'RU000A104YT5', 200),
    ('10567890', 'RU000A0JQZZ2', 300),
    ('10567890', 'RU000A106R95', 30),
    ('10678901', 'RU000A0ZZ8A2', 800),
    ('10678901', 'RU000A0JVRC8', 150),
    ('10678901', 'RU000A0JX0J2', 40),
    ('10678901', 'RU000A103X66', 50);

INSERT INTO tax_records (account_id, year, income, tax_accrued, tax_paid, tax_to_pay, tax_to_return) VALUES
    ('10234567', 2025, 184500.0, 23985.0, 20000.0, 3985.0, 0.0),
    ('10345678', 2025, 56200.0, 7306.0, 7306.0, 0.0, 0.0),
    ('10456789', 2025, 1240000.0, 161200.0, 150000.0, 11200.0, 0.0),
    ('10567890', 2025, 4100.0, 533.0, 900.0, 0.0, 367.0),
    ('10678901', 2025, 312000.0, 40560.0, 40560.0, 0.0, 0.0);

INSERT INTO operations (account_id, date, type, isin, amount, sum) VALUES
    ('10234567', '2026-06-02', 'Покупка', 'RU0009029540', 100, 27800.0),
    ('10234567', '2026-07-15', 'Покупка', 'RU0009029540', 100, 28100.0),
    ('10234567', '2026-05-20', 'Покупка', 'RU0007661625', 500, 82500.0),
    ('10234567', '2026-08-01', 'Выплата дивидендов', 'RU0009029540', 200, 6800.0),
    ('10345678', '2026-04-11', 'Покупка', 'RU000A0JXQ82', 10, 41200.0),
    ('10345678', '2026-06-30', 'Покупка', 'RU0008943394', 5, 74500.0),
    ('10345678', '2026-07-05', 'Покупка', 'RU000A103X66', 100, 100200.0),
    ('10456789', '2026-03-02', 'Покупка', 'RU0009024277', 30, 205000.0),
    ('10456789', '2026-03-20', 'Покупка', 'RU0009084396', 1000, 540000.0),
    ('10456789', '2026-07-18', 'Продажа', 'RU0009084396', 200, 111000.0),
    ('10456789', '2026-08-10', 'Покупка', 'RU000A0JWQV5', 20, 265000.0),
    ('10567890', '2026-02-14', 'Покупка', 'RU000A0JQZZ2', 300, 70500.0),
    ('10567890', '2026-05-01', 'Покупка', 'RU000A106R95', 30, 26400.0),
    ('10678901', '2026-01-25', 'Покупка', 'RU000A0ZZ8A2', 800, 480000.0),
    ('10678901', '2026-04-30', 'Покупка', 'RU000A0JVRC8', 150, 165000.0),
    ('10678901', '2026-06-11', 'Покупка', 'RU000A0JX0J2', 40, 232000.0);

INSERT INTO client_training (cus, test_id, test_name, completed) VALUES
    ('1001', 'T-MARGIN', 'Тестирование для доступа к маржинальной торговле', TRUE),
    ('1001', 'T-BONDS-NR', 'Тестирование по облигациям без рейтинга', FALSE),
    ('1002', 'T-MARGIN', 'Тестирование для доступа к маржинальной торговле', FALSE),
    ('1003', 'T-MARGIN', 'Тестирование для доступа к маржинальной торговле', TRUE),
    ('1003', 'T-DERIV', 'Тестирование по производным финансовым инструментам', TRUE),
    ('1004', 'T-MARGIN', 'Тестирование для доступа к маржинальной торговле', FALSE),
    ('1005', 'T-MARGIN', 'Тестирование для доступа к маржинальной торговле', TRUE);
