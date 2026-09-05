"""Синтетические данные MCP-сервера Инвеста. Все клиенты, счета и цифры вымышленные."""

from datetime import date, timedelta

INSTRUMENTS = [
    {"isin": "RU0009029540", "ticker": "SBER", "name": "Сбербанк, ао", "type": "stock", "sector": "Финансы", "market": "MOEX", "price": 285.40, "currency": "RUB"},
    {"isin": "RU0007661625", "ticker": "GAZP", "name": "Газпром, ао", "type": "stock", "sector": "Нефть и газ", "market": "MOEX", "price": 168.20, "currency": "RUB"},
    {"isin": "RU0009024277", "ticker": "LKOH", "name": "Лукойл, ао", "type": "stock", "sector": "Нефть и газ", "market": "MOEX", "price": 7120.00, "currency": "RUB"},
    {"isin": "RU000A0JXQ82", "ticker": "YDEX", "name": "Яндекс, ао", "type": "stock", "sector": "Технологии", "market": "MOEX", "price": 4210.00, "currency": "RUB"},
    {"isin": "RU0008943394", "ticker": "GMKN", "name": "Норникель, ао", "type": "stock", "sector": "Металлургия", "market": "MOEX", "price": 15400.00, "currency": "RUB"},
    {"isin": "RU0009084396", "ticker": "ROSN", "name": "Роснефть, ао", "type": "stock", "sector": "Нефть и газ", "market": "MOEX", "price": 560.00, "currency": "RUB"},
    {"isin": "RU000A0JX0J2", "ticker": "MGNT", "name": "Магнит, ао", "type": "stock", "sector": "Ритейл", "market": "MOEX", "price": 6100.00, "currency": "RUB"},
    {"isin": "RU000A0ZZ8A2", "ticker": "TATN", "name": "Татнефть, ао", "type": "stock", "sector": "Нефть и газ", "market": "MOEX", "price": 640.00, "currency": "RUB"},
    {"isin": "RU000A0JQZZ2", "ticker": "MTSS", "name": "МТС, ао", "type": "stock", "sector": "Телеком", "market": "MOEX", "price": 245.00, "currency": "RUB"},
    {"isin": "RU000A0JVRC8", "ticker": "NVTK", "name": "Новатэк, ао", "type": "stock", "sector": "Нефть и газ", "market": "MOEX", "price": 1180.00, "currency": "RUB"},
    {"isin": "RU000A0JWQV5", "ticker": "PLZL", "name": "Полюс, ао", "type": "stock", "sector": "Металлургия", "market": "MOEX", "price": 13500.00, "currency": "RUB"},
    {
        "isin": "RU000A105EX7", "ticker": "OFZ-26240", "name": "ОФЗ 26240", "type": "bond", "sector": "Госдолг", "market": "MOEX",
        "price": 920.50, "currency": "RUB", "nominal": 1000.0, "coupon_rate": 7.0, "maturity": "2036-07-30",
    },
    {
        "isin": "RU000A106R95", "ticker": "OFZ-26243", "name": "ОФЗ 26243", "type": "bond", "sector": "Госдолг", "market": "MOEX",
        "price": 890.00, "currency": "RUB", "nominal": 1000.0, "coupon_rate": 9.8, "maturity": "2038-05-19",
    },
    {
        "isin": "RU000A103X66", "ticker": "AFBB-01", "name": "АльфаБанк Б1P-01", "type": "bond", "sector": "Финансы", "market": "MOEX",
        "price": 1005.00, "currency": "RUB", "nominal": 1000.0, "coupon_rate": 11.5, "maturity": "2027-03-10",
    },
    {
        "isin": "RU000A104YT5", "ticker": "RZDF-01", "name": "РЖД БО-01", "type": "bond", "sector": "Транспорт", "market": "MOEX",
        "price": 985.00, "currency": "RUB", "nominal": 1000.0, "coupon_rate": 10.2, "maturity": "2029-11-25",
    },
]

_INSTRUMENTS_BY_ISIN = {i["isin"]: i for i in INSTRUMENTS}

EMITENTS = {
    "RU0009029540": {"company_name": "ПАО Сбербанк", "sector": "Финансы", "description": "Крупнейший банк России.", "pe": 4.2, "dividend_yield": 11.5, "rating": "AAA(RU)"},
    "RU0007661625": {"company_name": "ПАО Газпром", "sector": "Нефть и газ", "description": "Крупнейшая газовая компания России.", "pe": 3.1, "dividend_yield": 0.0, "rating": "AA(RU)"},
    "RU0009024277": {"company_name": "ПАО Лукойл", "sector": "Нефть и газ", "description": "Одна из крупнейших нефтяных компаний России.", "pe": 5.8, "dividend_yield": 13.2, "rating": "AAA(RU)"},
    "RU000A0JXQ82": {"company_name": "МКПАО Яндекс", "sector": "Технологии", "description": "Технологическая компания, поиск, такси, e-commerce.", "pe": 12.4, "dividend_yield": 0.0, "rating": "AA(RU)"},
    "RU0008943394": {"company_name": "ПАО ГМК Норникель", "sector": "Металлургия", "description": "Крупнейший производитель никеля и палладия.", "pe": 7.9, "dividend_yield": 8.4, "rating": "AA(RU)"},
    "RU0009084396": {"company_name": "ПАО НК Роснефть", "sector": "Нефть и газ", "description": "Крупнейшая нефтяная компания России.", "pe": 4.9, "dividend_yield": 9.1, "rating": "AAA(RU)"},
    "RU000A0JX0J2": {"company_name": "ПАО Магнит", "sector": "Ритейл", "description": "Розничная сеть продуктовых магазинов.", "pe": 9.1, "dividend_yield": 7.0, "rating": "AA(RU)"},
    "RU000A0ZZ8A2": {"company_name": "ПАО Татнефть", "sector": "Нефть и газ", "description": "Нефтяная компания Республики Татарстан.", "pe": 6.2, "dividend_yield": 12.0, "rating": "AA+(RU)"},
    "RU000A0JQZZ2": {"company_name": "ПАО МТС", "sector": "Телеком", "description": "Телекоммуникационный оператор.", "pe": 10.0, "dividend_yield": 14.5, "rating": "AA(RU)"},
    "RU000A0JVRC8": {"company_name": "ПАО Новатэк", "sector": "Нефть и газ", "description": "Крупный независимый производитель газа.", "pe": 8.3, "dividend_yield": 5.5, "rating": "AAA(RU)"},
    "RU000A0JWQV5": {"company_name": "ПАО Полюс", "sector": "Металлургия", "description": "Крупнейший производитель золота в России.", "pe": 11.1, "dividend_yield": 3.2, "rating": "AA(RU)"},
}

MARGIN_INFO = {
    "RU0009029540": {"margin_available": True, "short_available": True, "risk_long": 0.20, "risk_short": 0.25},
    "RU0007661625": {"margin_available": True, "short_available": True, "risk_long": 0.25, "risk_short": 0.30},
    "RU0009024277": {"margin_available": True, "short_available": False, "risk_long": 0.25, "risk_short": None},
    "RU000A0JXQ82": {"margin_available": True, "short_available": True, "risk_long": 0.35, "risk_short": 0.40},
    "RU0008943394": {"margin_available": True, "short_available": True, "risk_long": 0.30, "risk_short": 0.35},
    "RU0009084396": {"margin_available": True, "short_available": True, "risk_long": 0.25, "risk_short": 0.30},
    "RU000A0JX0J2": {"margin_available": False, "short_available": False, "risk_long": None, "risk_short": None},
    "RU000A0ZZ8A2": {"margin_available": True, "short_available": False, "risk_long": 0.25, "risk_short": None},
    "RU000A0JQZZ2": {"margin_available": True, "short_available": True, "risk_long": 0.30, "risk_short": 0.35},
    "RU000A0JVRC8": {"margin_available": True, "short_available": True, "risk_long": 0.25, "risk_short": 0.30},
    "RU000A0JWQV5": {"margin_available": True, "short_available": False, "risk_long": 0.30, "risk_short": None},
}

_TODAY = date(2026, 8, 26)

DIVIDENDS = [
    {"isin": "RU0009029540", "amount": 34.0, "currency": "RUB", "yield_pct": 11.9, "fix_date": "2026-09-12", "last_buy_date": "2026-09-10", "pay_date": "2026-10-05", "year": 2026},
    {"isin": "RU0009024277", "amount": 498.0, "currency": "RUB", "yield_pct": 7.0, "fix_date": "2026-09-25", "last_buy_date": "2026-09-23", "pay_date": "2026-10-20", "year": 2026},
    {"isin": "RU0008943394", "amount": 620.0, "currency": "RUB", "yield_pct": 4.0, "fix_date": "2026-10-02", "last_buy_date": "2026-09-30", "pay_date": "2026-10-28", "year": 2026},
    {"isin": "RU0009084396", "amount": 41.0, "currency": "RUB", "yield_pct": 7.3, "fix_date": "2026-09-18", "last_buy_date": "2026-09-16", "pay_date": "2026-10-12", "year": 2026},
    {"isin": "RU000A0JQZZ2", "amount": 35.0, "currency": "RUB", "yield_pct": 14.3, "fix_date": "2026-10-10", "last_buy_date": "2026-10-08", "pay_date": "2026-11-01", "year": 2026},
    {"isin": "RU000A0ZZ8A2", "amount": 33.0, "currency": "RUB", "yield_pct": 5.2, "fix_date": "2026-09-05", "last_buy_date": "2026-09-03", "pay_date": "2026-09-29", "year": 2026},
]

_COUPON_PERIOD_DAYS = 182


def _coupon_schedule(isin: str) -> list[dict]:
    inst = _INSTRUMENTS_BY_ISIN.get(isin)
    if not inst or inst["type"] != "bond":
        return []
    nominal = inst["nominal"]
    coupon_rate = inst["coupon_rate"]
    amount_per_period = round(nominal * coupon_rate / 100 / 2, 2)
    maturity = date.fromisoformat(inst["maturity"])
    dates = []
    d = maturity
    while d > _TODAY - timedelta(days=365):
        dates.append(d)
        d = d - timedelta(days=_COUPON_PERIOD_DAYS)
    dates.reverse()
    schedule = []
    for d in dates:
        ret_nominal = round(nominal, 2) if d == maturity else 0.0
        schedule.append({"date": d.isoformat(), "rate": coupon_rate, "amount": amount_per_period, "ret_nominal": ret_nominal})
    return schedule


IDEAS = [
    {"isin": "RU0009029540", "ticker": "SBER", "direction": "long", "target_price": 340.0, "expected_yield_pct": 19.1, "published_at": "2026-08-10", "summary": "Ожидаем рост чистой прибыли по итогам 2026 года и повышение дивидендных выплат."},
    {"isin": "RU000A0JXQ82", "ticker": "YDEX", "direction": "long", "target_price": 5200.0, "expected_yield_pct": 23.5, "published_at": "2026-08-15", "summary": "Рост рекламной выручки и облачного сегмента поддержит переоценку компании."},
    {"isin": "RU0007661625", "ticker": "GAZP", "direction": "short", "target_price": 145.0, "expected_yield_pct": -13.8, "published_at": "2026-08-05", "summary": "Риски снижения экспортных объёмов давят на котировки."},
    {"isin": "RU000A0JWQV5", "ticker": "PLZL", "direction": "long", "target_price": 15800.0, "expected_yield_pct": 17.0, "published_at": "2026-08-20", "summary": "Высокие цены на золото поддерживают маржинальность компании."},
]


def get_instrument(isin: str) -> dict | None:
    return _INSTRUMENTS_BY_ISIN.get(isin)
