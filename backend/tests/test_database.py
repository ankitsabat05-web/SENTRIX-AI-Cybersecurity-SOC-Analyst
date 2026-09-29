import importlib


def test_database_module_loads_without_sqlalchemy():
    module = importlib.import_module("app.database.database")

    assert hasattr(module, "Base")
    module.init_db()
