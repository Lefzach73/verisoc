-- Disposable local synthetic test DB ONLY. Not a production credential/configuration.
CREATE ROLE verisoc_app LOGIN PASSWORD 'verisoc_test_only' NOSUPERUSER NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA public TO verisoc_app;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO verisoc_app;
GRANT UPDATE ON reports TO verisoc_app;
