-- Prices are in Tanzanian shillings (TZS). Existing books switch to TZS: check each book's price
-- in the dashboard. Past orders and payments keep the currency they were actually paid in.
ALTER TABLE books ALTER COLUMN currency SET DEFAULT 'TZS';
UPDATE books SET currency = 'TZS', updated_at = now() WHERE currency <> 'TZS';
