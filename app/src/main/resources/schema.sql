CREATE TABLE IF NOT EXISTS cards (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    customer_id VARCHAR(64) NOT NULL,
    brand       VARCHAR(16) NOT NULL,
    last4       CHAR(4)     NOT NULL,
    token       VARCHAR(64) NOT NULL
);
