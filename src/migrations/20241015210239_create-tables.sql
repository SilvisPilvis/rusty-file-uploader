-- Create all tables

DROP TABLE IF EXISTS users, stores, files, user_store, file_store;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(30),
    password VARCHAR(97)
);

CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30),
    cover INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256),
    original_name VARCHAR(256),
    content_type VARCHAR(255) NOT NULL,
    md5 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE user_store (
    id SERIAL PRIMARY KEY,
    userId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(userId)
    REFERENCES users(id),
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
);

CREATE TABLE file_store (
    id SERIAL PRIMARY KEY,
    fileId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(fileId)
    REFERENCES files(id),
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
);

-- shared store is just like a new store but with file refernces

-- -- Basic query to get store names and IDs
-- SELECT 
--     s.id,
--     s.name
-- FROM stores s
-- INNER JOIN user_store us ON s.id = us.storeId
-- WHERE us.userId = 1;

-- -- Extended version with additional store details
-- SELECT 
--     s.id,
--     s.name,
--     s.created_at,
--     s.cover
-- FROM stores s
-- INNER JOIN user_store us ON s.id = us.storeId
-- WHERE us.userId = 1
-- ORDER BY s.created_at DESC;

-- -- Version with count of files in each store (if needed)
-- SELECT 
--     s.id,
--     s.name,
--     s.created_at,
--     COUNT(f.id) as file_count
-- FROM stores s
-- INNER JOIN user_store us ON s.id = us.storeId
-- LEFT JOIN files f ON f.id = s.cover
-- WHERE us.userId = 1
-- GROUP BY s.id, s.name, s.created_at
-- ORDER BY s.created_at DESC;
