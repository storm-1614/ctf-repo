SET NAMES utf8mb4;

-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE test;

-- 创建示例表
CREATE TABLE IF NOT EXISTS wp_news (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    title   VARCHAR(200) NOT NULL,
    content TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建用户表（用于登录绕过练习）
CREATE TABLE IF NOT EXISTS users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50)  NOT NULL,
    password VARCHAR(50)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入测试数据
INSERT INTO wp_news (title, content) VALUES
    ('第一条新闻', '欢迎来到SQL注入练习平台！'),
    ('关于SQL注入', 'SQL注入是一种代码注入技术，攻击者通过在输入中插入恶意SQL语句来操纵数据库。'),
    ('安全公告', '永远不要信任用户输入，始终使用参数化查询。'),
    ('CTF技巧', '在CTF比赛中，SQL注入是最常见的Web题型之一。');

INSERT INTO users (username, password) VALUES
    ('admin', 'supersecret123'),
    ('guest', 'guest123'),
    ('test',  'test456');
