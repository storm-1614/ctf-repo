FROM php:8.2-apache

# 安装 mysqli 扩展
RUN docker-php-ext-install mysqli

# 启用 Apache rewrite（可选）
RUN a2enmod rewrite
