FROM php:8.1-fpm

# Set default UID and GID if not provided
# ARG UID=1000
# ARG GID=1000

RUN groupadd -g 1000 www && \
    useradd -u 1000 -g www -m www

# Install Laravel dependencies (example)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

WORKDIR /var/www

# Switch to the user
USER www
