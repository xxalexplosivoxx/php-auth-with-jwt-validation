FROM php:8.2-apache


RUN apt-get update && apt-get install -y \
    libmagickwand-dev \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*



RUN docker-php-ext-install pdo pdo_mysql iconv


RUN pecl install imagick && docker-php-ext-enable imagick


RUN a2enmod rewrite


COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
