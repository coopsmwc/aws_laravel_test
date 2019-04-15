FROM php:7.2-apache

RUN apt-get update && apt-get install -y vim \
&& apt-get install -y iputils-ping && apt-get install -y net-tools \
&& a2enmod rewrite

ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
COPY docker/files/aws-laravel-test.conf /etc/apache2/sites-enabled/.

ENV API_URL=http://local-laravel-api.test
ENV OAUTH_CLIENT_ID=2
ENV OAUTH_CLIENT_SECRET=GzrJTDlKZQCAAKzP6ruJsVtRlnyFFFnXXgkBu8la
