FROM ulsmith/alpine-apache-php7
 
RUN apk add --no-cache mysql-client

COPY ./ /app
RUN chown -R apache:apache  /app/storage

ENV DB_HOST=beanstalk-abs.ckkzpudtbjwv.us-east-2.rds.amazonaws.com

ENV API_URL=http://api
ENV OAUTH_CLIENT_ID=2
ENV OAUTH_CLIENT_SECRET=Iy3Vphif7nvTphuWf51I5U5rhOo6v7duxrH6aYaQ

