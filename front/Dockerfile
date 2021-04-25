FROM nginx:stable
COPY . /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN chmod -R o+rwx /usr/share/nginx/html