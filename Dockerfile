# Pull the minimal Ubuntu image
FROM ubuntu

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx

# Copy the Nginx config
COPY testconf /etc/nginx/sites-available/default

# Expose the port for access
EXPOSE 3001

# Run the Nginx server
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
