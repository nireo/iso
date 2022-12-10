# Pull the minimal Ubuntu image
FROM ubuntu

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx python3

# Copy the Nginx config
RUN mkdir -p /iso
RUN mkdir -p /tmp/volume
RUN chmod 777 /tmp/volume
COPY volume.py /iso/volume.py

# Expose the port for access
EXPOSE 80

# Run the Nginx server
CMD ["python3", "/iso/volume.py", "3001", "/tmp/volume/"]
