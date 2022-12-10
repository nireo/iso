import argparse
import os
import subprocess
import tempfile


def nginx_volume_server_conf(path):
    nginx_conf = """
    daemon off;
    worker_processes auto;
    pcre_jit on;

    error_log /dev/stderr;
    pid %s/nginx_volume.pid;

    events {
        multi_accept on;
        accept_mutex off;
        worker_connections 4096;
    }

    http {
        sendfile on;
        sendfile_max_chunk 1024k;

        tcp_nodelay on;
        tcp_nopush on;

        open_file_cache off;
        types_hash_max_size 2048;

        server_tokens off;

        default_type application/octet-stream;

        error_log /dev/stderr error;

        server {
            listen 80 default_server backlog=4096;
            location / {
                root %s;
                disable_symlinks off;

                client_body_temp_path %s/body_temp;
                client_max_body_size 0;

                dav_methods PUT DELETE;
                dav_access group:rw all:r;
                create_full_put_path on;

                autoindex on;
                autoindex_format json;
            }
        }
    }
    """
    return nginx_conf % (path, path, path)


def nginx_temporary_config_file(conf):
    fd, path = tempfile.mkstemp()
    os.write(fd, conf.encode())
    os.close(fd)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start an iso volume server")
    parser.add_argument("port", type=int, help="volume server port")
    parser.add_argument("path", help="volume server path")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        os.makedirs(args.path)

    conf = nginx_volume_server_conf(args.path)
    conf_path = nginx_temporary_config_file(conf)
    run_cmd = ["nginx", "-c", conf_path, "-p", args.path]

    try:
        subprocess.run(run_cmd)
    except KeyboardInterrupt:
        pass
