import socket, threading, os, math
from tcp_by_size import recv_by_size, send_with_size

IP = "192.168.1.135"
PORT = 11111
CHUNK_SIZE = 2048


def handle_client(sock, tid):
    exit_thread = False
    while not exit_thread:
        try:
            data = recv_by_size(sock).decode()
            if data == b"":
                print("Client disconnected...")
                break
            handle_message(data, sock)
        except socket.timeout:
            continue
        except Exception as err:
            print(err)
            break
    sock.close()


def handle_message(data: str, sock):
    to_send = ""
    fields = data.split("~")
    msg_type = fields[0]
    if msg_type == "GTF":
        send_file_by_size(sock, fields[1], offset=int(fields[2]),size=int(fields[3]))
    return to_send


def send_file_by_size(sock, filename, offset, size):
    try:
        with open(filename, 'rb') as f:
            f.seek(offset, 0)
            num_chunks = math.floor(size / CHUNK_SIZE)

            # Send the number of chunks
            send_with_size(sock, "FCS~" + str(num_chunks + 1))

            for _ in range(num_chunks):
                chunk = f.read(CHUNK_SIZE)
                send_with_size(sock, chunk)
            chunk = f.read(size - (CHUNK_SIZE * num_chunks))
            send_with_size(sock, chunk)

        return "file has been sent"
    except FileNotFoundError:
        print(f"File '{filename}' not found")
        return "file hasnt been found"
    except Exception as e:
        print(f"Error sending file: {e}")
        return f"Error sending file: {e}"


def send_file(sock, filename):
    try:
        with open(filename, 'rb') as f:
            # Calculate the number of chunks
            file_size = os.stat(filename).st_size
            num_chunks = math.ceil(file_size / CHUNK_SIZE)

            # Send the number of chunks

            send_with_size(sock, str(num_chunks))

            # Send the file data in chunks
            f.seek(0)
            for _ in range(num_chunks):
                chunk = f.read(CHUNK_SIZE)
                send_with_size(sock, chunk)
        return "file has been sent"
    except FileNotFoundError:
        print(f"File '{filename}' not found")
        return "file hasnt been found"
    except Exception as e:
        print(f"Error sending file: {e}")
        return f"Error sending file: {e}"


def main():
    server_sock = socket.socket()
    server_sock.bind((IP, PORT))
    server_sock.listen(5)
    threads = []
    i = 1
    while True:
        print("Listenning....")
        cli_sock, addr = server_sock.accept()
        print("new connection " + str(i))
        t = threading.Thread(target=handle_client, args=(cli_sock, i))
        t.start()
        i += 1
        threads.append(t)

        if i > 100000:
            break

    for t in threads:
        t.join()

    server_sock.close()
    print("Bye....")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
